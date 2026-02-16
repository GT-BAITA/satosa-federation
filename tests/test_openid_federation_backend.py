# SPDX-FileCopyrightText: 2026 Kushal Das <kushal@sunet.se>
# SPDX-License-Identifier: BSD-2-Clause
"""
Tests for the OpenID Federation backend plugin.
"""

import base64
import hashlib
import json
import os
import sys
import time
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
import responses
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from jwkest.jwk import ECKey
from jwkest.jws import JWS

from satosa.context import Context
from satosa.exception import SATOSAAuthenticationError, SATOSAMissingStateError
from satosa.internal import InternalData
from satosa.response import Redirect
from satosa.state import State

# Ensure the plugin directory is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugin"))

from openid_federation import _int_to_b64url, FederationError
from openid_federation_backend import (
    OpenIDFederationBackend,
    _generate_pkce,
    _html_escape,
    _OPMetadataCache,
    _OPListCache,
    NONCE_KEY,
    STATE_KEY,
    CODE_VERIFIER_KEY,
    INTERNAL_REQUEST_KEY,
    DISCOVERY_PENDING_KEY,
)


INTERNAL_ATTRIBUTES = {
    "attributes": {
        "mail": {"saml": ["email"], "openid": ["email"]},
        "givenname": {"saml": ["givenName"], "openid": ["given_name"]},
        "surname": {"saml": ["sn"], "openid": ["family_name"]},
    }
}
BASE_URL = "https://satosarp.example.com"
RP_ENTITY_ID = "https://satosarp.example.com"
OP_ENTITY_ID = "https://op.example.com"
OP2_ENTITY_ID = "https://op2.example.com"
TA_ENTITY_ID = "https://trust-anchor.example.com"

OP_AUTHORIZATION_ENDPOINT = f"{OP_ENTITY_ID}/authorize"
OP_TOKEN_ENDPOINT = f"{OP_ENTITY_ID}/token"
OP_USERINFO_ENDPOINT = f"{OP_ENTITY_ID}/userinfo"

COLLECTION_ENDPOINT = f"{TA_ENTITY_ID}/collection"


# --- Key generation helpers ---


def _generate_ec_key():
    """Generate an EC P-256 key pair and return (private_key_obj, ECKey)."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    nums = private_key.private_numbers()
    pub = nums.public_numbers
    jwk_dict = {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_b64url(pub.x, 32),
        "y": _int_to_b64url(pub.y, 32),
        "d": _int_to_b64url(nums.private_value, 32),
    }
    eck = ECKey(**jwk_dict, use="sig")
    return private_key, eck


def _save_ec_key_to_file(private_key, path):
    """Save EC private key to PEM file."""
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def _sign_jwt(payload_dict, key, alg="ES256"):
    """Sign a payload dict as a JWT and return the compact serialization."""
    return JWS(json.dumps(payload_dict), alg=alg).sign_compact(keys=[key])


# --- Fixtures ---


@pytest.fixture
def ec_keys():
    """Generate EC key pairs for RP, OP, and TA."""
    _, rp_key = _generate_ec_key()
    _, op_key = _generate_ec_key()
    _, ta_key = _generate_ec_key()
    return {"rp": rp_key, "op": op_key, "ta": ta_key}


@pytest.fixture
def rp_key_file(tmp_path):
    """Create a temporary EC key file for the RP backend."""
    private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
    key_path = str(tmp_path / "rp_federation_ec.key")
    _save_ec_key_to_file(private_key, key_path)
    return key_path


@pytest.fixture
def op_jwks(ec_keys):
    """Return the OP's JWKS (public keys) for id_token verification."""
    return {"keys": [ec_keys["op"].serialize(private=False)]}


@pytest.fixture
def backend_config(rp_key_file, ec_keys):
    """Build a backend configuration dict (single OP mode)."""
    ta_pub = ec_keys["ta"].serialize(private=False)
    return {
        "op_entity_id": OP_ENTITY_ID,
        "entity_id": RP_ENTITY_ID,
        "scope": "openid email",
        "federation": {
            "signing_key_path": rp_key_file,
            "signing_key_id": "rp-fed-key-1",
            "signing_algorithm": "ES256",
            "authority_hints": [TA_ENTITY_ID],
            "trust_anchors": {
                TA_ENTITY_ID: {
                    "keys": [ta_pub],
                },
            },
            "entity_configuration_lifetime": 86400,
            "organization_name": "Test RP Proxy",
        },
    }


@pytest.fixture
def mock_resolve_result(op_jwks):
    """Return a mock resolve result for the OP."""
    return {
        "iss": TA_ENTITY_ID,
        "sub": OP_ENTITY_ID,
        "metadata": {
            "openid_provider": {
                "issuer": OP_ENTITY_ID,
                "authorization_endpoint": OP_AUTHORIZATION_ENDPOINT,
                "token_endpoint": OP_TOKEN_ENDPOINT,
                "userinfo_endpoint": OP_USERINFO_ENDPOINT,
                "jwks": op_jwks,
            },
        },
    }


@pytest.fixture
def backend(backend_config, mock_resolve_result):
    """Create an OpenIDFederationBackend instance with mocked OP resolution."""
    with patch(
        "openid_federation_backend.resolve_via_trust_anchors",
        return_value=mock_resolve_result,
    ):
        instance = OpenIDFederationBackend(
            auth_callback_func=MagicMock(),
            internal_attributes=INTERNAL_ATTRIBUTES,
            config=backend_config,
            base_url=BASE_URL,
            name="OIDFedRP",
        )
    return instance


@pytest.fixture
def discovery_config(rp_key_file, ec_keys):
    """Build a backend configuration dict with discovery enabled."""
    ta_pub = ec_keys["ta"].serialize(private=False)
    return {
        "entity_id": RP_ENTITY_ID,
        "scope": "openid email",
        "discovery": {
            "enable": True,
            "collection_endpoint": COLLECTION_ENDPOINT,
            "cache_ttl": 3600,
            "page_title": "Test Discovery",
        },
        "federation": {
            "signing_key_path": rp_key_file,
            "signing_key_id": "rp-fed-key-1",
            "signing_algorithm": "ES256",
            "authority_hints": [TA_ENTITY_ID],
            "trust_anchors": {
                TA_ENTITY_ID: {
                    "keys": [ta_pub],
                },
            },
            "entity_configuration_lifetime": 86400,
            "organization_name": "Test RP Proxy",
        },
    }


@pytest.fixture
def discovery_backend(discovery_config):
    """Create a backend with discovery enabled (no OP resolved at init)."""
    instance = OpenIDFederationBackend(
        auth_callback_func=MagicMock(),
        internal_attributes=INTERNAL_ATTRIBUTES,
        config=discovery_config,
        base_url=BASE_URL,
        name="OIDFedRP",
    )
    return instance


@pytest.fixture
def context():
    ctx = Context()
    ctx.state = State()
    return ctx


# --- Tests ---


class TestPKCE:
    def test_generate_pkce_returns_tuple(self):
        """PKCE generation returns (code_verifier, code_challenge) tuple."""
        verifier, challenge = _generate_pkce()
        assert isinstance(verifier, str)
        assert isinstance(challenge, str)
        assert len(verifier) > 0
        assert len(challenge) > 0

    def test_pkce_challenge_is_s256(self):
        """code_challenge is the S256 hash of code_verifier."""
        verifier, challenge = _generate_pkce()
        expected = (
            base64.urlsafe_b64encode(
                hashlib.sha256(verifier.encode("ascii")).digest()
            )
            .rstrip(b"=")
            .decode("ascii")
        )
        assert challenge == expected

    def test_pkce_unique(self):
        """Each PKCE generation produces unique values."""
        v1, c1 = _generate_pkce()
        v2, c2 = _generate_pkce()
        assert v1 != v2
        assert c1 != c2


class TestHtmlEscape:
    def test_escapes_special_chars(self):
        assert _html_escape('<script>alert("xss")</script>') == (
            "&lt;script&gt;alert(&quot;xss&quot;)&lt;/script&gt;"
        )

    def test_escapes_ampersand(self):
        assert _html_escape("foo&bar") == "foo&amp;bar"

    def test_escapes_single_quote(self):
        assert _html_escape("it's") == "it&#x27;s"

    def test_passthrough_safe_string(self):
        assert _html_escape("hello world") == "hello world"


class TestOPMetadataCache:
    def test_cache_miss_returns_none(self):
        cache = _OPMetadataCache(ttl=3600)
        assert cache.get("https://unknown.example.com") is None

    def test_cache_hit(self):
        cache = _OPMetadataCache(ttl=3600)
        meta = {"authorization_endpoint": "https://op.example.com/auth"}
        cache.put("https://op.example.com", meta)
        assert cache.get("https://op.example.com") == meta

    def test_cache_expiry(self):
        cache = _OPMetadataCache(ttl=0)
        cache.put("https://op.example.com", {"key": "val"})
        time.sleep(0.01)
        assert cache.get("https://op.example.com") is None


class TestOPListCache:
    def test_cache_miss_returns_none(self):
        cache = _OPListCache(ttl=300)
        assert cache.get() is None

    def test_cache_hit(self):
        cache = _OPListCache(ttl=300)
        entities = [{"entity_id": "https://op.example.com", "display_name": "Test OP"}]
        cache.put(entities)
        assert cache.get() == entities

    def test_cache_expiry(self):
        cache = _OPListCache(ttl=0)
        cache.put([{"entity_id": "test"}])
        time.sleep(0.01)
        assert cache.get() is None


class TestEntityConfiguration:
    def test_entity_configuration_returns_jwt(self, context, backend):
        """Entity configuration endpoint returns JWT with correct content-type."""
        resp = backend.entity_configuration_endpoint(context)
        assert resp.status == "200 OK"
        content_types = [v for k, v in resp.headers if k == "Content-Type"]
        assert "application/entity-statement+jwt" in content_types

    def test_entity_configuration_claims(self, context, backend):
        """JWT contains correct RP entity configuration claims."""
        resp = backend.entity_configuration_endpoint(context)
        jwt_str = resp.message
        parts = jwt_str.split(".")
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))

        assert claims["iss"] == RP_ENTITY_ID
        assert claims["sub"] == RP_ENTITY_ID
        assert "jwks" in claims
        assert "keys" in claims["jwks"]
        assert claims["authority_hints"] == [TA_ENTITY_ID]
        assert "metadata" in claims
        assert "openid_relying_party" in claims["metadata"]
        rp_meta = claims["metadata"]["openid_relying_party"]
        assert f"{BASE_URL}/OIDFedRP/callback" in rp_meta["redirect_uris"]
        assert rp_meta["response_types"] == ["code"]
        assert rp_meta["token_endpoint_auth_method"] == "private_key_jwt"
        assert "iat" in claims
        assert "exp" in claims

    def test_entity_configuration_self_signed(self, context, backend):
        """JWT is verifiable with the embedded JWKS."""
        from openid_federation import verify_entity_statement, decode_entity_statement

        resp = backend.entity_configuration_endpoint(context)
        jwt_str = resp.message
        claims = decode_entity_statement(jwt_str)
        verified = verify_entity_statement(jwt_str, claims["jwks"])
        assert verified["iss"] == RP_ENTITY_ID

    def test_entity_configuration_includes_organization(self, context, backend):
        """Entity configuration includes federation_entity metadata."""
        from openid_federation import decode_entity_statement

        resp = backend.entity_configuration_endpoint(context)
        claims = decode_entity_statement(resp.message)
        assert "federation_entity" in claims["metadata"]
        assert claims["metadata"]["federation_entity"]["organization_name"] == "Test RP Proxy"


class TestStartAuth:
    def test_start_auth_redirects(self, context, backend):
        """start_auth returns a Redirect to the OP's authorization endpoint."""
        internal_req = InternalData()
        resp = backend.start_auth(context, internal_req)
        assert isinstance(resp, Redirect)
        parsed = urlparse(resp.message)
        assert parsed.scheme == "https"
        assert parsed.netloc == "op.example.com"
        assert parsed.path == "/authorize"

    def test_start_auth_params(self, context, backend):
        """Authorization URL includes required parameters."""
        internal_req = InternalData()
        resp = backend.start_auth(context, internal_req)
        parsed = urlparse(resp.message)
        params = parse_qs(parsed.query)

        assert params["client_id"] == [RP_ENTITY_ID]
        assert params["response_type"] == ["code"]
        assert params["scope"] == ["openid email"]
        assert "request" in params

    def test_start_auth_stores_state(self, context, backend):
        """start_auth stores nonce, state, code_verifier, and op_entity_id in session."""
        internal_req = InternalData()
        backend.start_auth(context, internal_req)

        backend_state = context.state[backend.name]
        assert NONCE_KEY in backend_state
        assert STATE_KEY in backend_state
        assert CODE_VERIFIER_KEY in backend_state
        assert backend_state["op_entity_id"] == OP_ENTITY_ID
        assert len(backend_state[NONCE_KEY]) > 0
        assert len(backend_state[STATE_KEY]) > 0
        assert len(backend_state[CODE_VERIFIER_KEY]) > 0

    def test_start_auth_request_object_is_signed_jwt(self, context, backend):
        """The request parameter contains a signed JWT with correct claims."""
        internal_req = InternalData()
        resp = backend.start_auth(context, internal_req)
        parsed = urlparse(resp.message)
        params = parse_qs(parsed.query)
        request_jwt = params["request"][0]

        parts = request_jwt.split(".")
        payload_b64 = parts[1] + "=" * (4 - len(parts[1]) % 4)
        claims = json.loads(base64.urlsafe_b64decode(payload_b64))

        assert claims["iss"] == RP_ENTITY_ID
        assert claims["aud"] == OP_ENTITY_ID
        assert claims["client_id"] == RP_ENTITY_ID
        assert claims["response_type"] == "code"
        assert claims["scope"] == "openid email"
        assert f"{BASE_URL}/OIDFedRP/callback" == claims["redirect_uri"]
        assert "code_challenge" in claims
        assert claims["code_challenge_method"] == "S256"
        assert "nonce" in claims
        assert "state" in claims


class TestResponseEndpoint:
    def _setup_backend_state(self, context, backend, nonce="test-nonce",
                             state="test-state", op_entity_id=OP_ENTITY_ID):
        """Set up backend state as if start_auth had been called."""
        code_verifier, _ = _generate_pkce()
        context.state[backend.name] = {
            NONCE_KEY: nonce,
            STATE_KEY: state,
            CODE_VERIFIER_KEY: code_verifier,
            "op_entity_id": op_entity_id,
        }
        return code_verifier

    def test_missing_state_raises(self, context, backend):
        """Response without session state raises SATOSAMissingStateError."""
        context.request = {"code": "auth-code", "state": "some-state"}
        with pytest.raises(SATOSAMissingStateError):
            backend.response_endpoint(context)

    def test_op_error_raises(self, context, backend):
        """OP returning an error raises SATOSAAuthenticationError."""
        self._setup_backend_state(context, backend)
        context.request = {"error": "access_denied", "error_description": "User denied"}
        with pytest.raises(SATOSAAuthenticationError, match="User denied"):
            backend.response_endpoint(context)

    def test_state_mismatch_raises(self, context, backend):
        """State mismatch raises SATOSAAuthenticationError."""
        self._setup_backend_state(context, backend, state="expected-state")
        context.request = {"code": "auth-code", "state": "wrong-state"}
        with pytest.raises(SATOSAAuthenticationError, match="State mismatch"):
            backend.response_endpoint(context)

    def test_missing_code_raises(self, context, backend):
        """Missing authorization code raises SATOSAAuthenticationError."""
        self._setup_backend_state(context, backend, state="test-state")
        context.request = {"state": "test-state"}
        with pytest.raises(SATOSAAuthenticationError, match="No authorization code"):
            backend.response_endpoint(context)

    @responses.activate
    def test_successful_flow(self, context, backend, ec_keys):
        """Full successful flow: code exchange, id_token verification, userinfo."""
        nonce = "test-nonce-123"
        state = "test-state-456"
        self._setup_backend_state(context, backend, nonce=nonce, state=state)

        op_key = ec_keys["op"]

        now = int(time.time())
        id_token_claims = {
            "iss": OP_ENTITY_ID,
            "sub": "user-12345",
            "aud": RP_ENTITY_ID,
            "iat": now,
            "exp": now + 3600,
            "nonce": nonce,
            "email": "user@example.com",
        }
        id_token_jwt = _sign_jwt(id_token_claims, op_key)

        token_response = {
            "access_token": "access-token-xyz",
            "token_type": "Bearer",
            "id_token": id_token_jwt,
        }
        responses.add(
            responses.POST, OP_TOKEN_ENDPOINT, json=token_response, status=200,
        )

        userinfo_response = {
            "sub": "user-12345",
            "email": "user@example.com",
            "given_name": "Test",
            "family_name": "User",
        }
        responses.add(
            responses.GET, OP_USERINFO_ENDPOINT, json=userinfo_response, status=200,
        )

        context.request = {"code": "auth-code-789", "state": state}
        backend.response_endpoint(context)

        backend.auth_callback_func.assert_called_once()
        call_args = backend.auth_callback_func.call_args
        internal_resp = call_args[0][1]
        assert internal_resp.subject_id == "user-12345"
        assert "mail" in internal_resp.attributes
        assert internal_resp.attributes["mail"] == ["user@example.com"]

    @responses.activate
    def test_token_exchange_uses_private_key_jwt(self, context, backend, ec_keys):
        """Token exchange includes client_assertion with private_key_jwt."""
        nonce = "nonce-1"
        state = "state-1"
        self._setup_backend_state(context, backend, nonce=nonce, state=state)

        op_key = ec_keys["op"]
        now = int(time.time())
        id_token_claims = {
            "iss": OP_ENTITY_ID,
            "sub": "user-1",
            "aud": RP_ENTITY_ID,
            "iat": now,
            "exp": now + 3600,
            "nonce": nonce,
        }
        id_token_jwt = _sign_jwt(id_token_claims, op_key)

        responses.add(
            responses.POST, OP_TOKEN_ENDPOINT,
            json={"access_token": "at", "id_token": id_token_jwt}, status=200,
        )
        responses.add(
            responses.GET, OP_USERINFO_ENDPOINT, json={"sub": "user-1"}, status=200,
        )

        context.request = {"code": "code-1", "state": state}
        backend.response_endpoint(context)

        token_request_body = responses.calls[0].request.body
        assert "client_assertion=" in token_request_body
        assert "client_assertion_type=urn" in token_request_body
        assert "grant_type=authorization_code" in token_request_body
        assert "code=code-1" in token_request_body
        assert "code_verifier=" in token_request_body

    @responses.activate
    def test_token_endpoint_failure_raises(self, context, backend):
        """Token endpoint returning non-200 raises FederationError."""
        state = "state-err"
        self._setup_backend_state(context, backend, state=state)

        responses.add(
            responses.POST, OP_TOKEN_ENDPOINT, body="Internal Server Error", status=500,
        )

        context.request = {"code": "code-err", "state": state}
        with pytest.raises(FederationError, match="Token endpoint error"):
            backend.response_endpoint(context)

    @responses.activate
    def test_id_token_nonce_mismatch_raises(self, context, backend, ec_keys):
        """id_token with wrong nonce raises SATOSAAuthenticationError."""
        nonce = "expected-nonce"
        state = "state-nonce"
        self._setup_backend_state(context, backend, nonce=nonce, state=state)

        op_key = ec_keys["op"]
        now = int(time.time())
        id_token_claims = {
            "iss": OP_ENTITY_ID, "sub": "user-1", "aud": RP_ENTITY_ID,
            "iat": now, "exp": now + 3600, "nonce": "wrong-nonce",
        }
        id_token_jwt = _sign_jwt(id_token_claims, op_key)

        responses.add(
            responses.POST, OP_TOKEN_ENDPOINT,
            json={"access_token": "at", "id_token": id_token_jwt}, status=200,
        )

        context.request = {"code": "code-1", "state": state}
        with pytest.raises(SATOSAAuthenticationError, match="nonce mismatch"):
            backend.response_endpoint(context)

    @responses.activate
    def test_id_token_issuer_mismatch_raises(self, context, backend, ec_keys):
        """id_token with wrong issuer raises SATOSAAuthenticationError."""
        nonce = "nonce-iss"
        state = "state-iss"
        self._setup_backend_state(context, backend, nonce=nonce, state=state)

        op_key = ec_keys["op"]
        now = int(time.time())
        id_token_claims = {
            "iss": "https://evil.example.com", "sub": "user-1", "aud": RP_ENTITY_ID,
            "iat": now, "exp": now + 3600, "nonce": nonce,
        }
        id_token_jwt = _sign_jwt(id_token_claims, op_key)

        responses.add(
            responses.POST, OP_TOKEN_ENDPOINT,
            json={"access_token": "at", "id_token": id_token_jwt}, status=200,
        )

        context.request = {"code": "code-1", "state": state}
        with pytest.raises(SATOSAAuthenticationError, match="issuer mismatch"):
            backend.response_endpoint(context)

    @responses.activate
    def test_id_token_audience_mismatch_raises(self, context, backend, ec_keys):
        """id_token with wrong audience raises SATOSAAuthenticationError."""
        nonce = "nonce-aud"
        state = "state-aud"
        self._setup_backend_state(context, backend, nonce=nonce, state=state)

        op_key = ec_keys["op"]
        now = int(time.time())
        id_token_claims = {
            "iss": OP_ENTITY_ID, "sub": "user-1", "aud": "https://wrong-rp.example.com",
            "iat": now, "exp": now + 3600, "nonce": nonce,
        }
        id_token_jwt = _sign_jwt(id_token_claims, op_key)

        responses.add(
            responses.POST, OP_TOKEN_ENDPOINT,
            json={"access_token": "at", "id_token": id_token_jwt}, status=200,
        )

        context.request = {"code": "code-1", "state": state}
        with pytest.raises(SATOSAAuthenticationError, match="audience mismatch"):
            backend.response_endpoint(context)

    @responses.activate
    def test_userinfo_failure_still_succeeds_with_id_token(self, context, backend, ec_keys):
        """If userinfo fails but id_token has claims, auth still succeeds."""
        nonce = "nonce-ui"
        state = "state-ui"
        self._setup_backend_state(context, backend, nonce=nonce, state=state)

        op_key = ec_keys["op"]
        now = int(time.time())
        id_token_claims = {
            "iss": OP_ENTITY_ID, "sub": "user-ui-1", "aud": RP_ENTITY_ID,
            "iat": now, "exp": now + 3600, "nonce": nonce, "email": "fallback@example.com",
        }
        id_token_jwt = _sign_jwt(id_token_claims, op_key)

        responses.add(
            responses.POST, OP_TOKEN_ENDPOINT,
            json={"access_token": "at", "id_token": id_token_jwt}, status=200,
        )
        responses.add(
            responses.GET, OP_USERINFO_ENDPOINT, body="Service Unavailable", status=503,
        )

        context.request = {"code": "code-ui", "state": state}
        backend.response_endpoint(context)

        backend.auth_callback_func.assert_called_once()
        internal_resp = backend.auth_callback_func.call_args[0][1]
        assert internal_resp.subject_id == "user-ui-1"

    @responses.activate
    def test_no_id_token_no_userinfo_raises(self, context, backend):
        """No id_token and no userinfo raises SATOSAAuthenticationError."""
        state = "state-empty"
        self._setup_backend_state(context, backend, state=state)

        responses.add(
            responses.POST, OP_TOKEN_ENDPOINT,
            json={"access_token": "at", "token_type": "Bearer"}, status=200,
        )
        responses.add(
            responses.GET, OP_USERINFO_ENDPOINT, body="Not Found", status=404,
        )

        context.request = {"code": "code-empty", "state": state}
        with pytest.raises(SATOSAAuthenticationError, match="No id_token or userinfo"):
            backend.response_endpoint(context)


class TestRegisterEndpoints:
    def test_register_endpoints(self, backend):
        """Backend registers callback and entity-configuration endpoints."""
        endpoints = backend.register_endpoints()
        patterns = [ep[0] for ep in endpoints]
        assert any("callback" in p for p in patterns)
        assert any("entity-configuration" in p for p in patterns)

    def test_register_endpoints_no_discovery(self, backend):
        """Backend without discovery registers exactly 2 endpoints."""
        endpoints = backend.register_endpoints()
        assert len(endpoints) == 2

    def test_register_endpoints_with_discovery(self, discovery_backend):
        """Backend with discovery registers 3 endpoints including /discovery."""
        endpoints = discovery_backend.register_endpoints()
        patterns = [ep[0] for ep in endpoints]
        assert len(endpoints) == 3
        assert any("discovery" in p for p in patterns)
        assert any("callback" in p for p in patterns)
        assert any("entity-configuration" in p for p in patterns)


class TestConfiguration:
    def test_missing_both_op_and_discovery_raises(self, rp_key_file, ec_keys):
        """Config without op_entity_id and without discovery raises ValueError."""
        ta_pub = ec_keys["ta"].serialize(private=False)
        config = {
            "entity_id": RP_ENTITY_ID,
            "federation": {
                "signing_key_path": rp_key_file,
                "signing_algorithm": "ES256",
                "trust_anchors": {TA_ENTITY_ID: {"keys": [ta_pub]}},
            },
        }
        with pytest.raises(ValueError, match="op_entity_id.*discovery"):
            OpenIDFederationBackend(
                MagicMock(), INTERNAL_ATTRIBUTES, config, BASE_URL, "test"
            )

    def test_op_resolution_failure_raises(self, backend_config):
        """Failed OP metadata resolution at init raises."""
        with patch(
            "openid_federation_backend.resolve_via_trust_anchors",
            side_effect=FederationError("Could not resolve"),
        ):
            with pytest.raises(FederationError, match="Could not resolve"):
                OpenIDFederationBackend(
                    MagicMock(), INTERNAL_ATTRIBUTES, backend_config, BASE_URL, "test"
                )

    def test_discovery_mode_skips_init_resolution(self, discovery_config):
        """Discovery mode does not resolve any OP at startup."""
        with patch(
            "openid_federation_backend.resolve_via_trust_anchors"
        ) as mock_resolve:
            OpenIDFederationBackend(
                MagicMock(), INTERNAL_ATTRIBUTES, discovery_config, BASE_URL, "test"
            )
            mock_resolve.assert_not_called()

    def test_get_metadata_desc(self, backend):
        """get_metadata_desc returns empty list."""
        assert backend.get_metadata_desc() == []


class TestDiscovery:
    """Tests for OP discovery flow."""

    @responses.activate
    def test_start_auth_returns_discovery_page(self, context, discovery_backend):
        """start_auth returns HTML discovery page when discovery is enabled."""
        responses.add(
            responses.GET,
            COLLECTION_ENDPOINT,
            json={
                "entities": [
                    {
                        "entity_id": OP_ENTITY_ID,
                        "ui_infos": {
                            "openid_provider": {"display_name": "Test OP"},
                        },
                    },
                    {
                        "entity_id": OP2_ENTITY_ID,
                        "ui_infos": {
                            "federation_entity": {"display_name": "Second OP"},
                        },
                    },
                ]
            },
            status=200,
        )

        internal_req = InternalData()
        resp = discovery_backend.start_auth(context, internal_req)

        assert resp.status == "200 OK"
        html = resp.message
        assert "Test OP" in html
        assert OP_ENTITY_ID in html
        assert "Second OP" in html
        assert OP2_ENTITY_ID in html
        assert "form" in html.lower()
        assert "Test Discovery" in html

    @responses.activate
    def test_start_auth_saves_internal_request(self, context, discovery_backend):
        """start_auth saves internal_request in state for restoration after discovery."""
        responses.add(
            responses.GET, COLLECTION_ENDPOINT,
            json={"entities": []}, status=200,
        )

        internal_req = InternalData()
        discovery_backend.start_auth(context, internal_req)

        backend_state = context.state[discovery_backend.name]
        assert backend_state[DISCOVERY_PENDING_KEY] is True
        assert INTERNAL_REQUEST_KEY in backend_state

    @responses.activate
    def test_discovery_endpoint_selects_op_and_redirects(
        self, context, discovery_backend, ec_keys, op_jwks
    ):
        """POST to /discovery resolves selected OP and redirects to it."""
        internal_req = InternalData()
        context.state[discovery_backend.name] = {
            DISCOVERY_PENDING_KEY: True,
            INTERNAL_REQUEST_KEY: internal_req.to_dict(),
        }

        mock_result = {
            "iss": TA_ENTITY_ID,
            "sub": OP_ENTITY_ID,
            "metadata": {
                "openid_provider": {
                    "issuer": OP_ENTITY_ID,
                    "authorization_endpoint": OP_AUTHORIZATION_ENDPOINT,
                    "token_endpoint": OP_TOKEN_ENDPOINT,
                    "userinfo_endpoint": OP_USERINFO_ENDPOINT,
                    "jwks": op_jwks,
                },
            },
        }

        context.request = {"entity_id": OP_ENTITY_ID}

        with patch(
            "openid_federation_backend.resolve_via_trust_anchors",
            return_value=mock_result,
        ):
            resp = discovery_backend.discovery_endpoint(context)

        assert isinstance(resp, Redirect)
        assert "authorize" in resp.message
        assert "op.example.com" in resp.message

    @responses.activate
    def test_discovery_endpoint_empty_selection_shows_error(
        self, context, discovery_backend
    ):
        """POST without entity_id re-renders discovery page with error."""
        context.state[discovery_backend.name] = {
            DISCOVERY_PENDING_KEY: True,
            INTERNAL_REQUEST_KEY: InternalData().to_dict(),
        }
        context.request = {"entity_id": ""}

        responses.add(
            responses.GET, COLLECTION_ENDPOINT,
            json={"entities": []}, status=200,
        )

        resp = discovery_backend.discovery_endpoint(context)
        assert resp.status == "200 OK"
        assert "Please select" in resp.message

    @responses.activate
    def test_discovery_endpoint_resolution_failure_shows_error(
        self, context, discovery_backend
    ):
        """Failed OP resolution re-renders discovery page with error."""
        context.state[discovery_backend.name] = {
            DISCOVERY_PENDING_KEY: True,
            INTERNAL_REQUEST_KEY: InternalData().to_dict(),
        }
        context.request = {"entity_id": OP_ENTITY_ID}

        responses.add(
            responses.GET, COLLECTION_ENDPOINT,
            json={"entities": []}, status=200,
        )

        with patch(
            "openid_federation_backend.resolve_via_trust_anchors",
            side_effect=FederationError("TA returned 404"),
        ):
            resp = discovery_backend.discovery_endpoint(context)

        assert resp.status == "200 OK"
        assert "Could not resolve" in resp.message

    def test_discovery_endpoint_missing_state_raises(self, context, discovery_backend):
        """Discovery response without session raises SATOSAMissingStateError."""
        context.request = {"entity_id": OP_ENTITY_ID}
        with pytest.raises(SATOSAMissingStateError):
            discovery_backend.discovery_endpoint(context)

    def test_discovery_endpoint_no_pending_flag_raises(self, context, discovery_backend):
        """Discovery response without pending flag raises SATOSAAuthenticationError."""
        context.state[discovery_backend.name] = {NONCE_KEY: "x", STATE_KEY: "y"}
        context.request = {"entity_id": OP_ENTITY_ID}
        with pytest.raises(SATOSAAuthenticationError, match="Unexpected"):
            discovery_backend.discovery_endpoint(context)

    @responses.activate
    def test_collection_endpoint_failure_returns_empty_list(self, context, discovery_backend):
        """If collection endpoint fails, discovery page shows empty state."""
        responses.add(
            responses.GET, COLLECTION_ENDPOINT,
            body="Internal Server Error", status=500,
        )

        internal_req = InternalData()
        resp = discovery_backend.start_auth(context, internal_req)

        assert resp.status == "200 OK"
        assert "No identity providers found" in resp.message

    @responses.activate
    def test_op_list_cached(self, context, discovery_backend):
        """Second call to _fetch_op_list uses cache."""
        responses.add(
            responses.GET, COLLECTION_ENDPOINT,
            json={"entities": [{"entity_id": OP_ENTITY_ID, "ui_infos": {}}]},
            status=200,
        )

        result1 = discovery_backend._fetch_op_list()
        assert len(result1) == 1
        assert len(responses.calls) == 1

        result2 = discovery_backend._fetch_op_list()
        assert result2 == result1
        assert len(responses.calls) == 1  # No new HTTP call


class TestMultiOPFlow:
    """Tests for the full flow with dynamic OP selection via state."""

    @responses.activate
    def test_callback_uses_op_from_state(self, context, discovery_backend, ec_keys, op_jwks):
        """response_endpoint reads op_entity_id from state and uses correct OP."""
        nonce = "nonce-multi"
        state = "state-multi"
        code_verifier, _ = _generate_pkce()

        context.state[discovery_backend.name] = {
            NONCE_KEY: nonce,
            STATE_KEY: state,
            CODE_VERIFIER_KEY: code_verifier,
            "op_entity_id": OP_ENTITY_ID,
        }

        op_key = ec_keys["op"]
        now = int(time.time())
        id_token_claims = {
            "iss": OP_ENTITY_ID, "sub": "user-multi", "aud": RP_ENTITY_ID,
            "iat": now, "exp": now + 3600, "nonce": nonce, "email": "multi@example.com",
        }
        id_token_jwt = _sign_jwt(id_token_claims, op_key)

        responses.add(
            responses.POST, OP_TOKEN_ENDPOINT,
            json={"access_token": "at", "id_token": id_token_jwt}, status=200,
        )
        responses.add(
            responses.GET, OP_USERINFO_ENDPOINT,
            json={"sub": "user-multi", "email": "multi@example.com"}, status=200,
        )

        mock_result = {
            "iss": TA_ENTITY_ID,
            "sub": OP_ENTITY_ID,
            "metadata": {
                "openid_provider": {
                    "issuer": OP_ENTITY_ID,
                    "authorization_endpoint": OP_AUTHORIZATION_ENDPOINT,
                    "token_endpoint": OP_TOKEN_ENDPOINT,
                    "userinfo_endpoint": OP_USERINFO_ENDPOINT,
                    "jwks": op_jwks,
                },
            },
        }

        context.request = {"code": "code-multi", "state": state}

        with patch(
            "openid_federation_backend.resolve_via_trust_anchors",
            return_value=mock_result,
        ):
            discovery_backend.response_endpoint(context)

        discovery_backend.auth_callback_func.assert_called_once()
        internal_resp = discovery_backend.auth_callback_func.call_args[0][1]
        assert internal_resp.subject_id == "user-multi"
        assert internal_resp.attributes["mail"] == ["multi@example.com"]
