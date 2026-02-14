# SPDX-FileCopyrightText: 2026 Kushal Das <kushal@sunet.se>
# SPDX-License-Identifier: BSD-2-Clause
"""
Tests for the OpenID Federation frontend plugin.
"""

import base64
import json
import os
import sys
import time
from unittest.mock import Mock, patch
from urllib.parse import parse_qsl

import pytest
import responses
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from jwkest.jwk import ECKey, RSAKey
from jwkest.jws import JWS
from oic.oic.message import AuthorizationRequest

from satosa.context import Context
from satosa.state import State

# Ensure the plugin directory is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "plugin"))

from openid_federation import (
    OpenIDFederationFrontend,
    FederationError,
    _load_ec_signing_key,
    _int_to_b64url,
    decode_entity_statement,
    keys_from_jwks,
    verify_entity_statement,
    resolve_trust_chain,
    apply_metadata_policies,
    _apply_policy_to_metadata,
    _merge_policies,
)


INTERNAL_ATTRIBUTES = {
    "attributes": {"mail": {"saml": ["email"], "openid": ["email"]}}
}
BASE_URL = "https://op.example.com"
ENTITY_ID = "https://op.example.com"
TA_ENTITY_ID = "https://trust-anchor.example.com"
RP_ENTITY_ID = "https://rp.example.com"
INTERMEDIATE_ENTITY_ID = "https://intermediate.example.com"


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


def _generate_rsa_key():
    """Generate an RSA 2048 key pair and return the private key object."""
    return rsa.generate_private_key(
        public_exponent=65537, key_size=2048, backend=default_backend()
    )


def _save_ec_key_to_file(private_key, path):
    """Save EC private key to PEM file."""
    pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    )
    with open(path, "wb") as f:
        f.write(pem)


def _save_rsa_key_to_file(private_key, path):
    """Save RSA private key to PEM file."""
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


def _make_entity_configuration(entity_id, ec_key, authority_hints=None, metadata=None,
                                trust_marks=None, extra_claims=None):
    """Build and sign an Entity Configuration JWT."""
    now = int(time.time())
    claims = {
        "iss": entity_id,
        "sub": entity_id,
        "iat": now,
        "exp": now + 86400,
        "jwks": {"keys": [ec_key.serialize(private=False)]},
    }
    if authority_hints is not None:
        claims["authority_hints"] = authority_hints
    if metadata is not None:
        claims["metadata"] = metadata
    if trust_marks is not None:
        claims["trust_marks"] = trust_marks
    if extra_claims:
        claims.update(extra_claims)
    return _sign_jwt(claims, ec_key)


def _make_subordinate_statement(issuer_id, subject_id, issuer_key, metadata_policy=None,
                                 extra_claims=None):
    """Build and sign a Subordinate Statement JWT."""
    now = int(time.time())
    claims = {
        "iss": issuer_id,
        "sub": subject_id,
        "iat": now,
        "exp": now + 86400,
    }
    if metadata_policy is not None:
        claims["metadata_policy"] = metadata_policy
    if extra_claims:
        claims.update(extra_claims)
    return _sign_jwt(claims, issuer_key)


# --- Fixtures ---


@pytest.fixture
def ec_keys():
    """Generate EC key pairs for OP, TA, RP, and intermediate."""
    _, op_key = _generate_ec_key()
    _, ta_key = _generate_ec_key()
    _, rp_key = _generate_ec_key()
    _, intermediate_key = _generate_ec_key()
    return {
        "op": op_key,
        "ta": ta_key,
        "rp": rp_key,
        "intermediate": intermediate_key,
    }


@pytest.fixture
def key_files(tmp_path, ec_keys):
    """Create temporary key files for the frontend."""
    # Generate fresh keys for files (need the raw private key objects)
    op_ec_private = ec.generate_private_key(ec.SECP256R1(), default_backend())
    rsa_private = _generate_rsa_key()

    ec_key_path = str(tmp_path / "federation_ec.key")
    rsa_key_path = str(tmp_path / "oidc_signing.key")

    _save_ec_key_to_file(op_ec_private, ec_key_path)
    _save_rsa_key_to_file(rsa_private, rsa_key_path)

    return {
        "ec_key_path": ec_key_path,
        "rsa_key_path": rsa_key_path,
    }


@pytest.fixture
def frontend_config(key_files, ec_keys):
    """Build a frontend configuration dict."""
    ta_pub = ec_keys["ta"].serialize(private=False)
    return {
        "signing_key_path": key_files["rsa_key_path"],
        "signing_key_id": "oidc-key-1",
        "provider": {
            "response_types_supported": ["code"],
            "subject_types_supported": ["pairwise"],
            "scopes_supported": ["openid", "email"],
        },
        "federation": {
            "entity_id": ENTITY_ID,
            "signing_key_path": key_files["ec_key_path"],
            "signing_key_id": "fed-key-1",
            "signing_algorithm": "ES256",
            "authority_hints": [TA_ENTITY_ID],
            "trust_anchors": {
                TA_ENTITY_ID: {
                    "keys": [ta_pub],
                },
            },
            "entity_configuration_lifetime": 86400,
            "rp_cache_ttl": 3600,
            "organization_name": "Test OP",
            "organization_uri": "https://example.com",
            "trust_marks": [],
        },
    }


@pytest.fixture
def frontend(frontend_config):
    """Create an OpenIDFederationFrontend instance."""
    instance = OpenIDFederationFrontend(
        lambda ctx, req: None,
        INTERNAL_ATTRIBUTES,
        frontend_config,
        BASE_URL,
        "oidfed_frontend",
    )
    instance.register_endpoints(["test_backend"])
    return instance


@pytest.fixture
def context():
    ctx = Context()
    ctx.state = State()
    return ctx


# --- Tests ---


class TestEntityConfiguration:
    def test_entity_configuration_endpoint(self, context, frontend):
        """GET .well-known/openid-federation returns JWT with correct content-type."""
        resp = frontend.federation_entity_configuration(context)
        assert resp.status == "200 OK"
        # Check content-type header
        content_types = [v for k, v in resp.headers if k == "Content-Type"]
        assert "application/entity-statement+jwt" in content_types

    def test_entity_configuration_claims(self, context, frontend):
        """JWT contains iss==sub==entity_id, jwks, authority_hints, metadata."""
        resp = frontend.federation_entity_configuration(context)
        claims = decode_entity_statement(resp.message)

        assert claims["iss"] == ENTITY_ID
        assert claims["sub"] == ENTITY_ID
        assert claims["iss"] == claims["sub"]
        assert "jwks" in claims
        assert "keys" in claims["jwks"]
        assert len(claims["jwks"]["keys"]) >= 1
        assert claims["authority_hints"] == [TA_ENTITY_ID]
        assert "metadata" in claims
        assert "openid_provider" in claims["metadata"]
        assert "federation_entity" in claims["metadata"]
        assert claims["metadata"]["federation_entity"]["organization_name"] == "Test OP"
        assert "iat" in claims
        assert "exp" in claims

    def test_entity_configuration_self_signed(self, context, frontend):
        """JWT signature is verifiable with the embedded jwks."""
        resp = frontend.federation_entity_configuration(context)
        jwt_str = resp.message
        claims = decode_entity_statement(jwt_str)
        # Should not raise
        verified = verify_entity_statement(jwt_str, claims["jwks"])
        assert verified["iss"] == ENTITY_ID

    def test_key_separation(self, context, frontend):
        """Federation jwks uses EC, OIDC jwks uses RSA."""
        # Federation key
        resp = frontend.federation_entity_configuration(context)
        claims = decode_entity_statement(resp.message)
        fed_keys = claims["jwks"]["keys"]
        assert all(k["kty"] == "EC" for k in fed_keys)

        # OIDC key
        oidc_jwks = frontend.provider.jwks
        oidc_keys = oidc_jwks["keys"]
        assert all(k["kty"] == "RSA" for k in oidc_keys)


class TestOIDCDiscovery:
    def test_oidc_discovery_still_works(self, context, frontend):
        """.well-known/openid-configuration returns valid OIDC metadata."""
        resp = frontend.provider_config(context)
        config = json.loads(resp.message)
        assert "issuer" in config
        assert config["issuer"] == BASE_URL
        assert "authorization_endpoint" in config
        assert "response_types_supported" in config


class TestAutoRegistration:
    def test_auto_register_known_client(self, context, frontend):
        """Pre-registered client proceeds without federation lookup."""
        client_id = "pre-registered-client"
        redirect_uri = "https://client.example.com/callback"
        frontend.provider.clients[client_id] = {
            "client_id": client_id,
            "response_types": ["code"],
            "redirect_uris": [redirect_uri],
            "client_secret": "secret",
        }

        mock_callback = Mock()
        frontend.auth_req_callback_func = mock_callback

        authn_req = AuthorizationRequest(
            client_id=client_id,
            response_type="code",
            scope="openid",
            redirect_uri=redirect_uri,
            state="test_state",
            nonce="test_nonce",
        )
        context.request = dict(parse_qsl(authn_req.to_urlencoded()))

        # Should not make any HTTP requests since client is already registered
        with responses.RequestsMock() as rsps:
            frontend.handle_authn_request(context)

        assert mock_callback.call_count == 1

    @responses.activate
    def test_auto_register_via_federation(self, context, frontend, ec_keys):
        """Unknown client_id triggers trust chain resolution and registration."""
        rp_key = ec_keys["rp"]
        ta_key = ec_keys["ta"]

        rp_redirect_uri = "https://rp.example.com/callback"

        # RP Entity Configuration
        rp_ec_jwt = _make_entity_configuration(
            RP_ENTITY_ID,
            rp_key,
            authority_hints=[TA_ENTITY_ID],
            metadata={
                "openid_relying_party": {
                    "redirect_uris": [rp_redirect_uri],
                    "response_types": ["code"],
                    "client_name": "Test RP",
                    "token_endpoint_auth_method": "none",
                },
            },
        )
        responses.add(
            responses.GET,
            f"{RP_ENTITY_ID}/.well-known/openid-federation",
            body=rp_ec_jwt,
            status=200,
        )

        # TA Entity Configuration
        ta_ec_jwt = _make_entity_configuration(
            TA_ENTITY_ID,
            ta_key,
            metadata={
                "federation_entity": {
                    "federation_fetch_endpoint": f"{TA_ENTITY_ID}/fetch",
                },
            },
        )
        responses.add(
            responses.GET,
            f"{TA_ENTITY_ID}/.well-known/openid-federation",
            body=ta_ec_jwt,
            status=200,
        )

        # TA's subordinate statement about the RP
        sub_stmt_jwt = _make_subordinate_statement(
            TA_ENTITY_ID, RP_ENTITY_ID, ta_key
        )
        responses.add(
            responses.GET,
            f"{TA_ENTITY_ID}/fetch",
            body=sub_stmt_jwt,
            status=200,
        )

        # Now send an auth request from the unknown RP
        mock_callback = Mock()
        frontend.auth_req_callback_func = mock_callback

        authn_req = AuthorizationRequest(
            client_id=RP_ENTITY_ID,
            response_type="code",
            scope="openid",
            redirect_uri=rp_redirect_uri,
            state="test_state",
            nonce="test_nonce",
        )
        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        frontend.handle_authn_request(context)

        # Client should now be registered
        assert RP_ENTITY_ID in frontend.provider.clients
        client_info = frontend.provider.clients[RP_ENTITY_ID]
        assert rp_redirect_uri in client_info["redirect_uris"]
        assert mock_callback.call_count == 1

    @responses.activate
    def test_auto_register_untrusted_rp_rejected(self, context, frontend, ec_keys):
        """RP whose trust chain doesn't reach a configured TA is rejected."""
        rp_key = ec_keys["rp"]

        # RP claims an authority hint that's not a configured TA
        unknown_authority = "https://unknown-authority.example.com"
        _, unknown_key = _generate_ec_key()

        rp_ec_jwt = _make_entity_configuration(
            RP_ENTITY_ID,
            rp_key,
            authority_hints=[unknown_authority],
            metadata={
                "openid_relying_party": {
                    "redirect_uris": ["https://rp.example.com/callback"],
                },
            },
        )
        responses.add(
            responses.GET,
            f"{RP_ENTITY_ID}/.well-known/openid-federation",
            body=rp_ec_jwt,
            status=200,
        )

        # Unknown authority's entity config - no fetch endpoint
        unknown_ec_jwt = _make_entity_configuration(
            unknown_authority,
            unknown_key,
            metadata={
                "federation_entity": {
                    "federation_fetch_endpoint": f"{unknown_authority}/fetch",
                },
            },
        )
        responses.add(
            responses.GET,
            f"{unknown_authority}/.well-known/openid-federation",
            body=unknown_ec_jwt,
            status=200,
        )

        # Subordinate statement from unknown authority
        sub_stmt_jwt = _make_subordinate_statement(
            unknown_authority, RP_ENTITY_ID, unknown_key
        )
        responses.add(
            responses.GET,
            f"{unknown_authority}/fetch",
            body=sub_stmt_jwt,
            status=200,
        )

        authn_req = AuthorizationRequest(
            client_id=RP_ENTITY_ID,
            response_type="code",
            scope="openid",
            redirect_uri="https://rp.example.com/callback",
            state="test_state",
            nonce="test_nonce",
        )
        context.request = dict(parse_qsl(authn_req.to_urlencoded()))
        resp = frontend.handle_authn_request(context)

        # Should return BadRequest
        assert resp.status == "400 Bad Request"
        assert RP_ENTITY_ID not in frontend.provider.clients

    @responses.activate
    def test_auto_register_expired_chain_rejected(self, context, frontend, ec_keys):
        """Expired entity statements cause rejection."""
        rp_key = ec_keys["rp"]

        # RP Entity Configuration with expired timestamps
        now = int(time.time())
        rp_claims = {
            "iss": RP_ENTITY_ID,
            "sub": RP_ENTITY_ID,
            "iat": now - 200000,
            "exp": now - 100000,  # expired
            "jwks": {"keys": [rp_key.serialize(private=False)]},
            "authority_hints": [TA_ENTITY_ID],
            "metadata": {
                "openid_relying_party": {
                    "redirect_uris": ["https://rp.example.com/callback"],
                },
            },
        }
        rp_ec_jwt = _sign_jwt(rp_claims, rp_key)
        responses.add(
            responses.GET,
            f"{RP_ENTITY_ID}/.well-known/openid-federation",
            body=rp_ec_jwt,
            status=200,
        )

        # TA with expired entity configuration
        ta_key = ec_keys["ta"]
        ta_claims = {
            "iss": TA_ENTITY_ID,
            "sub": TA_ENTITY_ID,
            "iat": now - 200000,
            "exp": now - 100000,  # expired
            "jwks": {"keys": [ta_key.serialize(private=False)]},
            "metadata": {
                "federation_entity": {
                    "federation_fetch_endpoint": f"{TA_ENTITY_ID}/fetch",
                },
            },
        }
        ta_ec_jwt = _sign_jwt(ta_claims, ta_key)
        responses.add(
            responses.GET,
            f"{TA_ENTITY_ID}/.well-known/openid-federation",
            body=ta_ec_jwt,
            status=200,
        )

        # Expired subordinate statement
        sub_claims = {
            "iss": TA_ENTITY_ID,
            "sub": RP_ENTITY_ID,
            "iat": now - 200000,
            "exp": now - 100000,  # expired
        }
        sub_stmt_jwt = _sign_jwt(sub_claims, ta_key)
        responses.add(
            responses.GET,
            f"{TA_ENTITY_ID}/fetch",
            body=sub_stmt_jwt,
            status=200,
        )

        authn_req = AuthorizationRequest(
            client_id=RP_ENTITY_ID,
            response_type="code",
            scope="openid",
            redirect_uri="https://rp.example.com/callback",
            state="test_state",
            nonce="test_nonce",
        )
        context.request = dict(parse_qsl(authn_req.to_urlencoded()))

        resp = frontend.handle_authn_request(context)
        # Expired chain should be rejected
        assert resp.status == "400 Bad Request"
        assert RP_ENTITY_ID not in frontend.provider.clients


class TestMetadataPolicy:
    def test_metadata_policy_applied(self):
        """Metadata policies from subordinate statements are correctly applied."""
        _, rp_key = _generate_ec_key()
        _, ta_key = _generate_ec_key()

        now = int(time.time())
        leaf_config = {
            "iss": RP_ENTITY_ID,
            "sub": RP_ENTITY_ID,
            "iat": now,
            "exp": now + 86400,
            "jwks": {"keys": [rp_key.serialize(private=False)]},
            "authority_hints": [TA_ENTITY_ID],
            "metadata": {
                "openid_relying_party": {
                    "redirect_uris": ["https://rp.example.com/callback"],
                    "response_types": ["code"],
                    "client_name": "Test RP",
                },
            },
        }

        sub_stmt = {
            "iss": TA_ENTITY_ID,
            "sub": RP_ENTITY_ID,
            "iat": now,
            "exp": now + 86400,
            "metadata_policy": {
                "openid_relying_party": {
                    "token_endpoint_auth_method": {
                        "default": "client_secret_basic",
                    },
                    "response_types": {
                        "subset_of": ["code", "code id_token"],
                    },
                },
            },
        }

        ta_config = {
            "iss": TA_ENTITY_ID,
            "sub": TA_ENTITY_ID,
            "iat": now,
            "exp": now + 86400,
            "jwks": {"keys": [ta_key.serialize(private=False)]},
        }

        chain = [leaf_config, sub_stmt, ta_config]
        resolved = apply_metadata_policies(chain)

        rp_meta = resolved["openid_relying_party"]
        assert rp_meta["token_endpoint_auth_method"] == "client_secret_basic"
        assert rp_meta["response_types"] == ["code"]
        assert rp_meta["redirect_uris"] == ["https://rp.example.com/callback"]

    def test_policy_one_of_violation(self):
        """Policy violation on one_of raises FederationError."""
        metadata = {"grant_types": "implicit"}
        policy = {
            "grant_types": {
                "one_of": ["authorization_code"],
            },
        }
        with pytest.raises(FederationError, match="not in"):
            _apply_policy_to_metadata(metadata, policy)

    def test_policy_subset_of_violation(self):
        """Policy violation on subset_of raises FederationError."""
        metadata = {"response_types": ["code", "token"]}
        policy = {
            "response_types": {
                "subset_of": ["code"],
            },
        }
        with pytest.raises(FederationError, match="not subset"):
            _apply_policy_to_metadata(metadata, policy)

    def test_policy_superset_of_violation(self):
        """Policy violation on superset_of raises FederationError."""
        metadata = {"scopes": ["openid"]}
        policy = {
            "scopes": {
                "superset_of": ["openid", "email"],
            },
        }
        with pytest.raises(FederationError, match="not superset"):
            _apply_policy_to_metadata(metadata, policy)

    def test_policy_essential_missing(self):
        """Policy violation on essential raises FederationError."""
        metadata = {}
        policy = {
            "redirect_uris": {
                "essential": True,
            },
        }
        with pytest.raises(FederationError, match="essential but missing"):
            _apply_policy_to_metadata(metadata, policy)

    def test_policy_value_operator(self):
        """Value operator forces a specific value."""
        metadata = {"token_endpoint_auth_method": "client_secret_post"}
        policy = {
            "token_endpoint_auth_method": {
                "value": "private_key_jwt",
            },
        }
        result = _apply_policy_to_metadata(metadata, policy)
        assert result["token_endpoint_auth_method"] == "private_key_jwt"

    def test_policy_add_operator(self):
        """Add operator adds values to a list."""
        metadata = {"scopes": ["openid"]}
        policy = {
            "scopes": {
                "add": ["email"],
            },
        }
        result = _apply_policy_to_metadata(metadata, policy)
        assert set(result["scopes"]) == {"openid", "email"}


class TestRPCache:
    @responses.activate
    def test_rp_cache_used(self, context, frontend, ec_keys):
        """Second request for same RP uses cache instead of re-fetching."""
        rp_key = ec_keys["rp"]
        ta_key = ec_keys["ta"]
        rp_redirect_uri = "https://rp.example.com/callback"

        # RP Entity Configuration
        rp_ec_jwt = _make_entity_configuration(
            RP_ENTITY_ID,
            rp_key,
            authority_hints=[TA_ENTITY_ID],
            metadata={
                "openid_relying_party": {
                    "redirect_uris": [rp_redirect_uri],
                    "response_types": ["code"],
                    "client_name": "Test RP",
                    "token_endpoint_auth_method": "none",
                },
            },
        )
        responses.add(
            responses.GET,
            f"{RP_ENTITY_ID}/.well-known/openid-federation",
            body=rp_ec_jwt,
            status=200,
        )

        # TA Entity Configuration
        ta_ec_jwt = _make_entity_configuration(
            TA_ENTITY_ID,
            ta_key,
            metadata={
                "federation_entity": {
                    "federation_fetch_endpoint": f"{TA_ENTITY_ID}/fetch",
                },
            },
        )
        responses.add(
            responses.GET,
            f"{TA_ENTITY_ID}/.well-known/openid-federation",
            body=ta_ec_jwt,
            status=200,
        )

        # Subordinate statement
        sub_stmt_jwt = _make_subordinate_statement(
            TA_ENTITY_ID, RP_ENTITY_ID, ta_key
        )
        responses.add(
            responses.GET,
            f"{TA_ENTITY_ID}/fetch",
            body=sub_stmt_jwt,
            status=200,
        )

        # First registration - should make HTTP requests
        frontend._auto_register_client(RP_ENTITY_ID)
        assert RP_ENTITY_ID in frontend.provider.clients

        # Count how many HTTP calls were made
        first_call_count = len(responses.calls)
        assert first_call_count > 0

        # Remove from client DB to force re-registration
        del frontend.provider.clients[RP_ENTITY_ID]

        # Second registration - should use cache, no new HTTP calls
        frontend._auto_register_client(RP_ENTITY_ID)
        assert RP_ENTITY_ID in frontend.provider.clients
        assert len(responses.calls) == first_call_count  # No new HTTP calls


class TestConfiguration:
    def test_missing_federation_config_raises(self, key_files):
        """Config without 'federation' block raises ValueError."""
        config = {
            "signing_key_path": key_files["rsa_key_path"],
            "provider": {
                "response_types_supported": ["code"],
                "scopes_supported": ["openid"],
            },
        }
        with pytest.raises(ValueError, match="federation"):
            OpenIDFederationFrontend(
                lambda ctx, req: None,
                INTERNAL_ATTRIBUTES,
                config,
                BASE_URL,
                "test",
            )


class TestTrustChainResolution:
    @responses.activate
    def test_resolve_trust_chain_single_hop(self, ec_keys):
        """RP -> Trust Anchor (direct) resolves correctly."""
        rp_key = ec_keys["rp"]
        ta_key = ec_keys["ta"]

        trust_anchors = {
            TA_ENTITY_ID: {"keys": [ta_key.serialize(private=False)]},
        }

        # RP Entity Configuration
        rp_ec_jwt = _make_entity_configuration(
            RP_ENTITY_ID,
            rp_key,
            authority_hints=[TA_ENTITY_ID],
            metadata={
                "openid_relying_party": {
                    "redirect_uris": ["https://rp.example.com/callback"],
                },
            },
        )
        responses.add(
            responses.GET,
            f"{RP_ENTITY_ID}/.well-known/openid-federation",
            body=rp_ec_jwt,
            status=200,
        )

        # TA Entity Configuration
        ta_ec_jwt = _make_entity_configuration(
            TA_ENTITY_ID,
            ta_key,
            metadata={
                "federation_entity": {
                    "federation_fetch_endpoint": f"{TA_ENTITY_ID}/fetch",
                },
            },
        )
        responses.add(
            responses.GET,
            f"{TA_ENTITY_ID}/.well-known/openid-federation",
            body=ta_ec_jwt,
            status=200,
        )

        # Subordinate statement
        sub_stmt_jwt = _make_subordinate_statement(
            TA_ENTITY_ID, RP_ENTITY_ID, ta_key
        )
        responses.add(
            responses.GET,
            f"{TA_ENTITY_ID}/fetch",
            body=sub_stmt_jwt,
            status=200,
        )

        chain = resolve_trust_chain(RP_ENTITY_ID, trust_anchors)
        assert len(chain) == 3  # leaf, sub_stmt, ta_config
        assert chain[0]["iss"] == RP_ENTITY_ID
        assert chain[2]["iss"] == TA_ENTITY_ID

    @responses.activate
    def test_resolve_trust_chain_multi_hop(self, ec_keys):
        """RP -> Intermediate -> Trust Anchor resolves correctly."""
        rp_key = ec_keys["rp"]
        ta_key = ec_keys["ta"]
        int_key = ec_keys["intermediate"]

        trust_anchors = {
            TA_ENTITY_ID: {"keys": [ta_key.serialize(private=False)]},
        }

        # RP Entity Configuration - points to intermediate
        rp_ec_jwt = _make_entity_configuration(
            RP_ENTITY_ID,
            rp_key,
            authority_hints=[INTERMEDIATE_ENTITY_ID],
            metadata={
                "openid_relying_party": {
                    "redirect_uris": ["https://rp.example.com/callback"],
                },
            },
        )
        responses.add(
            responses.GET,
            f"{RP_ENTITY_ID}/.well-known/openid-federation",
            body=rp_ec_jwt,
            status=200,
        )

        # Intermediate Entity Configuration - points to TA
        int_ec_jwt = _make_entity_configuration(
            INTERMEDIATE_ENTITY_ID,
            int_key,
            authority_hints=[TA_ENTITY_ID],
            metadata={
                "federation_entity": {
                    "federation_fetch_endpoint": f"{INTERMEDIATE_ENTITY_ID}/fetch",
                },
            },
        )
        responses.add(
            responses.GET,
            f"{INTERMEDIATE_ENTITY_ID}/.well-known/openid-federation",
            body=int_ec_jwt,
            status=200,
        )

        # Intermediate's subordinate statement about RP
        int_sub_stmt_jwt = _make_subordinate_statement(
            INTERMEDIATE_ENTITY_ID, RP_ENTITY_ID, int_key
        )
        responses.add(
            responses.GET,
            f"{INTERMEDIATE_ENTITY_ID}/fetch",
            body=int_sub_stmt_jwt,
            status=200,
        )

        # TA Entity Configuration
        ta_ec_jwt = _make_entity_configuration(
            TA_ENTITY_ID,
            ta_key,
            metadata={
                "federation_entity": {
                    "federation_fetch_endpoint": f"{TA_ENTITY_ID}/fetch",
                },
            },
        )
        responses.add(
            responses.GET,
            f"{TA_ENTITY_ID}/.well-known/openid-federation",
            body=ta_ec_jwt,
            status=200,
        )

        # TA's subordinate statement about intermediate
        ta_sub_stmt_jwt = _make_subordinate_statement(
            TA_ENTITY_ID, INTERMEDIATE_ENTITY_ID, ta_key
        )
        responses.add(
            responses.GET,
            f"{TA_ENTITY_ID}/fetch",
            body=ta_sub_stmt_jwt,
            status=200,
        )

        chain = resolve_trust_chain(RP_ENTITY_ID, trust_anchors)
        # chain should be: [rp_config, int_sub_stmt, int_config, ta_sub_stmt, ta_config]
        assert len(chain) == 5
        assert chain[0]["iss"] == RP_ENTITY_ID
        assert chain[2]["iss"] == INTERMEDIATE_ENTITY_ID
        assert chain[4]["iss"] == TA_ENTITY_ID
