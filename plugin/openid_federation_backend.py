# SPDX-FileCopyrightText: 2026 Kushal Das <kushal@sunet.se>
# SPDX-License-Identifier: BSD-2-Clause
"""
OpenID Federation 1.0 backend plugin for SATOSA.

This plugin extends SATOSA's BackendModule to act as a federation-aware
OpenID Connect Relying Party (RP). It connects upstream to federation OPs
(discovered via Trust Anchor resolve endpoints) and translates OIDC responses
into SATOSA InternalData for downstream frontends (e.g., SAMLFrontend).

Architecture & Request Flow
----------------------------

  SAML SP                                                        Federation OP
    │                                                                  │
    │  1. SAML AuthnRequest → SAMLFrontend (IdP)                      │
    │     └─ SATOSA routes to this backend                             │
    │                                                                  │
    │  2. start_auth():                                                │
    │     ├─ [Discovery mode] Show OP selection page                   │
    │     ├─ Generate PKCE code_verifier + code_challenge              │
    │     ├─ Build signed request object JWT (RFC 9101)                │
    │     └─ Redirect to OP's authorization endpoint                   │
    │              │                                                   │
    │              └─ GET /authorization?client_id=<rp>&request=<jwt> ─►│
    │                                                                  │
    │  3. OP resolves RP's trust chain, authenticates user              │
    │              ◄──── Redirect with authorization code ─────────────│
    │                                                                  │
    │  4. response_endpoint():                                         │
    │     ├─ Exchange code via private_key_jwt at token endpoint        │
    │     ├─ Verify id_token JWT against OP's JWKS                     │
    │     ├─ Fetch userinfo                                            │
    │     └─ Convert to InternalData → SAMLFrontend                    │

Key Design Decisions
---------------------

- **Single federation key:** One EC P-256 key signs the Entity Configuration,
  request objects, and client_assertion JWTs. This is the standard federation
  RP pattern — the OP verifies all three using the RP's federation JWKS.

- **OP discovery:** When enabled, queries the Trust Anchor's collection
  endpoint for available OPs and presents an HTML selection page. The
  selected OP's metadata is resolved via trust chain and cached.

- **PKCE:** Always used (S256 code_challenge_method) per federation best
  practices.

Dependencies
-------------
- jwkest: JWT signing/verification (ECKey, JWS)
- requests: HTTP client for federation and OIDC endpoints
- openid_federation: Reuses helpers from the frontend plugin
"""

import base64
import hashlib
import json
import logging
import os
import time
import uuid
from datetime import datetime
from urllib.parse import urlencode

import requests as http_requests
from jwkest.jwk import ECKey
from jwkest.jws import JWS
from oic.utils.authn.authn_context import UNSPECIFIED

import satosa.logging_util as lu
from satosa.backends.base import BackendModule
from satosa.exception import SATOSAAuthenticationError, SATOSAMissingStateError
from satosa.internal import AuthenticationInformation, InternalData
from satosa.response import Redirect, Response

from openid_federation import (
    FederationError,
    _load_ec_signing_key,
    _build_trust_anchor_keys,
    fetch_entity_configuration,
    decode_entity_statement,
    verify_entity_statement,
    keys_from_jwks,
    resolve_via_trust_anchors,
)

logger = logging.getLogger(__name__)

NONCE_KEY = "oidc_nonce"
STATE_KEY = "oidc_state"
CODE_VERIFIER_KEY = "code_verifier"
INTERNAL_REQUEST_KEY = "internal_request"
DISCOVERY_PENDING_KEY = "discovery_pending"


def _generate_pkce():
    """Generate PKCE code_verifier and S256 code_challenge.

    Returns (code_verifier, code_challenge) tuple.
    """
    code_verifier = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b"=").decode("ascii")
    code_challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode("ascii")).digest())
        .rstrip(b"=")
        .decode("ascii")
    )
    return code_verifier, code_challenge


def _html_escape(text):
    """Minimal HTML escaping for user-visible strings."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


class _OPMetadataCache:
    """In-memory cache for resolved OP metadata with TTL expiry."""

    def __init__(self, ttl=3600):
        self._cache = {}
        self._ttl = ttl

    def get(self, entity_id):
        """Return cached metadata or None if missing/expired."""
        entry = self._cache.get(entity_id)
        if entry and entry["exp"] > time.time():
            return entry["metadata"]
        return None

    def put(self, entity_id, metadata):
        """Cache metadata with TTL."""
        self._cache[entity_id] = {
            "metadata": metadata,
            "exp": time.time() + self._ttl,
        }


class _OPListCache:
    """Cache for the federation OP listing from the collection endpoint."""

    def __init__(self, ttl=300):
        self._entities = None
        self._exp = 0
        self._ttl = ttl

    def get(self):
        """Return cached entity list or None if expired."""
        if self._entities is not None and self._exp > time.time():
            return self._entities
        return None

    def put(self, entities):
        """Cache the entity list."""
        self._entities = entities
        self._exp = time.time() + self._ttl


class OpenIDFederationBackend(BackendModule):
    """SATOSA backend that acts as an OpenID Federation RP.

    Connects to upstream federation OPs using trust chain resolution,
    signed request objects (RFC 9101), and private_key_jwt authentication.
    Publishes an Entity Configuration so OPs can resolve this RP's trust chain.

    Supports two modes:
    - **Single OP mode** (default): Uses a preconfigured op_entity_id, resolved at startup.
    - **Discovery mode**: Queries the TA's collection endpoint to list available OPs
      and presents a selection page to the user.
    """

    def __init__(self, auth_callback_func, internal_attributes, config, base_url, name):
        super().__init__(auth_callback_func, internal_attributes, base_url, name)
        self.config = config

        fed_config = config["federation"]

        # Load federation signing key (EC P-256)
        self.federation_signing_key = _load_ec_signing_key(
            fed_config["signing_key_path"],
            kid=fed_config.get("signing_key_id", "rp-fed-key"),
        )
        self.federation_signing_alg = fed_config.get("signing_algorithm", "ES256")

        # Entity identity
        self.entity_id = config["entity_id"]
        self.authority_hints = fed_config.get("authority_hints", [])
        self.organization_name = fed_config.get("organization_name", "")

        # Trust marks
        self.trust_marks = fed_config.get("trust_marks", [])
        for i, tm in enumerate(self.trust_marks):
            if not isinstance(tm, dict) or "id" not in tm or "trust_mark" not in tm:
                raise ValueError(
                    f"trust_marks[{i}]: each entry must have 'id' and 'trust_mark' keys"
                )

        # Trust anchors
        self.trust_anchors = _build_trust_anchor_keys(fed_config["trust_anchors"])

        # Entity Configuration lifetime
        self.entity_configuration_lifetime = fed_config.get(
            "entity_configuration_lifetime", 86400
        )

        # OIDC parameters
        self.scope = config.get("scope", "openid")
        self.redirect_uri = f"{base_url}/{name}/callback"

        # Discovery configuration
        discovery_config = config.get("discovery", {})
        self.enable_discovery = discovery_config.get("enable", False)
        self.collection_endpoint = discovery_config.get("collection_endpoint")
        self.discovery_page_title = discovery_config.get(
            "page_title", "Select Identity Provider"
        )
        cache_ttl = discovery_config.get("cache_ttl", 3600)

        # Caches
        self._op_metadata_cache = _OPMetadataCache(ttl=cache_ttl)
        self._op_list_cache = _OPListCache(ttl=min(cache_ttl, 300))

        # Resolve upstream OP metadata
        self.op_entity_id = config.get("op_entity_id")

        if self.op_entity_id and not self.enable_discovery:
            # Single OP mode: resolve at startup
            self._resolve_and_set_op_metadata(self.op_entity_id)
        elif not self.enable_discovery and not self.op_entity_id:
            raise ValueError(
                "Either 'op_entity_id' must be set or 'discovery.enable' must be true"
            )

    def _resolve_and_set_op_metadata(self, op_entity_id):
        """Resolve OP metadata via trust chain and cache it.

        Returns dict with keys: authorization_endpoint, token_endpoint,
        userinfo_endpoint, issuer, jwks.
        """
        cached = self._op_metadata_cache.get(op_entity_id)
        if cached:
            return cached

        try:
            resolve_result = resolve_via_trust_anchors(
                op_entity_id, self.trust_anchors
            )
            op_metadata = resolve_result.get("metadata", {}).get("openid_provider", {})
            if not op_metadata:
                raise FederationError(
                    f"No openid_provider metadata in resolve result for {op_entity_id}"
                )

            # Extract JWKS
            op_jwks = op_metadata.get("jwks", {"keys": []})
            if not op_jwks.get("keys") and "jwks_uri" in op_metadata:
                resp = http_requests.get(op_metadata["jwks_uri"], timeout=10)
                resp.raise_for_status()
                op_jwks = resp.json()
            if not op_jwks.get("keys"):
                op_jwks = resolve_result.get("jwks", {"keys": []})

            result = {
                "authorization_endpoint": op_metadata["authorization_endpoint"],
                "token_endpoint": op_metadata["token_endpoint"],
                "userinfo_endpoint": op_metadata.get("userinfo_endpoint"),
                "issuer": op_metadata.get("issuer", op_entity_id),
                "jwks": op_jwks,
            }

            self._op_metadata_cache.put(op_entity_id, result)

            logger.info(
                "Resolved OP metadata for %s: auth=%s token=%s",
                op_entity_id,
                result["authorization_endpoint"],
                result["token_endpoint"],
            )
            return result
        except Exception as e:
            logger.error("Failed to resolve OP metadata for %s: %s", op_entity_id, e)
            raise

    def _fetch_op_list(self):
        """Fetch available OPs from the Trust Anchor's collection endpoint.

        Returns list of dicts: [{"entity_id": str, "display_name": str, "logo_uri": str}, ...]
        """
        cached = self._op_list_cache.get()
        if cached is not None:
            return cached

        if not self.collection_endpoint:
            logger.warning("Discovery enabled but no collection_endpoint configured")
            return []

        try:
            resp = http_requests.get(
                self.collection_endpoint,
                params={"entity_type": "openid_provider"},
                timeout=15,
            )
            resp.raise_for_status()
            data = resp.json()
        except Exception as e:
            logger.error(
                "Failed to fetch OP list from %s: %s", self.collection_endpoint, e
            )
            return []

        entities = []
        for entity in data.get("entities", []):
            ui = entity.get("ui_infos", {})
            op_ui = ui.get("openid_provider", {})
            fe_ui = ui.get("federation_entity", {})
            entities.append(
                {
                    "entity_id": entity["entity_id"],
                    "display_name": (
                        op_ui.get("display_name")
                        or fe_ui.get("display_name")
                        or entity["entity_id"]
                    ),
                    "logo_uri": (
                        op_ui.get("logo_uri") or fe_ui.get("logo_uri") or ""
                    ),
                }
            )

        self._op_list_cache.put(entities)
        return entities

    def register_endpoints(self):
        """Register the callback, entity configuration, and discovery endpoints."""
        endpoints = [
            (f"^{self.name}/callback$", self.response_endpoint),
            (f"^{self.name}/entity-configuration$", self.entity_configuration_endpoint),
        ]

        if self.enable_discovery:
            endpoints.append(
                (f"^{self.name}/discovery$", self.discovery_endpoint),
            )

        return endpoints

    def entity_configuration_endpoint(self, context):
        """Serve the RP's Entity Configuration as a self-signed JWT.

        Published at /{name}/entity-configuration (Caddy rewrites
        /.well-known/openid-federation to this path).

        Contains openid_relying_party metadata so OPs can discover
        this RP's redirect_uris, supported response types, and JWKS.
        """
        now = int(time.time())

        rp_metadata = {
            "redirect_uris": [self.redirect_uri],
            "response_types": ["code"],
            "grant_types": ["authorization_code"],
            "token_endpoint_auth_method": "private_key_jwt",
            "token_endpoint_auth_signing_alg": self.federation_signing_alg,
            "client_registration_types": ["automatic"],
            "jwks": {"keys": [self.federation_signing_key.serialize(private=False)]},
        }

        ec_claims = {
            "iss": self.entity_id,
            "sub": self.entity_id,
            "iat": now,
            "exp": now + self.entity_configuration_lifetime,
            "jwks": {"keys": [self.federation_signing_key.serialize(private=False)]},
            "authority_hints": self.authority_hints,
            "metadata": {
                "openid_relying_party": rp_metadata,
            },
        }

        if self.organization_name:
            ec_claims["metadata"]["federation_entity"] = {
                "organization_name": self.organization_name,
            }

        if self.trust_marks:
            ec_claims["trust_marks"] = self.trust_marks

        _jws = JWS(json.dumps(ec_claims), alg=self.federation_signing_alg)
        jwt_str = _jws.sign_compact(
            keys=[self.federation_signing_key],
            protected={"typ": "entity-statement+jwt", "kid": self.federation_signing_key.kid},
        )

        return Response(jwt_str, content="application/entity-statement+jwt")

    def start_auth(self, context, internal_request):
        """Initiate OIDC authorization with an upstream federation OP.

        If discovery is enabled, shows an OP selection page. Otherwise
        redirects directly to the configured OP's authorization endpoint.
        """
        if self.enable_discovery:
            context.state[self.name] = {
                DISCOVERY_PENDING_KEY: True,
                INTERNAL_REQUEST_KEY: internal_request.to_dict(),
            }
            op_list = self._fetch_op_list()
            return self._render_discovery_page(op_list)

        return self._start_auth_with_op(context, internal_request, self.op_entity_id)

    def _start_auth_with_op(self, context, internal_request, op_entity_id):
        """Start OIDC auth flow with a specific OP.

        Resolves OP metadata (from cache or federation), generates PKCE,
        builds a signed request object, and redirects to the OP.
        """
        op_meta = self._resolve_and_set_op_metadata(op_entity_id)

        oidc_nonce = str(uuid.uuid4())
        oidc_state = str(uuid.uuid4())
        code_verifier, code_challenge = _generate_pkce()

        # Store state for the callback
        context.state[self.name] = {
            NONCE_KEY: oidc_nonce,
            STATE_KEY: oidc_state,
            CODE_VERIFIER_KEY: code_verifier,
            "op_entity_id": op_entity_id,
        }

        # Build signed request object (RFC 9101)
        now = int(time.time())
        request_claims = {
            "iss": self.entity_id,
            "aud": op_entity_id,
            "iat": now,
            "exp": now + 300,
            "jti": str(uuid.uuid4()),
            "client_id": self.entity_id,
            "response_type": "code",
            "scope": self.scope,
            "redirect_uri": self.redirect_uri,
            "state": oidc_state,
            "nonce": oidc_nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        _jws = JWS(json.dumps(request_claims), alg=self.federation_signing_alg)
        request_jwt = _jws.sign_compact(
            keys=[self.federation_signing_key],
            protected={"kid": self.federation_signing_key.kid},
        )

        # Redirect to OP's authorization endpoint
        auth_params = {
            "client_id": self.entity_id,
            "request": request_jwt,
            "response_type": "code",
            "scope": self.scope,
        }
        auth_url = f"{op_meta['authorization_endpoint']}?{urlencode(auth_params)}"

        msg = f"Redirecting to OP authorization: {op_entity_id}"
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)

        return Redirect(auth_url)

    def discovery_endpoint(self, context, *args):
        """Handle the user's OP selection from the discovery page.

        Extracts the selected OP entity_id, resolves its metadata,
        restores the original internal_request from state, and initiates
        the OIDC authorization flow with the chosen OP.
        """
        if self.name not in context.state:
            raise SATOSAMissingStateError(
                "Discovery response received without SATOSA session"
            )

        backend_state = context.state[self.name]
        if not backend_state.get(DISCOVERY_PENDING_KEY):
            raise SATOSAAuthenticationError(
                context.state, "Unexpected discovery response"
            )

        selected_op = context.request.get("entity_id", "").strip()
        if not selected_op:
            op_list = self._fetch_op_list()
            return self._render_discovery_page(
                op_list, error="Please select an identity provider."
            )

        # Restore the original internal_request
        internal_request_data = backend_state.get(INTERNAL_REQUEST_KEY, {})
        internal_request = InternalData.from_dict(internal_request_data)

        try:
            return self._start_auth_with_op(context, internal_request, selected_op)
        except FederationError as e:
            logger.error("Failed to resolve OP %s: %s", selected_op, e)
            op_list = self._fetch_op_list()
            return self._render_discovery_page(
                op_list,
                error=f"Could not resolve the selected provider: {e}",
            )

    def _render_discovery_page(self, op_list, error=None):
        """Render a self-contained HTML page for OP selection."""
        error_html = ""
        if error:
            error_html = f'<div class="error-banner">{_html_escape(error)}</div>'

        if op_list:
            items_html = ""
            for op in op_list:
                entity_id = _html_escape(op["entity_id"])
                display_name = _html_escape(op["display_name"])
                logo_uri = _html_escape(op.get("logo_uri", ""))

                if logo_uri:
                    icon_html = (
                        f'<img src="{logo_uri}" alt="" width="24" height="24"'
                        f' style="border-radius:4px">'
                    )
                else:
                    icon_html = (
                        '<svg width="20" height="20" viewBox="0 0 20 20" fill="none">'
                        '<path d="M10 2L3 5.5V10C3 14.78 6.06 19.21 10 20.27'
                        "C13.94 19.21 17 14.78 17 10V5.5L10 2Z"
                        ' stroke="currentColor" stroke-width="1.3" fill="none"/>'
                        '<circle cx="10" cy="8.5" r="2" stroke="currentColor"'
                        ' stroke-width="1.2" fill="none"/>'
                        '<path d="M6.5 14.5C6.5 12.5 8 11.5 10 11.5C12 11.5'
                        ' 13.5 12.5 13.5 14.5" stroke="currentColor"'
                        ' stroke-width="1.2" stroke-linecap="round" fill="none"/>'
                        "</svg>"
                    )

                discovery_url = f"{self.base_url}/{self.name}/discovery"
                items_html += (
                    f'<form method="post" action="{_html_escape(discovery_url)}">'
                    f'<input type="hidden" name="entity_id" value="{entity_id}">'
                    f'<button type="submit" class="provider-item">'
                    f'<div class="provider-icon">{icon_html}</div>'
                    f'<div class="provider-text">'
                    f'<span class="provider-name">{display_name}</span>'
                    f'<span class="provider-desc">{entity_id}</span>'
                    f"</div>"
                    f'<svg class="provider-arrow" width="16" height="16" viewBox="0 0 16 16" fill="none">'
                    f'<path d="M6 3L11 8L6 13" stroke="currentColor" stroke-width="1.5"'
                    f' stroke-linecap="round" stroke-linejoin="round"/></svg>'
                    f"</button></form>"
                )

            list_html = f'<div class="provider-list">{items_html}</div>'
        else:
            list_html = (
                '<div class="empty-state">'
                "<p>No identity providers found.</p>"
                "</div>"
            )

        page_title = _html_escape(self.discovery_page_title)

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{page_title}</title>
<style>
*{{margin:0;padding:0;box-sizing:border-box}}
body{{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
background:#f5f7fa;color:#1a1a2e;min-height:100vh;
display:flex;justify-content:center;padding:2rem 1rem}}
.container{{max-width:480px;width:100%}}
h1{{font-size:1.5rem;margin-bottom:.5rem}}
.subtitle{{color:#6b7280;margin-bottom:1.5rem}}
.card{{background:#fff;border-radius:8px;padding:1.5rem;
box-shadow:0 1px 3px rgba(0,0,0,.1)}}
.error-banner{{background:#fef2f2;border:1px solid #fecaca;
color:#991b1b;padding:.75rem 1rem;border-radius:6px;
margin-bottom:1rem;font-size:.9rem}}
.provider-list{{display:flex;flex-direction:column;gap:.5rem}}
.provider-item{{display:flex;align-items:center;gap:.75rem;
padding:.75rem 1rem;border:1px solid #e5e7eb;border-radius:6px;
background:#fff;width:100%;cursor:pointer;text-align:left;
font-family:inherit;font-size:inherit;transition:all .15s ease}}
.provider-item:hover{{border-color:#3b82f6;background:#eff6ff}}
.provider-icon{{width:36px;height:36px;border-radius:6px;
background:#eff6ff;display:flex;align-items:center;
justify-content:center;color:#3b82f6;flex-shrink:0}}
.provider-item:hover .provider-icon{{background:#fff}}
.provider-text{{flex:1;display:flex;flex-direction:column;min-width:0}}
.provider-name{{font-weight:600;font-size:.9rem;color:#1e293b}}
.provider-desc{{font-size:.75rem;color:#6b7280;margin-top:.1rem;
overflow:hidden;text-overflow:ellipsis;white-space:nowrap}}
.provider-arrow{{color:#9ca3af;flex-shrink:0;transition:transform .15s ease}}
.provider-item:hover .provider-arrow{{color:#3b82f6;transform:translateX(2px)}}
.empty-state{{text-align:center;padding:2rem 0;color:#6b7280}}
form{{margin:0}}
</style>
</head>
<body>
<div class="container">
<h1>{page_title}</h1>
<p class="subtitle">Select an identity provider to sign in.</p>
<div class="card">
{error_html}
{list_html}
</div>
</div>
</body>
</html>"""

        return Response(html)

    def response_endpoint(self, context, *args):
        """Handle the authorization response callback from the OP.

        Exchanges the authorization code for tokens using private_key_jwt,
        verifies the id_token, fetches userinfo, and converts to InternalData.
        """
        if self.name not in context.state:
            raise SATOSAMissingStateError(
                "Received AuthN response without a SATOSA session cookie"
            )

        backend_state = context.state[self.name]

        # Determine which OP we're talking to
        op_entity_id = backend_state.get("op_entity_id", self.op_entity_id)
        op_meta = self._resolve_and_set_op_metadata(op_entity_id)

        # Parse authorization response
        auth_response = context.request
        if "error" in auth_response:
            error_desc = auth_response.get("error_description", auth_response["error"])
            msg = f"OP returned error: {error_desc}"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, msg)

        # Verify state
        received_state = auth_response.get("state")
        if received_state != backend_state[STATE_KEY]:
            msg = "State mismatch in authorization response"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, msg)

        code = auth_response.get("code")
        if not code:
            msg = "No authorization code in response"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, msg)

        # Exchange code for tokens
        token_response = self._exchange_code(code, backend_state, op_meta)

        # Verify id_token
        id_token_claims = {}
        id_token_jwt = token_response.get("id_token")
        if id_token_jwt:
            id_token_claims = self._verify_id_token(
                id_token_jwt, backend_state[NONCE_KEY], context, op_meta
            )

        # Fetch userinfo
        userinfo = {}
        access_token = token_response.get("access_token")
        if access_token and op_meta.get("userinfo_endpoint"):
            userinfo = self._get_userinfo(access_token, context, op_meta)

        if not id_token_claims and not userinfo:
            msg = "No id_token or userinfo received"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, msg)

        # Merge claims (userinfo takes precedence for overlapping keys)
        all_claims = dict(list(id_token_claims.items()) + list(userinfo.items()))

        msg = f"UserInfo: {all_claims}"
        logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
        logger.debug(logline)

        internal_resp = self._translate_response(all_claims, op_meta["issuer"])
        return self.auth_callback_func(context, internal_resp)

    def _exchange_code(self, code, backend_state, op_meta):
        """Exchange authorization code for tokens using private_key_jwt.

        Builds a client_assertion JWT signed with the federation key,
        includes the PKCE code_verifier, and POSTs to the OP's token endpoint.
        """
        now = int(time.time())
        assertion_claims = {
            "iss": self.entity_id,
            "sub": self.entity_id,
            "aud": op_meta["token_endpoint"],
            "iat": now,
            "exp": now + 120,
            "jti": str(uuid.uuid4()),
        }

        _jws = JWS(json.dumps(assertion_claims), alg=self.federation_signing_alg)
        client_assertion = _jws.sign_compact(
            keys=[self.federation_signing_key],
            protected={"kid": self.federation_signing_key.kid},
        )

        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "client_id": self.entity_id,
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": client_assertion,
            "code_verifier": backend_state[CODE_VERIFIER_KEY],
        }

        logger.debug(
            "Token request to %s for client_id=%s",
            op_meta["token_endpoint"], self.entity_id,
        )

        resp = http_requests.post(op_meta["token_endpoint"], data=token_data, timeout=15)
        if resp.status_code != 200:
            logger.error(
                "Token endpoint returned %s: %s", resp.status_code, resp.text[:500]
            )
            raise FederationError(
                f"Token endpoint error: {resp.status_code} {resp.text[:200]}"
            )

        return resp.json()

    def _verify_id_token(self, id_token_jwt, expected_nonce, context, op_meta):
        """Verify the id_token JWT signature and claims.

        Checks signature against OP's JWKS, verifies issuer, audience, and nonce.
        """
        try:
            claims = verify_entity_statement(id_token_jwt, op_meta["jwks"])
        except FederationError as e:
            msg = f"ID token verification failed: {e}"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, msg) from e

        # Verify issuer
        if claims.get("iss") != op_meta["issuer"]:
            msg = f"ID token issuer mismatch: {claims.get('iss')} != {op_meta['issuer']}"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, msg)

        # Verify audience
        aud = claims.get("aud")
        if isinstance(aud, list):
            if self.entity_id not in aud:
                msg = f"ID token audience mismatch: {aud}"
                raise SATOSAAuthenticationError(context.state, msg)
        elif aud != self.entity_id:
            msg = f"ID token audience mismatch: {aud} != {self.entity_id}"
            raise SATOSAAuthenticationError(context.state, msg)

        # Verify nonce
        if claims.get("nonce") != expected_nonce:
            msg = "ID token nonce mismatch"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.error(logline)
            raise SATOSAAuthenticationError(context.state, msg)

        return claims

    def _get_userinfo(self, access_token, context, op_meta):
        """Fetch userinfo from the OP's userinfo endpoint."""
        headers = {"Authorization": f"Bearer {access_token}"}
        try:
            resp = http_requests.get(
                op_meta["userinfo_endpoint"], headers=headers, timeout=15
            )
            resp.raise_for_status()
            return resp.json()
        except Exception as e:
            msg = f"Userinfo request failed: {e}"
            logline = lu.LOG_FMT.format(id=lu.get_session_id(context.state), message=msg)
            logger.warning(logline)
            return {}

    def _translate_response(self, response, issuer):
        """Translate OIDC claims to SATOSA InternalData."""
        auth_info = AuthenticationInformation(UNSPECIFIED, str(datetime.now()), issuer)
        internal_resp = InternalData(auth_info=auth_info)
        internal_resp.attributes = self.converter.to_internal("openid", response)
        internal_resp.subject_id = response["sub"]
        return internal_resp

    def get_metadata_desc(self):
        """Not applicable for federation RP backends."""
        return []
