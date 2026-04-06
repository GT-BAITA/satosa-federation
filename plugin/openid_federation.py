# SPDX-FileCopyrightText: 2026 Kushal Das <kushal@sunet.se>
# SPDX-License-Identifier: BSD-2-Clause
"""
OpenID Federation 1.0 frontend plugin for SATOSA.

This plugin extends SATOSA's OpenIDConnectFrontend to act as a federation-aware
OpenID Provider (OP). It bridges two worlds:

  1. **Upstream (backend):** SATOSA authenticates users via SAML2, OIDC, or other
     backends — this plugin does not touch that side at all.
  2. **Downstream (frontend):** Relying Parties (RPs) discover and interact with
     this OP using OpenID Federation 1.0 trust chain resolution instead of
     pre-configured client registration.

Architecture & Request Flow
----------------------------

  RP  ─────────────────────────────────────────────────────────────  IdP
   │                                                                  │
   │  1. Fetch /.well-known/openid-federation                        │
   │     (Entity Configuration JWT — signed with federation EC key)   │
   │                                                                  │
   │  2. Build trust chain:                                           │
   │     RP → Intermediate(s) → Trust Anchor                         │
   │     (validates OP metadata via subordinate statements)           │
   │                                                                  │
   │  3. GET /OIDFed/authorization?client_id=<rp>&request=<jwt>       │
   │     ├─ Auto-register RP via trust chain resolution               │
   │     ├─ Unpack & verify request object JWT                        │
   │     └─ Delegate to pyop's standard authorization endpoint        │
   │              │                                                   │
   │              └─ SATOSA routes to SAML backend ────────────────►  │
   │                                                                  │
   │  4. IdP authenticates user, sends SAML assertion back            │
   │              ◄─────────────────────────────────── SAML Response  │
   │                                                                  │
   │  5. POST /OIDFed/token  (authorization_code + private_key_jwt)   │
   │     ├─ Verify client_assertion JWT (private_key_jwt)             │
   │     ├─ Strip assertion, delegate to pyop with auth="none"        │
   │     └─ Return id_token + access_token                            │
   │                                                                  │
   │  6. GET /OIDFed/userinfo  (Bearer access_token)                  │
   │     └─ Standard pyop userinfo, returns claims                    │

Key Design Decisions
---------------------

- **pyop workaround for private_key_jwt:** pyop (the OpenID Provider library)
  only supports client_secret_basic, client_secret_post, and "none" for client
  authentication. Federation RPs universally use private_key_jwt. We work around
  this by: (a) registering federation clients with auth method "none" in pyop's
  client DB, (b) intercepting token requests in our overridden token_endpoint()
  to verify the client_assertion JWT ourselves, then stripping it before passing
  to pyop.

- **Request object unpacking:** Federation RPs send authorization requests as
  signed JWTs in a `request` parameter (RFC 9101). pyop would need the RP's
  signing keys in its keyjar to verify these, but we manage keys via federation
  JWKS instead. So we verify and unpack the request object ourselves, replacing
  the JWT with plain parameters before delegating to pyop.

- **Trust chain caching:** Resolved trust chains and metadata are cached per-RP
  with a configurable TTL to avoid repeated HTTP fetches on every request.

- **Federation signing key:** A separate EC P-256 key (distinct from the OIDC
  signing key) is used to sign the Entity Configuration JWT, per the OpenID
  Federation spec's key separation requirement.

Dependencies
-------------
- jwkest: JWT signing/verification (ECKey, RSAKey, JWS)
- pyop: OpenID Provider core (inherited via OpenIDConnectFrontend)
- pysaml2: Used by the SAML backend (not directly by this plugin)
- requests: HTTP client for fetching entity configurations and subordinate statements
"""

import base64
import json
import logging
import time

import requests as http_requests
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from jwkest.jwk import ECKey, RSAKey
from jwkest.jws import JWS

from urllib.parse import urlencode

from pyop.exceptions import (
    InvalidClientAuthentication,
    OAuthError,
)
from oic.oic.message import TokenErrorResponse

from satosa.frontends.openid_connect import OpenIDConnectFrontend
from satosa.response import BadRequest, Response, Unauthorized

logger = logging.getLogger(__name__)


class FederationError(Exception):
    """Raised when federation trust chain resolution or validation fails.

    This covers: invalid JWTs, expired statements, signature verification
    failures, broken trust chains, metadata policy violations, and missing
    required fields.
    """

    pass


# ---------------------------------------------------------------------------
# Utility helpers: key loading and encoding
# ---------------------------------------------------------------------------


def _int_to_b64url(n, length):
    """Encode a big-endian integer as a base64url string (no padding).

    Used to convert Python int values from cryptography's EC key numbers into
    the JWK format (x, y, d coordinates).
    """
    b = n.to_bytes(length, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _load_ec_signing_key(key_path, kid="federation-key"):
    """Load an EC P-256 private key from a PEM file and return a jwkest ECKey.

    The federation signing key is separate from the OIDC signing key (RSA)
    managed by pyop. This key is used exclusively for signing the Entity
    Configuration JWT at /.well-known/openid-federation.

    The PEM file is read, its private numbers are extracted via the
    cryptography library, and a JWK dict is constructed manually because
    jwkest's ECKey does not support direct PEM loading.
    """
    with open(key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )

    nums = private_key.private_numbers()
    pub = nums.public_numbers

    # Construct the JWK dict with the P-256 curve coordinates
    jwk_dict = {
        "kty": "EC",
        "crv": "P-256",
        "x": _int_to_b64url(pub.x, 32),
        "y": _int_to_b64url(pub.y, 32),
        "d": _int_to_b64url(nums.private_value, 32),  # private component
    }
    key = ECKey(**jwk_dict, use="sig", kid=kid)
    return key


def _build_trust_anchor_keys(trust_anchors_config):
    """Convert trust anchor config into {entity_id: JWKS dict}.

    The YAML config maps each trust anchor entity ID to its pre-distributed
    public keys. These keys are used to verify the final link in any trust
    chain — the Trust Anchor's Entity Configuration must be signed by one
    of these keys.

    Config format:
        trust_anchors:
          "https://ta.example.com":
            keys:
              - {kty: EC, crv: P-256, x: ..., y: ...}
    """
    result = {}
    for entity_id, ta_conf in trust_anchors_config.items():
        keys_list = ta_conf.get("keys", [])
        result[entity_id] = {"keys": keys_list}
    return result


# ---------------------------------------------------------------------------
# Trust Chain Resolution via Resolve Endpoints
# ---------------------------------------------------------------------------
#
# OpenID Federation trust chains prove that an entity (e.g., an RP) is a
# legitimate member of a federation. Rather than manually walking the chain
# ourselves (fetching entity configs, subordinate statements, etc.), we
# delegate this to the Trust Anchor's federation_resolve_endpoint.
#
# The resolve endpoint (OpenID Federation 1.0 Section 10.1.1) does all the
# heavy lifting server-side:
#   1. We call GET {resolve_endpoint}?sub={entity_id}&anchor={ta_id}
#   2. The Trust Anchor walks the chain, verifies signatures, applies policies
#   3. It returns a signed JWT containing the resolved metadata
#
# We try each configured Trust Anchor in order. The first one that
# successfully resolves the entity wins. If all Trust Anchors fail (no
# resolve endpoint, network errors, or the entity isn't in their federation),
# we raise a FederationError.
# ---------------------------------------------------------------------------


def fetch_entity_configuration(entity_id):
    """Fetch the Entity Configuration JWT from {entity_id}/.well-known/openid-federation.

    Every OpenID Federation entity MUST publish a self-signed Entity
    Configuration at this well-known URL. The response content type is
    application/entity-statement+jwt.
    """
    url = f"{entity_id.rstrip('/')}/.well-known/openid-federation"
    resp = http_requests.get(url, timeout=10)
    resp.raise_for_status()
    return resp.text.strip()


def decode_entity_statement(jwt_str):
    """Decode a JWT payload WITHOUT verifying the signature.

    Used when we need to peek at claims (e.g., to find the issuer or
    subject) before we have the right keys for verification. The actual
    cryptographic verification is always done separately via
    verify_entity_statement().
    """
    parts = jwt_str.split(".")
    if len(parts) != 3:
        raise FederationError("Invalid JWT format")
    payload_b64 = parts[1]
    # base64url requires padding to a multiple of 4
    padding = 4 - len(payload_b64) % 4
    if padding != 4:
        payload_b64 += "=" * padding
    payload_bytes = base64.urlsafe_b64decode(payload_b64)
    return json.loads(payload_bytes)


def keys_from_jwks(jwks_dict):
    """Convert a JWKS dict {"keys": [...]} to a list of jwkest key objects.

    Supports EC (P-256, P-384, P-521) and RSA key types. Unknown key types
    are silently skipped.
    """
    keys = []
    for key_data in jwks_dict.get("keys", []):
        if key_data.get("kty") == "EC":
            keys.append(ECKey(**key_data))
        elif key_data.get("kty") == "RSA":
            keys.append(RSAKey(**key_data))
    return keys


def verify_entity_statement(jwt_str, jwks):
    """Verify a JWT signature against the provided JWKS and return the payload.

    This is the core cryptographic verification used throughout trust chain
    resolution. It:
      1. Converts the JWKS to jwkest key objects
      2. Verifies the JWS signature against those keys
      3. Checks the exp claim (if present) to reject expired statements

    Raises FederationError if verification fails or the statement is expired.
    """
    keys = keys_from_jwks(jwks)
    if not keys:
        raise FederationError("No usable keys in JWKS")
    try:
        payload = JWS().verify_compact(jwt_str, keys=keys)
    except Exception as e:
        raise FederationError(f"JWT signature verification failed: {e}") from e
    if isinstance(payload, str):
        payload = json.loads(payload)
    exp = payload.get("exp")
    if exp is not None and exp < time.time():
        raise FederationError(
            f"Entity statement expired at {exp} (now={int(time.time())})"
        )
    return payload


def resolve_via_trust_anchors(entity_id, trust_anchors):
    """Resolve an entity's metadata by querying Trust Anchor resolve endpoints.

    Instead of manually walking authority_hints, we delegate trust chain
    resolution to the Trust Anchors themselves via their federation_resolve_endpoint
    (OpenID Federation 1.0 Section 10.1.1).

    For each configured Trust Anchor:
      1. Fetch the TA's Entity Configuration from /.well-known/openid-federation
      2. Find its federation_resolve_endpoint in metadata.federation_entity
      3. Call GET {resolve_endpoint}?sub={entity_id}&trust_anchor={ta_entity_id}
      4. The response is a JWT (application/resolve-response+jwt) signed by the TA
      5. Verify the JWT against the TA's pre-distributed keys
      6. Extract the resolved metadata from the payload

    All configured Trust Anchors are tried in order. The first successful
    resolution wins. If all fail, FederationError is raised with details
    of each failure.

    Args:
        entity_id: The entity to resolve (e.g., the RP's entity identifier)
        trust_anchors: Dict of {ta_entity_id: jwks_dict} for pre-trusted Trust Anchors

    Returns:
        dict: The resolve response payload containing 'metadata' (resolved,
              with policies already applied by the TA), 'trust_chain' (array
              of JWTs), and standard JWT claims (iss, sub, iat, exp).

    Raises:
        FederationError: If none of the Trust Anchors can resolve the entity
    """
    errors = []

    for ta_entity_id, ta_jwks in trust_anchors.items():
        try:
            # Step 1: Fetch the TA's Entity Configuration to find its resolve endpoint
            ta_jwt = fetch_entity_configuration(ta_entity_id)
            ta_config = decode_entity_statement(ta_jwt)

            # Verify the TA's Entity Configuration against pre-distributed keys
            verify_entity_statement(ta_jwt, ta_jwks)

            fed_meta = ta_config.get("metadata", {}).get("federation_entity", {})
            resolve_endpoint = fed_meta.get("federation_resolve_endpoint")
            if not resolve_endpoint:
                errors.append(f"{ta_entity_id}: no federation_resolve_endpoint")
                continue

            # Step 2: Call the resolve endpoint
            logger.debug(
                "Calling resolve endpoint %s for sub=%s anchor=%s",
                resolve_endpoint, entity_id, ta_entity_id,
            )
            resp = http_requests.get(
                resolve_endpoint,
                params={"sub": entity_id, "trust_anchor": ta_entity_id},
                timeout=15,
            )
            resp.raise_for_status()

            # Step 3: The response is a signed JWT — verify against TA keys
            resolve_jwt = resp.text.strip()
            resolve_payload = verify_entity_statement(resolve_jwt, ta_jwks)

            # Sanity check: the resolved subject must match our query
            if resolve_payload.get("sub") != entity_id:
                errors.append(f"{ta_entity_id}: resolve response sub mismatch")
                continue

            logger.info(
                "Resolved trust chain for %s via Trust Anchor %s",
                entity_id, ta_entity_id,
            )
            return resolve_payload

        except FederationError as e:
            errors.append(f"{ta_entity_id}: {e}")
            logger.debug("Resolve via %s failed: %s", ta_entity_id, e)
        except Exception as e:
            errors.append(f"{ta_entity_id}: {e}")
            logger.debug("Resolve via %s failed: %s", ta_entity_id, e)

    raise FederationError(
        f"Could not resolve trust chain for {entity_id} via any trust anchor: "
        + "; ".join(errors)
    )


# ---------------------------------------------------------------------------
# Metadata Policy Helpers
# ---------------------------------------------------------------------------
# NOTE: These functions are NOT used in the main resolve-endpoint flow, since
# the Trust Anchor's federation_resolve_endpoint already applies metadata
# policies server-side. They are kept here for local validation, testing,
# and potential future use (e.g., applying additional local policies on top
# of the TA's resolution).
# ---------------------------------------------------------------------------


def apply_metadata_policies(chain):
    """Apply metadata policies from the trust chain to produce resolved metadata.

    In OpenID Federation, superiors (Trust Anchors and Intermediates) can
    constrain their subordinates' metadata via policies in subordinate
    statements. For example, a Trust Anchor might require all RPs to use
    private_key_jwt, or restrict allowed signing algorithms.

    This function:
      1. Extracts the leaf entity's declared metadata from chain[0]
      2. Collects all metadata_policy entries from subordinate statements
      3. Merges them (policies can only narrow, never widen)
      4. Applies the combined policy to produce "resolved metadata"

    The resolved metadata is what we actually use for client registration.

    Args:
        chain: [leaf_config, sub_stmt_1, auth_config_1, ..., ta_config]

    Returns:
        dict: Resolved metadata keyed by entity type (e.g., "openid_relying_party")
    """
    leaf_metadata = chain[0].get("metadata", {})

    # Collect metadata_policy from subordinate statements in the chain.
    # Entity Configurations (where iss==sub) typically don't have policies;
    # only subordinate statements (where iss != sub) carry metadata_policy.
    combined_policy = {}
    for stmt in chain[1:]:
        policy = stmt.get("metadata_policy", {})
        if policy:
            combined_policy = _merge_policies(combined_policy, policy)

    # Apply the combined policy to each entity type in the leaf's metadata
    resolved = {}
    for entity_type in leaf_metadata:
        if entity_type in combined_policy:
            resolved[entity_type] = _apply_policy_to_metadata(
                leaf_metadata[entity_type], combined_policy[entity_type]
            )
        else:
            resolved[entity_type] = dict(leaf_metadata[entity_type])

    return resolved


def _merge_policies(existing, new):
    """Merge two metadata policies together.

    Per the spec, policies can only become MORE restrictive as you move down
    the chain from Trust Anchor to leaf. This simple implementation merges
    operator dicts — a more complete implementation would detect conflicts
    where policies cannot be satisfied simultaneously.
    """
    merged = dict(existing)
    for entity_type, params in new.items():
        if entity_type not in merged:
            merged[entity_type] = {}
        for param, operators in params.items():
            if param not in merged[entity_type]:
                merged[entity_type][param] = {}
            merged[entity_type][param].update(operators)
    return merged


def _apply_policy_to_metadata(metadata, policy):
    """Apply policy operators to a single entity type's metadata.

    Supported operators (per OpenID Federation 1.0 Section 6):
      - value:       Force a specific value (overrides entity's declaration)
      - default:     Set a default if the parameter is absent
      - add:         Add values to an array parameter
      - one_of:      Scalar must be one of the allowed values
      - subset_of:   Array must be a subset of allowed values
      - superset_of: Array must be a superset of required values
      - essential:   Parameter must be present (boolean)

    Raises FederationError if any policy constraint is violated.
    """
    result = dict(metadata)
    for param, operators in policy.items():
        if "value" in operators:
            result[param] = operators["value"]
        if "default" in operators and param not in result:
            result[param] = operators["default"]
        if "add" in operators:
            existing = result.get(param, [])
            if isinstance(existing, list):
                result[param] = list(set(existing + operators["add"]))
        if "one_of" in operators and param in result:
            if result[param] not in operators["one_of"]:
                raise FederationError(
                    f"Policy violation: {param}={result[param]} "
                    f"not in {operators['one_of']}"
                )
        if "subset_of" in operators and param in result:
            if isinstance(result[param], list):
                if not set(result[param]).issubset(set(operators["subset_of"])):
                    raise FederationError(
                        f"Policy violation: {param} not subset of "
                        f"{operators['subset_of']}"
                    )
        if "superset_of" in operators and param in result:
            if isinstance(result[param], list):
                if not set(result[param]).issuperset(
                    set(operators["superset_of"])
                ):
                    raise FederationError(
                        f"Policy violation: {param} not superset of "
                        f"{operators['superset_of']}"
                    )
        if operators.get("essential") and param not in result:
            raise FederationError(
                f"Policy violation: {param} is essential but missing"
            )
    return result


# ---------------------------------------------------------------------------
# Frontend Plugin
# ---------------------------------------------------------------------------


class OpenIDFederationFrontend(OpenIDConnectFrontend):
    """OpenID Federation-aware OIDC frontend for SATOSA.

    This class extends SATOSA's built-in OpenIDConnectFrontend (which wraps pyop)
    to support OpenID Federation 1.0. It adds three capabilities on top of the
    standard OIDC Provider behavior:

    1. **Entity Configuration endpoint** (/.well-known/openid-federation):
       Publishes a self-signed JWT describing this OP's federation metadata,
       authority hints, and public federation keys. This is what RPs and
       intermediates fetch to discover and verify this OP.

    2. **Automatic client registration** via trust chain validation:
       When an unknown RP sends an authorization request, instead of rejecting
       it, we resolve its trust chain back to a configured Trust Anchor. If
       valid, the RP is automatically registered as an OIDC client.

    3. **pyop compatibility workarounds** for federation auth methods:
       - private_key_jwt: Verified by us, stripped before passing to pyop
       - Request objects (RFC 9101): Unpacked by us, replaced with plain params

    Configuration (in the plugin YAML under 'federation'):
        entity_id:                      OP's entity identifier URL
        authority_hints:                List of superior entity IDs
        trust_anchors:                  Dict of TA entity_id → {keys: [...]}
        signing_key_path:               Path to EC P-256 PEM private key
        signing_key_id:                 kid for the federation key
        signing_algorithm:              JWS algorithm (default: ES256)
        entity_configuration_lifetime:  Seconds until EC JWT expires (default: 86400)
        organization_name:              Human-readable org name
        organization_uri:               Organization homepage URL
        trust_marks:                    List of trust mark objects
        rp_cache_ttl:                   Seconds to cache resolved RP metadata (default: 3600)
    """

    def __init__(
        self, auth_req_callback_func, internal_attributes, conf, base_url, name
    ):
        if "federation" not in conf:
            raise ValueError(
                "Missing 'federation' configuration block for "
                "OpenIDFederationFrontend"
            )

        # Initialize the standard OIDC frontend (sets up pyop Provider, etc.)
        super().__init__(
            auth_req_callback_func, internal_attributes, conf, base_url, name
        )

        # Federation-specific configuration
        fed_conf = conf["federation"]
        self.entity_id = fed_conf.get("entity_id", base_url)
        self.authority_hints = fed_conf["authority_hints"]
        self.trust_anchors = _build_trust_anchor_keys(fed_conf["trust_anchors"])
        self.federation_signing_alg = fed_conf.get("signing_algorithm", "ES256")
        self.entity_configuration_lifetime = fed_conf.get(
            "entity_configuration_lifetime", 86400
        )
        self.organization_name = fed_conf.get("organization_name", "")
        self.organization_uri = fed_conf.get("organization_uri", "")
        self.trust_marks = fed_conf.get("trust_marks", [])
        for i, tm in enumerate(self.trust_marks):
            if not isinstance(tm, dict) or "id" not in tm or "trust_mark" not in tm:
                raise ValueError(
                    f"trust_marks[{i}]: each entry must have 'id' and 'trust_mark' keys"
                )

        # Load the EC P-256 federation signing key (separate from pyop's RSA OIDC key).
        # This key signs the Entity Configuration JWT at /.well-known/openid-federation.
        self.federation_signing_key = _load_ec_signing_key(
            fed_conf["signing_key_path"],
            fed_conf.get("signing_key_id", "federation-key"),
        )

        # In-memory cache for resolved RP trust chains and metadata.
        # Keyed by RP entity_id, value is {"metadata": resolved_dict, "exp": timestamp}.
        # This avoids re-fetching the entire trust chain on every request from the same RP.
        self._rp_cache = {}
        self._rp_cache_ttl = fed_conf.get("rp_cache_ttl", 3600)

    def register_endpoints(self, backend_names):
        """Register all OIDC endpoints plus the federation entity configuration endpoint."""
        url_map = super().register_endpoints(backend_names)

        # Add federation entity configuration endpoint
        entity_config_endpoint = (
            "^.well-known/openid-federation$",
            self.federation_entity_configuration,
        )
        url_map.append(entity_config_endpoint)

        return url_map

    def federation_entity_configuration(self, context):
        """
        Serve the Entity Configuration at /.well-known/openid-federation.

        Returns a self-signed JWT (application/entity-statement+jwt) containing:
        - iss, sub (both = entity_id)
        - jwks (federation EC public key)
        - authority_hints
        - metadata.openid_provider (OIDC provider configuration)
        - metadata.federation_entity (organization info)
        - trust_marks (if configured)
        """
        now = int(time.time())

        # Build OIDC provider metadata from pyop
        oidc_provider_metadata = json.loads(
            self.provider.provider_configuration.to_json()
        )

        # Add federation-required fields to OP metadata
        oidc_provider_metadata["client_registration_types_supported"] = ["automatic"]
        oidc_provider_metadata["request_parameter_supported"] = True
        if "private_key_jwt" not in oidc_provider_metadata.get(
            "token_endpoint_auth_methods_supported", []
        ):
            oidc_provider_metadata.setdefault(
                "token_endpoint_auth_methods_supported", []
            ).append("private_key_jwt")

        federation_entity_metadata = {}

        if self.organization_name:
            federation_entity_metadata["organization_name"] = self.organization_name
        if self.organization_uri:
            federation_entity_metadata["homepage_uri"] = self.organization_uri

        # Entity Configuration claims
        ec_claims = {
            "iss": self.entity_id,
            "sub": self.entity_id,
            "iat": now,
            "exp": now + self.entity_configuration_lifetime,
            "jwks": {"keys": [self.federation_signing_key.serialize(private=False)]},
            "authority_hints": self.authority_hints,
            "metadata": {
                "openid_provider": oidc_provider_metadata,
            },
        }

        if federation_entity_metadata:
            ec_claims["metadata"]["federation_entity"] = federation_entity_metadata

        if self.trust_marks:
            ec_claims["trust_marks"] = self.trust_marks

        # Self-sign with federation key (typ per OpenID Federation 1.0 spec)
        jwt_str = JWS(
            json.dumps(ec_claims), alg=self.federation_signing_alg
        ).sign_compact(
            keys=[self.federation_signing_key],
            protected={"typ": "entity-statement+jwt"},
        )

        return Response(jwt_str, content="application/entity-statement+jwt")

    def handle_authn_request(self, context):
        """Handle an authorization request with federation-aware auto-registration.

        This is the main entry point for incoming OIDC authorization requests.
        The flow is:

          1. Extract client_id from the request parameters
          2. If client_id is unknown, attempt federation auto-registration:
             - Resolve the RP's trust chain to a configured Trust Anchor
             - Apply metadata policies from the chain
             - Register the RP in pyop's client database
          3. If the request contains a `request` parameter (signed JWT per
             RFC 9101 / OpenID Federation), verify and unpack it:
             - Verify the JWT signature against the RP's federation JWKS
             - Replace the opaque JWT with plain OIDC parameters
             - This is needed because pyop doesn't have the RP's keys in
               its keyjar, so it can't verify the request object itself
          4. Delegate to pyop's standard authorization endpoint via super()

        If auto-registration or request object verification fails, a
        BadRequest response is returned immediately.
        """
        client_id = context.request.get("client_id")

        # Step 1: Auto-register unknown federation RPs
        if client_id and client_id not in self.provider.clients:
            try:
                self._auto_register_client(client_id)
            except FederationError as e:
                logger.warning(
                    "Federation auto-registration failed for %s: %s",
                    client_id,
                    e,
                )
                return BadRequest(f"Client registration failed: {e}")

        # Step 2: Unpack request object JWT if present.
        # Federation RPs typically send authorization parameters inside a signed
        # JWT in the `request` parameter rather than as plain query parameters.
        if "request" in context.request and client_id in self.provider.clients:
            try:
                context.request = self._unpack_request_object(
                    context.request, client_id
                )
            except FederationError as e:
                logger.warning(
                    "Request object verification failed for %s: %s",
                    client_id,
                    e,
                )
                return BadRequest(f"Invalid request object: {e}")

        # Step 3: Delegate to pyop's standard OIDC authorization handling
        return super().handle_authn_request(context)

    def _unpack_request_object(self, request, client_id):
        """Verify and unpack a request object JWT using the client's federation JWKS.

        In OpenID Federation, RPs send their authorization parameters inside a
        signed JWT (the "request object", per RFC 9101). This method:

          1. Extracts the JWT from request["request"]
          2. Looks up the RP's JWKS from our client database (populated during
             auto-registration from the RP's resolved federation metadata)
          3. Verifies the JWT signature and expiration
          4. Merges the decoded OIDC parameters (scope, redirect_uri, nonce, etc.)
             back into the request dict as plain key-value pairs
          5. Removes the raw "request" key

        This is necessary because pyop would need the RP's signing keys in its
        own keyjar to process request objects, but we manage RP keys via the
        federation trust chain instead.

        Returns:
            dict: The request with JWT parameters unpacked as plain values.
        """
        request_jwt = request["request"]
        client_info = self.provider.clients[client_id]

        client_jwks = client_info.get("jwks", {})
        if not client_jwks or not client_jwks.get("keys"):
            raise FederationError(
                f"No JWKS available for client {client_id} to verify request object"
            )

        # Verify signature and check expiration
        payload = verify_entity_statement(request_jwt, client_jwks)

        # Merge decoded OIDC params into the request, skipping JWT envelope claims
        merged = dict(request)
        del merged["request"]
        for key, value in payload.items():
            if key not in ("iss", "aud", "iat", "exp", "jti", "claims"):
                merged[key] = value

        logger.debug(
            "Unpacked request object for %s, params: %s",
            client_id,
            list(payload.keys()),
        )
        return merged

    def token_endpoint(self, context):
        """Handle token requests with private_key_jwt client authentication.

        Background: In OpenID Federation, RPs authenticate at the token endpoint
        using private_key_jwt (RFC 7523). The RP sends:
          - client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
          - client_assertion = <signed JWT proving client identity>

        Problem: pyop only implements client_secret_basic, client_secret_post,
        and "none". It has zero support for private_key_jwt.

        Workaround: We intercept the token request here and:
          1. Detect if private_key_jwt is being used (by checking the assertion params)
          2. Verify the client_assertion JWT ourselves using the RP's federation JWKS
             (checking signature, iss, sub, aud, and expiration)
          3. Strip the client_assertion and client_assertion_type from the request
          4. Pass the cleaned request to pyop, which sees auth method "none"
             (since we registered federation clients with token_endpoint_auth_method="none")

        If verification fails, we return an OAuth error response (invalid_client).
        """
        request = context.request

        # Detect private_key_jwt authentication
        if (
            request.get("client_assertion_type")
            == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
            and "client_assertion" in request
        ):
            try:
                self._verify_private_key_jwt(request)
            except FederationError as e:
                logger.warning("private_key_jwt verification failed: %s", e)
                error_resp = TokenErrorResponse(
                    error="invalid_client", error_description=str(e)
                )
                return Unauthorized(
                    error_resp.to_json(),
                    headers=[("WWW-Authenticate", "Basic")],
                    content="application/json",
                )

            # Strip assertion fields so pyop sees a plain unauthenticated request.
            # This works because we registered the client with auth method "none".
            cleaned = {
                k: v
                for k, v in request.items()
                if k not in ("client_assertion", "client_assertion_type")
            }
            context.request = cleaned

        return super().token_endpoint(context)

    def _verify_private_key_jwt(self, request):
        """Verify a private_key_jwt client_assertion per RFC 7523 Section 2.2.

        The client_assertion JWT must satisfy:
          - Signed by a key from the RP's JWKS (obtained during trust chain resolution)
          - iss == client_id (the RP asserts its own identity)
          - sub == client_id
          - aud contains our token endpoint URL
          - Not expired (checked inside verify_entity_statement)

        Args:
            request: The token request dict containing client_assertion and optionally client_id

        Raises:
            FederationError: If any verification check fails
        """
        assertion_jwt = request["client_assertion"]
        client_id = request.get("client_id")

        # client_id may not be in the form params — extract from the JWT itself
        if not client_id:
            payload = decode_entity_statement(assertion_jwt)
            client_id = payload.get("sub") or payload.get("iss")

        if not client_id or client_id not in self.provider.clients:
            raise FederationError(f"Unknown client: {client_id}")

        # Look up the RP's JWKS from our client database (stored during auto-registration)
        client_info = self.provider.clients[client_id]
        client_jwks = client_info.get("jwks", {})
        if not client_jwks or not client_jwks.get("keys"):
            raise FederationError(
                f"No JWKS for client {client_id} to verify client_assertion"
            )

        # Verify the JWT signature against the RP's federation keys
        payload = verify_entity_statement(assertion_jwt, client_jwks)

        # RFC 7523 Section 3: iss and sub MUST equal the client_id
        if payload.get("iss") != client_id:
            raise FederationError(
                f"client_assertion iss={payload.get('iss')} != client_id={client_id}"
            )
        if payload.get("sub") != client_id:
            raise FederationError(
                f"client_assertion sub={payload.get('sub')} != client_id={client_id}"
            )

        # RFC 7523 Section 3: aud MUST contain the token endpoint URL
        aud = payload.get("aud")
        if isinstance(aud, str):
            aud = [aud]

        # Removido path Hardcoded para token endpoint (/OIDFed/token)
        token_url = f"{self.entity_id}/token"
        if not aud or token_url not in aud:
            raise FederationError(
                f"client_assertion aud={aud} does not contain {token_url}"
            )

        logger.debug(
            "Verified private_key_jwt for client %s", client_id
        )

    def _auto_register_client(self, entity_id):
        """Resolve an RP's trust chain and register it as an OIDC client in pyop.

        This is the federation equivalent of dynamic client registration. Instead
        of the RP calling a registration endpoint with its metadata, we:

          1. Resolve the RP's trust chain back to a configured Trust Anchor
             (fetching Entity Configurations and subordinate statements)
          2. Apply any metadata policies from the chain (e.g., restricting
             allowed grant types, requiring specific auth methods)
          3. Extract the resolved openid_relying_party metadata
          4. Register the RP in pyop's in-memory client database

        The resolved metadata is cached (keyed by entity_id) to avoid
        re-fetching trust chains on subsequent requests from the same RP.

        Important pyop workaround:
          We register federation clients with token_endpoint_auth_method="none"
          because pyop cannot handle private_key_jwt. The real auth method
          (typically "private_key_jwt") is stored in "federation_auth_method"
          for reference. The actual private_key_jwt verification happens in
          our overridden token_endpoint() method.

        Args:
            entity_id: The RP's entity identifier (URL), also used as client_id

        Raises:
            FederationError: If trust chain resolution fails, policies are
                violated, or required metadata (redirect_uris) is missing
        """
        # Check the cache to avoid redundant trust chain resolution
        cached = self._rp_cache.get(entity_id)
        if cached and cached["exp"] > time.time():
            resolved_metadata = cached["metadata"]
        else:
            # Resolve via Trust Anchor resolve endpoints. The TA does all
            # the chain-walking and policy application server-side.
            resolve_result = resolve_via_trust_anchors(
                entity_id, self.trust_anchors
            )
            resolved_metadata = resolve_result.get("metadata", {})
            self._rp_cache[entity_id] = {
                "metadata": resolved_metadata,
                "exp": time.time() + self._rp_cache_ttl,
            }

        rp_metadata = resolved_metadata.get("openid_relying_party", {})
        if not rp_metadata.get("redirect_uris"):
            raise FederationError("RP metadata missing redirect_uris")

        # Register the RP in pyop's client database.
        # Note: token_endpoint_auth_method is set to "none" for pyop compatibility.
        # The real method is stored in federation_auth_method for our reference.
        real_auth_method = rp_metadata.get(
            "token_endpoint_auth_method", "private_key_jwt"
        )
        self.provider.clients[entity_id] = {
            "client_id": entity_id,
            "response_types": rp_metadata.get("response_types", ["code"]),
            "redirect_uris": rp_metadata["redirect_uris"],
            "token_endpoint_auth_method": "none",  # pyop workaround
            "federation_auth_method": real_auth_method,  # actual method
            "client_name": rp_metadata.get("client_name", entity_id),
            "subject_type": rp_metadata.get("subject_type", "pairwise"),
            "jwks": rp_metadata.get("jwks", {}),  # RP's federation public keys
            "jwks_uri": rp_metadata.get("jwks_uri"),
        }

        logger.info(
            "Auto-registered federation RP: %s with redirect_uris=%s",
            entity_id,
            rp_metadata["redirect_uris"],
        )
