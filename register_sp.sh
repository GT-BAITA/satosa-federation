#!/bin/bash
set -euo pipefail

# Register SATOSA's SAML SP metadata with the test IdP.
#
# Usage:
#   ./register_sp.sh [IDP_BASE_URL] [SP_METADATA_URL]
#
# Defaults:
#   IDP_BASE_URL     = https://samlidp.labb.sunet.se
#   SP_METADATA_URL  = (generated inside the running container via satosa-saml-metadata)

IDP_BASE_URL="${1:-https://samlidp.labb.sunet.se}"
SP_METADATA_URL="${2:-}"

TMPFILE=$(mktemp /tmp/satosa_sp_metadata.XXXXXX.xml)
trap 'rm -f "$TMPFILE"' EXIT

if [ -n "$SP_METADATA_URL" ]; then
    echo "Downloading SP metadata from ${SP_METADATA_URL} ..."
    curl -sf "$SP_METADATA_URL" -o "$TMPFILE"
else
    echo "Generating SP metadata from running container ..."
    docker compose exec -T satosa-proxy \
        satosa-saml-metadata \
        /opt/satosa/etc/proxy_conf.yaml \
        /opt/satosa/etc/keys/saml_backend.key \
        /opt/satosa/etc/keys/saml_backend.crt \
        --dir /tmp

    docker compose cp satosa-proxy:/tmp/backend.xml "$TMPFILE"
fi

echo "SP metadata saved to ${TMPFILE}"

# Extract entity ID for display
ENTITY_ID=$(python3 -c "
import xml.etree.ElementTree as ET
tree = ET.parse('${TMPFILE}')
print(tree.getroot().attrib['entityID'])
" 2>/dev/null || echo "unknown")

echo "SP Entity ID: ${ENTITY_ID}"

# Use the SP host as the key for the IdP's service registry
SP_KEY=$(echo "$ENTITY_ID" | sed 's|https\?://||' | cut -d/ -f1)

echo "Registering SP with IdP at ${IDP_BASE_URL}/services/${SP_KEY} ..."
HTTP_CODE=$(curl -s -o /dev/stderr -w "%{http_code}" \
    -X PUT \
    --data-binary "@${TMPFILE}" \
    "${IDP_BASE_URL}/services/${SP_KEY}")

if [ "$HTTP_CODE" -ge 200 ] && [ "$HTTP_CODE" -lt 300 ]; then
    echo "Success (HTTP ${HTTP_CODE}). SP registered with IdP."
else
    echo "Failed (HTTP ${HTTP_CODE}). Check that the IdP is running and accepts metadata uploads."
    exit 1
fi
