#!/bin/bash
set -euo pipefail
mkdir -p etc/keys

# Federation signing key (EC P-256)
# Used for: Entity Configuration, request objects, private_key_jwt
openssl ecparam -name prime256v1 -genkey -noout -out etc/keys/rp_federation_ec.key

# SAML frontend key + cert (acts as IdP to SAML SPs)
openssl req -x509 -newkey rsa:2048 \
    -keyout etc/keys/saml_frontend.key \
    -out etc/keys/saml_frontend.crt \
    -days 365 -nodes -subj "/CN=satosarp.labb.sunet.se"

chmod 600 etc/keys/*.key

echo "Keys generated in etc/keys/"
