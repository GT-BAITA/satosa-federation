#!/bin/bash
set -euo pipefail
mkdir -p etc/keys

# OIDC signing key (RSA 2048)
openssl genrsa -out etc/keys/oidc_signing.key 2048

# Federation signing key (EC P-256)
openssl ecparam -name prime256v1 -genkey -noout -out etc/keys/federation_ec.key

# SAML backend key + cert
openssl req -x509 -newkey rsa:2048 \
    -keyout etc/keys/saml_backend.key \
    -out etc/keys/saml_backend.crt \
    -days 365 -nodes -subj "/CN=satosa.labb.sunet.se"

echo "Keys generated in etc/keys/"
