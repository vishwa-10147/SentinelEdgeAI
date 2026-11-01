#!/usr/bin/env bash
# Live OIDC + SAML sign-in against a real Keycloak 26 in Docker (not part of pytest).
#   bash tests/live/run_keycloak_sso.sh
# Expected: alice (analyst group) signs in over OIDC and SAML; oscar (operator group) is refused for
# missing IdP MFA; nora (no mapped group) is refused.
set -euo pipefail
cd "$(dirname "$0")/../.."
D=$(mktemp -d); trap 'docker rm -f sentinel-kc >/dev/null 2>&1; rm -rf "$D"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$D/ca.key" -out "$D/ca.pem" -days 1 -subj "/CN=Test CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$D/tls.key" -out "$D/tls.csr" -subj "/CN=localhost" 2>/dev/null
printf "subjectAltName=DNS:localhost,IP:127.0.0.1\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" > "$D/ext.cnf"
openssl x509 -req -in "$D/tls.csr" -CA "$D/ca.pem" -CAkey "$D/ca.key" -CAcreateserial -out "$D/tls.pem" -days 1 -extfile "$D/ext.cnf" 2>/dev/null
chmod 644 "$D"/*
docker run -d --rm --name sentinel-kc -p 127.0.0.1:8443:8443 -v "$D":/certs:ro \
  -e KC_BOOTSTRAP_ADMIN_USERNAME=admin -e KC_BOOTSTRAP_ADMIN_PASSWORD=adminpass quay.io/keycloak/keycloak:26.0 \
  start-dev --https-certificate-file=/certs/tls.pem --https-certificate-key-file=/certs/tls.key --hostname=https://localhost:8443 >/dev/null
until curl -sf --cacert "$D/ca.pem" https://localhost:8443/realms/master >/dev/null; do sleep 3; done
KC_CERTS="$D" ${PYTHON:-.venv/bin/python} tests/live/keycloak_sso.py
