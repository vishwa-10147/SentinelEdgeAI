#!/usr/bin/env bash
set -euo pipefail

# Simple helper to write the model signing key to Vault using the KV v2 API
# Usage: provision_vault_kv.sh <vault_addr> <vault_token> <key_value>

VAULT_ADDR=${1:-}
VAULT_TOKEN=${2:-}
KEY_VALUE=${3:-}

if [[ -z "$VAULT_ADDR" || -z "$VAULT_TOKEN" || -z "$KEY_VALUE" ]]; then
  echo "Usage: $0 <vault_addr> <vault_token> <key_value>" >&2
  exit 2
fi

export VAULT_ADDR
export VAULT_TOKEN

curl -sSf -X POST "$VAULT_ADDR/v1/secret/data/sentinel/model-signing" \
  -H "X-Vault-Token: $VAULT_TOKEN" \
  -d "{\"data\":{\"key\":\"$KEY_VALUE\"}}"

echo "Wrote model signing key to secret/sentinel/model-signing"
