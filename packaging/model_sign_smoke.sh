#!/usr/bin/env bash
set -euo pipefail

PYTHON=${PYTHON:-python3}
TMPDIR=$(mktemp -d)
KEYFILE="$TMPDIR/key.txt"
MODEL="model/isolation_forest.pkl"
BACKUP_SIG="$TMPDIR/model.sig.bak"

if [ ! -f "$MODEL" ]; then
  echo "model not found: $MODEL" >&2
  exit 1
fi

if [ -f "${MODEL}.sig" ]; then
  cp "${MODEL}.sig" "$BACKUP_SIG"
fi

# generate a random key
${PYTHON} - <<'PY' > "$KEYFILE"
import secrets
print(secrets.token_hex(32))
PY

export SENTINEL_MODEL_SIGNING_KEY_FILE="$KEYFILE"

echo "Signing $MODEL using temporary key..."
${PYTHON} scripts/sign_model.py "$MODEL"

echo "Verifying signature for $MODEL..."
${PYTHON} scripts/sign_model.py --verify "$MODEL"

echo "Model signing smoke test succeeded"

# restore original signature if it existed
if [ -f "$BACKUP_SIG" ]; then
  mv "$BACKUP_SIG" "${MODEL}.sig"
fi

rm -rf "$TMPDIR"
