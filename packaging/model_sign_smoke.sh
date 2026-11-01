#!/usr/bin/env bash
# Smoke test of release model signing with a throw-away Ed25519 key, on a copy of the model.
set -euo pipefail

PYTHON=${PYTHON:-python3}
MODEL="model/isolation_forest.pkl"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

[ -f "$MODEL" ] || { echo "model not found: $MODEL" >&2; exit 1; }
cp "$MODEL" "$TMPDIR/isolation_forest.pkl"

${PYTHON} scripts/sign_model.py --generate-key "$TMPDIR/key.pem" --public-key "$TMPDIR/key.pub" >/dev/null
export SENTINEL_MODEL_SIGNING_KEY_FILE="$TMPDIR/key.pem"
export SENTINEL_MODEL_PUBLIC_KEY_FILE="$TMPDIR/key.pub"

echo "Signing a copy of $MODEL with a temporary key..."
${PYTHON} scripts/sign_model.py "$TMPDIR/isolation_forest.pkl" --quiet
echo "Verifying..."
${PYTHON} scripts/sign_model.py "$TMPDIR/isolation_forest.pkl" --verify --quiet
printf tamper >> "$TMPDIR/isolation_forest.pkl"
if ${PYTHON} scripts/sign_model.py "$TMPDIR/isolation_forest.pkl" --verify --quiet 2>/dev/null; then
  echo "tampered model verified" >&2; exit 1
fi
echo "Model signing smoke test succeeded"
