#!/usr/bin/env bash
set -euo pipefail

# OWASP ZAP baseline scan of a running console (Phase 1 exit check).
#
#   bash scripts/zap_baseline.sh                         # https://127.0.0.1:9000
#   bash scripts/zap_baseline.sh https://192.168.50.4:9000
#
# Needs Docker. The report lands in reports/zap/ (zap.html, zap.json).
# Exits non-zero on any FAIL or WARN that is not ignored in
# security/zap-baseline.conf.

REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
TARGET="${1:-https://127.0.0.1:9000}"
IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy:stable}"
OUT="$REPO_DIR/reports/zap"

mkdir -p "$OUT"
cp "$REPO_DIR/security/zap-baseline.conf" "$OUT/zap-baseline.conf"
chmod 777 "$OUT"
docker run --rm --network host -v "$OUT:/zap/wrk:rw" "$IMAGE" \
  zap-baseline.py -t "$TARGET" -c zap-baseline.conf -r zap.html -J zap.json
