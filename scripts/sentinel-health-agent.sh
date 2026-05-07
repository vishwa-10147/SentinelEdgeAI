#!/bin/bash
# Lightweight health agent: copies /etc/sentinel/health.env -> /run/sentinel/health.env
# Ensures runtime file lives in tmpfs and has 600 perms. Safe to call repeatedly.
set -euo pipefail
SRC=/etc/sentinel/health.env
DSTDIR=/run/sentinel
DST=${DSTDIR}/health.env

if [ ! -r "$SRC" ]; then
  logger -t sentinel-health-agent "Source $SRC not readable"
  exit 1
fi

mkdir -p "$DSTDIR"
chown root:root "$DSTDIR"
chmod 700 "$DSTDIR"

# write atomically
TMP=$(mktemp -p "$DSTDIR" .health.env.tmp.XXXXXX)
cat "$SRC" > "$TMP"
chmod 600 "$TMP"
chown root:root "$TMP"
mv "$TMP" "$DST"
logger -t sentinel-health-agent "Wrote runtime health env to $DST"
exit 0
