#!/usr/bin/env bash
set -euo pipefail

# Simple helper to install a local signing key file to /etc/sentinel/model_signing.key
# Usage: sudo ./provision_key.sh /path/to/keyfile

if [ "$EUID" -ne 0 ]; then
  echo "Run as root (sudo)" >&2
  exit 2
fi

if [ "$#" -ne 1 ]; then
  echo "Usage: $0 /path/to/keyfile" >&2
  exit 2
fi

KEY_SRC="$1"
KEY_DEST="/etc/sentinel/model_signing.key"

mkdir -p /etc/sentinel
cp "$KEY_SRC" "$KEY_DEST"
chmod 600 "$KEY_DEST"
chown root:root "$KEY_DEST"

echo "Installed signing key to $KEY_DEST (600)"
