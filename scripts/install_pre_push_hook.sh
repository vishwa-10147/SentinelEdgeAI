#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(git rev-parse --show-toplevel)"
HOOK_SRC="$REPO_ROOT/scripts/git_hooks/pre-push"
HOOK_DEST="$REPO_ROOT/.git/hooks/pre-push"

if [ ! -d "$REPO_ROOT/.git" ]; then
  echo "Not a git repository: $REPO_ROOT" >&2
  exit 1
fi

mkdir -p "$(dirname "$HOOK_DEST")"
cp "$HOOK_SRC" "$HOOK_DEST"
chmod +x "$HOOK_DEST"
echo "Installed pre-push hook -> $HOOK_DEST"
