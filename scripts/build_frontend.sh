#!/usr/bin/env bash
set -euo pipefail

# Build the frontend into `frontend/dist` for serving by FastAPI.
REPO_DIR="$(cd "$(dirname "$0")/.." && pwd)"
FRONTEND_DIR="$REPO_DIR/frontend"

if ! command -v npm >/dev/null 2>&1; then
  echo "npm not found — please install Node.js and npm to build the frontend"
  exit 2
fi

cd "$FRONTEND_DIR"
echo "Installing frontend dependencies (this may take a few minutes)"
# use legacy-peer-deps to avoid peer dependency conflicts on older plugin versions
npm install --legacy-peer-deps
echo "Building frontend"
npm run build
echo "Build complete — output in $FRONTEND_DIR/dist"