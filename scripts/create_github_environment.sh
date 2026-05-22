#!/usr/bin/env bash
# Create a GitHub Environment and set secrets using the `gh` CLI.
# Usage: ./scripts/create_github_environment.sh [env-name]
# Requires: `gh` logged in and repo access. Prompts for missing secret values.

set -euo pipefail

ENV_NAME=${1:-render}

OWNER_REPO=$(gh repo view --json nameWithOwner -q .nameWithOwner) || {
  echo "Failed to determine repo owner/name. Ensure you're in the repo and gh is authenticated." >&2
  exit 2
}

echo "Creating environment '$ENV_NAME' in $OWNER_REPO (no-op if exists)"
gh api --method PUT "/repos/${OWNER_REPO}/actions/environments/${ENV_NAME}" >/dev/null || true

set_secret(){
  name="$1"
  value="${!2:-}"
  if [ -z "$value" ]; then
    read -r -p "Enter value for $name (or leave empty to skip): " input
    value="$input"
  fi
  if [ -n "$value" ]; then
    echo "$value" | gh secret set "$name" --repo "$OWNER_REPO" --env "$ENV_NAME" --body -
    echo "Set environment secret: $name"
  else
    echo "Skipping $name (no value provided)"
  fi
}

# Secrets we commonly use for deploys/migrations
set_secret RENDER_API_KEY RENDER_API_KEY
set_secret RENDER_SERVICE_ID RENDER_SERVICE_ID
set_secret DATABASE_URL DATABASE_URL

echo "Done. Review environment in GitHub: https://github.com/${OWNER_REPO}/settings/environments/${ENV_NAME}"
