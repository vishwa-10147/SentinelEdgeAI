#!/usr/bin/env bash
# Prepare a backport branch for release fixes.
# Usage: ./scripts/prepare_backport.sh [base-branch]

set -euo pipefail

BASE=${1:-release}
BRANCH=backport/release-fixes

git fetch origin
if git show-ref --verify --quiet refs/heads/${BRANCH}; then
  echo "Branch ${BRANCH} already exists locally"
else
  if git ls-remote --exit-code --heads origin ${BASE}; then
    git checkout -b ${BRANCH} origin/${BASE}
  else
    git checkout -b ${BRANCH}
  fi
  echo "Created branch ${BRANCH} from ${BASE}" 
fi

echo "Edit files as needed, then push and create a PR:"
echo "  git push origin ${BRANCH}"
echo "  gh pr create --base ${BASE} --head ${BRANCH} --title 'Backport: critical fixes' --body 'Backporting critical fixes to ${BASE}'"
