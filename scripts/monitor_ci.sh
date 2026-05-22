#!/usr/bin/env bash
# Simple monitor for CI runs related to privileged/containerized integration.
# Usage: ./scripts/monitor_ci.sh [workflow-name-substring]

set -euo pipefail

FILTER=${1:-"Containerized Firewall Integration"}

echo "Listing recent runs that match: '$FILTER'"
gh run list --limit 50 --repo "$(gh repo view --json nameWithOwner -q .nameWithOwner)" | grep "$FILTER" || echo "No recent runs matching '$FILTER'"

echo
echo "To watch a specific run use: gh run watch <run-id>"
