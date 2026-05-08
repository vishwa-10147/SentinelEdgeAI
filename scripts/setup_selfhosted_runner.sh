#!/usr/bin/env bash
set -euo pipefail

# Usage:
# OWNER_REPO=owner/repo RUNNER_TOKEN=... ./scripts/setup_selfhosted_runner.sh [labels]
# Example:
# OWNER_REPO=vishwa-10147/SentinelEdgeAI RUNNER_TOKEN=abc123 ./scripts/setup_selfhosted_runner.sh "self-hosted,linux,docker"

OWNER_REPO=${OWNER_REPO:-}
RUNNER_TOKEN=${RUNNER_TOKEN:-}
LABELS=${1:-"self-hosted,linux,docker"}

if [ -z "$OWNER_REPO" ] || [ -z "$RUNNER_TOKEN" ]; then
  echo "ERROR: OWNER_REPO and RUNNER_TOKEN environment variables are required"
  echo "See top of this script for usage." >&2
  exit 2
fi

set -x

# Install Docker Engine (Ubuntu/Debian)
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" |
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo systemctl enable --now docker

# Add current user to docker group so runner can use docker
sudo usermod -aG docker "$USER" || true

# Install GitHub Actions runner
RUNNER_DIR="$HOME/actions-runner"
mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"

ARCH="x64"
TARBALL_URL="https://github.com/actions/runner/releases/latest/download/actions-runner-linux-${ARCH}.tar.gz"
curl -fsSL -o actions-runner.tar.gz "$TARBALL_URL"
tar xzf actions-runner.tar.gz

echo "Registering runner for https://github.com/$OWNER_REPO with labels: $LABELS"
./config.sh --url https://github.com/$OWNER_REPO --token "$RUNNER_TOKEN" --labels "$LABELS" --unattended

sudo ./svc.sh install
sudo ./svc.sh start

echo "Self-hosted runner installed and started. Verify at: https://github.com/$OWNER_REPO/settings/actions/runners"
