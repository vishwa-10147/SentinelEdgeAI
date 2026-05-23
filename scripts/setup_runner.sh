#!/usr/bin/env bash
set -euo pipefail

usage(){
  cat <<EOF
Usage: $0 --url <repo_url> --token <runner_token> [--labels <labels>]

Example:
  $0 --url https://github.com/owner/repo --token ABCDEF --labels self-hosted,privileged
EOF
}

REPO_URL=""
TOKEN=""
LABELS="self-hosted,privileged"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --url) REPO_URL="$2"; shift 2;;
    --token) TOKEN="$2"; shift 2;;
    --labels) LABELS="$2"; shift 2;;
    -h|--help) usage; exit 0;;
    *) echo "Unknown arg: $1"; usage; exit 2;;
  esac
done

if [[ -z "$REPO_URL" || -z "$TOKEN" ]]; then
  echo "--url and --token are required"
  usage
  exit 2
fi

mkdir -p ~/actions-runner
cd ~/actions-runner

echo "Downloading latest Actions runner..."
curl -L -o actions-runner.tar.gz \
  "https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64.tar.gz"
tar xzf ./actions-runner.tar.gz

echo "Configuring runner for $REPO_URL with labels: $LABELS"
./config.sh --url "$REPO_URL" --token "$TOKEN" --labels "$LABELS"

echo "Installing service"
sudo ./svc.sh install
sudo ./svc.sh start

echo "Runner configured and service started. Use 'sudo ./svc.sh status' to check."
