#!/usr/bin/env bash
set -euo pipefail

# Provision a self-hosted GitHub Actions runner on Debian/Ubuntu.
# Usage: sudo ./scripts/provision_runner.sh <github_repo_or_org> <runner_token> [runner_version]

REPO=${1:-}
TOKEN=${2:-}
VERSION=${3:-2.307.0}

if [[ -z "$REPO" || -z "$TOKEN" ]]; then
  echo "Usage: $0 <github_repo_or_org> <runner_token> [runner_version]" >&2
  exit 2
fi

USER=actions-runner
ARCHIVE=actions-runner-linux-x64-${VERSION}.tar.gz
URL="https://github.com/actions/runner/releases/download/v${VERSION}/${ARCHIVE}"

adduser --disabled-password --gecos "" $USER || true
usermod -aG docker $USER || true

mkdir -p /home/$USER/actions-runner
chown $USER:$USER /home/$USER/actions-runner

sudo -u $USER bash -lc "
cd ~/actions-runner
curl -O -L ${URL}
tar xzf ${ARCHIVE}
./config.sh --url https://github.com/${REPO} --token ${TOKEN} --labels self-hosted,privileged --unattended
"

cat <<'EOF' > /etc/systemd/system/actions-runner.service
[Unit]
Description=GitHub Actions Runner
After=network.target docker.service

[Service]
User=actions-runner
WorkingDirectory=/home/actions-runner/actions-runner
ExecStart=/home/actions-runner/actions-runner/run.sh
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now actions-runner.service

echo "Runner provisioned and service started"
