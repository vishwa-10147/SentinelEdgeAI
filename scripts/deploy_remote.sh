#!/usr/bin/env bash
set -euo pipefail

# deploy_remote.sh
# Usage: ./scripts/deploy_remote.sh user@pi_host [remote_path]
# Copies this repo to the Pi and runs the installer there.

if [ "$#" -lt 1 ]; then
  echo "Usage: $0 user@host [remote_path]"
  exit 1
fi

HOST="$1"
REMOTE_PATH="${2:-~/SentinelEdgeAI}"

echo "Copying repository to $HOST:$REMOTE_PATH (this may take a while)..."
rsync -azh --exclude .git --exclude '__pycache__' . "$HOST:$REMOTE_PATH"

echo "Setting permissions and running remote installer..."
ssh "$HOST" "cd $REMOTE_PATH && chmod +x scripts/setup_pi.sh && sudo bash scripts/setup_pi.sh"

cat <<EOF

Deployment finished.
Next steps on the Pi (recommended):
  # Activate venv and run smoke test
  ssh $HOST 'source $HOME/.venv/sentineledgeai/bin/activate && python $REMOTE_PATH/scripts/smoke_test.py'
  # View logs
  ssh $HOST 'sudo journalctl -u sentineledgeai.service -f'
EOF
