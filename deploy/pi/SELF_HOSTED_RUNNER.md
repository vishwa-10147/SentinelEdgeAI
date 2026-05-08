Self-hosted runner for privileged integration tests

This document describes a minimal, repeatable setup to provision a self-hosted
GitHub Actions runner that can execute privileged container integration tests
that require `--cap-add NET_ADMIN` or access to host networking.

Prereqs (on the runner host)
- Ubuntu 22.04 or Debian-based system
- Docker installed and the runner user in the `docker` group
- Sufficient disk and network access

Quick install (example):

```bash
# create runner user
sudo useradd -m -s /bin/bash actions-runner
sudo usermod -aG docker actions-runner

sudo -iu actions-runner bash <<'EOF'
mkdir -p ~/actions-runner && cd ~/actions-runner
# fetch the latest runner (replace URL with desired runner version)
curl -O -L https://github.com/actions/runner/releases/download/v2.307.0/actions-runner-linux-x64-2.307.0.tar.gz
tar xzf actions-runner-linux-x64-2.307.0.tar.gz
EOF

# Register the runner in your repo settings (use a repo-level or org-level registration token)
# Follow GitHub docs: Settings → Actions → Runners → Add runner. Use labels like `self-hosted`, `pi`, `privileged`.
```

Systemd service (example) - once runner is registered, install a systemd unit as the runner user:

```ini
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
```

Runner labels and security
- Use labels `privileged` or `net-admin` for jobs that need NET_ADMIN. Restrict which workflows can use these labels.
- Run the runner on isolated infrastructure (not the same host that contains secrets or production workloads).
- Limit runner IAM and network access; rotate tokens and use ephemeral VMs when possible.

Workflow example uses `runs-on: [self-hosted, privileged]` in `.github/workflows/privileged-integration.yml`.
Self-hosted GitHub Actions Runner for Privileged Firewall Integration

Purpose
-------
This guide explains how to set up a self-hosted runner to execute the privileged integration tests under
`.github/workflows/privileged-integration.yml`. The tests require Docker and the ability to add `NET_ADMIN` capability
to containers. Do not run these tests on GitHub-hosted runners.

Security note
-------------
- A self-hosted runner runs arbitrary code from your repository — restrict it to protected branches or run in an
  isolated VM/container. Use short-lived runners for CI or a dedicated machine in an isolated network.
- Limit who can trigger `workflow_dispatch` or who can push to the branch that triggers this workflow.
- Add the runner only to repositories that require privileged tests. Do not use a broad organization runner unless you have strict runner groups and workflow approvals.
- Protect `main`, require reviews for workflow changes, and restrict who can run manual privileged workflows.
- Rotate the runner registration token after provisioning and remove stale/offline runners from GitHub.

Prerequisites
-------------
- Ubuntu 22.04 or similar Linux host.
- Docker installed and configured for non-root use (recommended) or root access available.
- GitHub repo admin privileges to register the runner.

Install steps (example)
-----------------------
1. Create a dedicated directory and user (optional):

```bash
sudo useradd -m -s /bin/bash gh-runner || true
sudo mkdir -p /opt/gh-runner
sudo chown gh-runner:gh-runner /opt/gh-runner
sudo -u gh-runner -i
cd /opt/gh-runner
```

2. Download and configure the runner for your repository (follow the GitHub UI for the repo → Settings → Actions → Runners → New self-hosted runner). Choose labels `self-hosted`, `linux`, `docker` (or others you prefer).

3. Install Docker and ensure the runner user can run Docker and build containers:

```bash
sudo apt update && sudo apt install -y docker.io
sudo usermod -aG docker $USER   # or add gh-runner to docker group
newgrp docker
docker run --rm hello-world
```

4. Configure the runner service to start on boot (GitHub runner provides a systemd unit during setup). Ensure the runner has access to the Docker socket at `/var/run/docker.sock`.

Running privileged tests
-----------------------
- The privileged workflow uses `pytest` with `SENTINEL_RUN_FIREWALL_CONTAINER_TESTS=1` and expects the runner to be able to build and run containers with `--cap-add NET_ADMIN`.
- Trigger the workflow manually from GitHub (Actions → workflows → Privileged Integration Tests → Run workflow). Provide any required inputs.
- To validate the rollback guard in the same workflow, set the `run_rollback_validation` input to `true`.

Example manual command to validate locally on the runner host:

```bash
# from repo root on the runner host
export SENTINEL_RUN_FIREWALL_CONTAINER_TESTS=1
pytest -q tests/test_firewall_container_integration.py
```

Notes & troubleshooting
----------------------
- If Docker build fails due to missing packages, inspect the `tests/firewall_container/Dockerfile` and ensure packages are available for your architecture.
- If containers cannot add `NET_ADMIN`, verify the Docker daemon and runner environment can grant capabilities; some managed environments restrict adding capabilities.
- Clean up images between runs if disk space is constrained:

```bash
docker image prune -af
```

Cleanup
-------
- When decommissioning the runner, unregister it from GitHub (Actions runner UI) and remove the systemd service. Delete local images and runner files.
