Self-hosted runner required for privileged Docker integration tests

Overview
--------
The `containerized-firewall-integration.yml` workflow runs firewall integration tests inside a Docker container with `--cap-add=NET_ADMIN` and `--cap-add=SYS_ADMIN`. GitHub hosted runners do not allow starting privileged Docker containers on all images; therefore we require a self-hosted runner with Docker installed and the `docker` label.

Prerequisites for the self-hosted runner host
------------------------------------------------
- A Linux VM (Ubuntu 22.04/24.04 recommended) or a physical machine.
- Docker Engine installed and running.
- A user account to register the GitHub Actions runner.
- Network connectivity to GitHub (outbound HTTPS).

Recommended labels
------------------
When registering the runner, apply these labels so the workflow matches it:

- `self-hosted`
- `linux`
- `docker`

Quick setup (example commands to run on the runner host)
-------------------------------------------------------
1) Create a directory for the runner and download the runner package (replace `<OWNER/REPO>`):

```bash
mkdir -p ~/actions-runner && cd ~/actions-runner
curl -fsSL -o actions-runner.tar.gz https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64.tar.gz
tar xzf actions-runner.tar.gz
```

2) Install Docker (Ubuntu example):

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl gnupg lsb-release
sudo mkdir -p /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" |
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io
sudo systemctl enable --now docker
```

3) Add runner user to `docker` group so the runner can run Docker without sudo (optional):

```bash
sudo usermod -aG docker $USER
newgrp docker
```

4) Register the runner with GitHub (replace placeholders from your repo > Settings > Actions > Runners):

```bash
# Visit: https://github.com/<OWNER>/<REPO>/settings/actions/runners and copy the registration command
./config.sh --url https://github.com/<OWNER>/<REPO> --token <RUNNER_TOKEN> --labels "self-hosted,linux,docker"
sudo ./svc.sh install
sudo ./svc.sh start
```

Notes and safety
----------------
- The runner process will have network and Docker access. Only register runners you control.
- Ensure `docker` is the official Docker Engine; avoid installing conflicting container runtimes that may block `containerd` packages.
- If you use a cloud VM, restrict access with firewall rules and keep the OS updated.

After the runner is online
-------------------------
1) Re-dispatch the `containerized-firewall-integration.yml` workflow (from the PR UI or CLI) to execute on the self-hosted runner.
2) I'll monitor the run and fetch logs to triage any test failures.

CI helper notes
---------------
- The project now includes a CI security workflow (`.github/workflows/security-scans.yml`) that runs `pip-audit` and `bandit` and uploads JSON reports as artifacts.
- Some CI steps (e.g. the CI health-server helper `scripts/run_ci_health_server.py`) require the repository root on `PYTHONPATH` when launched under `nohup` or CI environments. The helper script now auto-adds the repo root to `sys.path` when executed directly.
