# Self-hosted Runner (Privileged) Setup

This guide shows how to provision a self-hosted GitHub Actions runner with the `self-hosted,linux,docker` labels, suitable for running integration tests that require Docker or elevated host access.

Security note: a self-hosted runner executes arbitrary workflow code from your repository. Only register runners on isolated hosts you control and restrict repository access.

Steps (summary):

1. Create a runner from your repository settings (Settings → Actions → Runners → New self-hosted runner).
2. On the runner host, follow the registration steps and add the labels `self-hosted,linux,docker`.
3. Install the runner as a service so it starts on boot.

Commands (example; replace placeholders):

```bash
# on the runner host
mkdir -p ~/actions-runner && cd ~/actions-runner
curl -L -o actions-runner.tar.gz \
  "https://github.com/actions/runner/releases/latest/download/actions-runner-linux-x64.tar.gz"
tar xzf ./actions-runner.tar.gz

# retrieve the token and registration URL from GitHub when creating the runner
./config.sh --url https://github.com/<OWNER>/<REPO> --token <RUNNER_TOKEN> --labels self-hosted,linux,docker
sudo ./svc.sh install
sudo ./svc.sh start
```

Minimal runner policy recommendations:
- Use a dedicated VM/container for privileged runners.
- Limit network access and use firewall rules to isolate the runner.
- Rotate the registration token if the host is re-used.

Using the workflow
- `.github/workflows/privileged-integration.yml` (pushes to `main`, manual runs) and `containerized-firewall-integration.yml` (pull requests) run on `runs-on: [self-hosted, linux, docker]`, so they only execute on runners with those labels.

If you want, run `scripts/setup_runner.sh --help` on the runner host to automate common steps.
