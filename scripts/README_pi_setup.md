Pi setup notes

1. Make the installer executable and run it:

```bash
chmod +x scripts/setup_pi.sh
sudo bash scripts/setup_pi.sh        # installs main.py service
sudo bash scripts/setup_pi.sh streamlit   # installs Streamlit service
```

2. Edit `config.yaml` before starting for production settings. Use `scripts/config.example.yaml` as a template.

3. To use `.env`, copy `scripts/.env.example` to `.env` and edit.

4. View logs:

```bash
sudo journalctl -u sentineledgeai.service -f
sudo journalctl -u sentineledgeai-streamlit.service -f
```

5. Hardware permissions: add your user to `video` group if camera access is required:

```bash
sudo usermod -aG video $USER
```

Reboot or re-login after group changes.

6. Environment overrides

 - You can create a `.env` file in the repo root to set environment variables. The installer will install `python-dotenv` into the virtualenv so these variables are loaded automatically.
 - To override nested config keys use double-underscores. Example:

```bash
# set logging.level=DEBUG
logging__level=DEBUG
```

The loader will attempt to cast overridden values to the existing config value type when possible.

7. Smoke test

 - A small smoke-test script was added at `scripts/smoke_test.py`. Run it inside the venv to quickly verify the environment and imports:

```bash
source $HOME/.venv/sentineledgeai/bin/activate
python scripts/smoke_test.py
```

The script returns exit code `0` on success and non-zero on failure. Use it before enabling the systemd service.
