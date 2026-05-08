Provisioning the model signing key with HashiCorp Vault

This document shows a recommended pattern to provision the HMAC signing key
to Pi devices securely using Vault and the Vault Agent (auto-auth). The
Vault Agent writes the secret to a local file which the sentinel service
reads via the `SENTINEL_MODEL_SIGNING_KEY_FILE` environment variable.

1) Store the key in Vault (example using CLI):

```bash
vault kv put secret/sentinel/model-signing key="<BASE64_OR_RAW_KEY>"
```

2) Example Vault Agent config (agent.hcl) on device:

```hcl
pid_file = "/var/run/vault-agent.pid"

auto_auth {
  method "approle" {
    mount_path = "auth/approle"
    config = {
      role_id_file_path = "/etc/vault/role_id"
      secret_id_file_path = "/etc/vault/secret_id"
    }
  }
}

template {
  source = "/etc/vault/templates/model_signing.tmpl"
  destination = "/etc/sentinel/model_signing.key"
  perms =  "0600"
}
```

3) Template file `/etc/vault/templates/model_signing.tmpl`:

```
{{ with secret "secret/data/sentinel/model-signing" }}{{ .Data.data.key }}{{ end }}
```

4) systemd unit for vault-agent (example): `/etc/systemd/system/vault-agent.service`

```ini
[Unit]
Description=Vault Agent (provision sentinel signing key)
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/bin/vault agent -config=/etc/vault/agent.hcl
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

5) Configure sentinel service to read key file via EnvironmentFile drop-in:

Create `/etc/systemd/system/sentineledgeai.service.d/signing_key.conf` containing:

```ini
[Service]
Environment= SENTINEL_MODEL_SIGNING_KEY_FILE=/etc/sentinel/model_signing.key
```

Then reload and restart:

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now vault-agent.service
sudo systemctl restart sentineledgeai.service
```

Notes
- Ensure Vault access method (AppRole) is secure for the device and tokens are short-lived.
- The file `/etc/sentinel/model_signing.key` must be readable only by the sentinel user (chmod 600).
- If you prefer asymmetric keys, write only the public verify key to devices and keep the private signing key in CI/Vault.

Automated setup (examples)

Copy the example agent config and template from the repository to the device and enable the service:

```bash
sudo mkdir -p /etc/vault/templates
sudo cp deploy/pi/vault_agent/agent.hcl /etc/vault/agent.hcl
sudo cp deploy/pi/vault_agent/model_signing.tmpl /etc/vault/templates/model_signing.tmpl
sudo cp deploy/pi/vault_agent/vault-agent.service /etc/systemd/system/vault-agent.service
sudo systemctl daemon-reload
sudo systemctl enable --now vault-agent.service
```

Ensure the sentinel service picks up the file by adding the drop-in (or editing your installed unit):

```bash
sudo mkdir -p /etc/systemd/system/sentineledgeai.service.d
cat <<'EOF' | sudo tee /etc/systemd/system/sentineledgeai.service.d/signing_key.conf
[Service]
Environment=SENTINEL_MODEL_SIGNING_KEY_FILE=/etc/sentinel/model_signing.key
EOF
sudo systemctl daemon-reload
sudo systemctl restart sentineledgeai.service
```

Install the local git pre-push hook to block unsigned models from being pushed (developer safety):

```bash
./scripts/install_pre_push_hook.sh
```

The hook runs `scripts/pre_push_check_signature.py` which uses the repository's
`security/model_signing.py` to verify any staged `*.pkl` model artifacts.

