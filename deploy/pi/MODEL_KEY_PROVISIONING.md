# Model Signing Key Provisioning

SentinelEdgeAI verifies `joblib` model artifacts before loading them. Runtime verification requires the same signing key used by CI to produce the `.sig` file.

## CI Signing

Store this GitHub Actions secret:

```text
SENTINEL_MODEL_SIGNING_KEY
```

The `.github/workflows/model-signing.yml` workflow signs `model/isolation_forest.pkl`, verifies it, checks tamper detection, and uploads:

- `model/isolation_forest.pkl`
- `model/isolation_forest.pkl.sig`

Do not print or commit the signing key.

## Device Runtime

Recommended Pi layout:

```bash
sudo mkdir -p /etc/sentinel
sudo install -m 600 -o root -g root model-signing.key /etc/sentinel/model-signing.key
```

Add a systemd drop-in for the SentinelEdgeAI service:

```bash
sudo mkdir -p /etc/systemd/system/sentineledgeai.service.d
sudo tee /etc/systemd/system/sentineledgeai.service.d/model-signing.conf >/dev/null <<'EOF'
[Service]
Environment="SENTINEL_MODEL_SIGNING_KEY_FILE=/etc/sentinel/model-signing.key"
EOF
sudo systemctl daemon-reload
sudo systemctl restart sentineledgeai.service
```

## Vault-Based Provisioning

If using Vault, store the key as `SENTINEL_MODEL_SIGNING_KEY` and render it to `/etc/sentinel/model-signing.key` during device provisioning. Keep permissions at `0600 root:root`.

Example:

```bash
vault kv put secret/sentineledge/model SENTINEL_MODEL_SIGNING_KEY='<long-random-key>'
vault kv get -field=SENTINEL_MODEL_SIGNING_KEY secret/sentineledge/model \
  | sudo tee /etc/sentinel/model-signing.key >/dev/null
sudo chmod 600 /etc/sentinel/model-signing.key
sudo chown root:root /etc/sentinel/model-signing.key
```

## Development Override

For local development only:

```bash
SENTINEL_ALLOW_UNSIGNED_MODELS=1 .venv/bin/python scripts/smoke_test.py
```

Do not set `SENTINEL_ALLOW_UNSIGNED_MODELS=1` on production devices.
