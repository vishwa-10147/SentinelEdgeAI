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

Install the key with the helper. It writes `/etc/sentinel/model_signing.key`, and `sentinelctl` then makes it readable to the `sentinel` service user:

```bash
sudo bash sentineledgeai-pi-<version>/deploy/pi/provision_key.sh /path/to/model_signing.key
```

`sentinelctl install` sets `SENTINEL_MODEL_SIGNING_KEY_FILE=/etc/sentinel/model_signing.key` in `/etc/sentinel/sentinel.env`. Every service reads it from there; no systemd drop-in is needed. Without a valid key the engine refuses to load the model, and the install's health check fails and rolls back.

The release Isolation Forest is HMAC-signed, so this key can also *sign* it. Keep it as secret as any credential. Moving that model to the Ed25519 registry, so devices hold only a public key, is planned (SECURITY.md §5). Models from the registry (autoencoder, federated models) already use Ed25519 keys created on the device.

## Vault-Based Provisioning

If using Vault, store the key as `SENTINEL_MODEL_SIGNING_KEY` and render it to `/etc/sentinel/model_signing.key` during device provisioning. Keep permissions at `0640 root:sentinel` (readable by the service, not by other users).

Example:

```bash
vault kv put secret/sentineledge/model SENTINEL_MODEL_SIGNING_KEY='<long-random-key>'
vault kv get -field=SENTINEL_MODEL_SIGNING_KEY secret/sentineledge/model \
  | sudo tee /etc/sentinel/model_signing.key >/dev/null
sudo chmod 640 /etc/sentinel/model_signing.key
sudo chown root:sentinel /etc/sentinel/model_signing.key
```

## Development Override

For local development only:

```bash
SENTINEL_ALLOW_UNSIGNED_MODELS=1 .venv/bin/python scripts/smoke_test.py
```

Do not set `SENTINEL_ALLOW_UNSIGNED_MODELS=1` on production devices.
