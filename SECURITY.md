# Security Policy

SentinelEdgeAI is a security appliance that can block network traffic. A flaw in it can either let attackers through or let an attacker turn it against the network it protects. This document explains how to report vulnerabilities, what the system defends against, which controls exist today, which are still missing, and how to deploy it safely.

Status legend: ✅ in place · 🟡 partial · 🔜 planned (see [PLAN.md](PLAN.md))

---

## 1. Reporting a vulnerability

**Please do not open a public GitHub issue for security problems.**

1. Use GitHub's private reporting: **Security → Report a vulnerability** on the repository.
2. Include: affected version/commit, component (sensor, brain, API, console, installer), steps to reproduce, and the impact you observed.
3. You will receive an acknowledgement within **3 business days** and a triage decision within **10 business days**.
4. Fixes are released as patch versions. Reporters are credited unless they ask not to be.

Please give us up to **90 days** to ship a fix before public disclosure. Do not test against networks you do not own or are not authorised to test.

### Supported versions

| Version | Security fixes |
|---|---|
| `main` / latest `0.9.x` | ✅ |
| older pre-releases | ❌ — upgrade to the latest |

From `v1.0` onward, the current and previous minor release will receive security fixes.

---

## 2. What we protect, and from whom

### Assets
* **The protected network's availability** — the appliance must never cause an outage.
* **Traffic metadata** — flows, IPs, MACs, device profiles and alerts reveal how the organisation works.
* **Enforcement capability** — the power to block or quarantine devices.
* **Detection models** — a tampered model could hide an attacker.
* **Credentials and keys** — API credentials, model signing key, TLS keys, database passwords.

### Threat actors
| Actor | Example goal |
|---|---|
| Attacker already inside the LAN | Evade detection; abuse the API to block the gateway or admins (denial of service) |
| Compromised IoT device | Flood the sensor to blind it or crash it |
| Malicious or careless insider | Change policy, whitelist themselves, delete evidence |
| Supply-chain attacker | Ship a poisoned model, dependency or installer |
| Network attacker between Pi and Jetson 🔜 | Forge flow data or forge "block" commands |

### Key threats and mitigations

| Threat | Mitigation | Status |
|---|---|---|
| Unauthorised use of the API (block/unblock/policy) | API key, or localhost-only when no key is set | ✅ |
| | Per-user accounts, roles, MFA, session expiry | 🔜 |
| | Rate limiting and lockout on login | 🔜 |
| Eavesdropping on the console/API | HTTPS with a certificate created at install | 🔜 |
| Appliance blocks critical hosts (self-DoS) | Whitelist; `127.0.0.1` always whitelisted | ✅ |
| | Auto-detect and protect gateway, DNS, management IPs | 🔜 |
| Bad rules lock the network | Dry-run default, TTL expiry, rollback API, systemd rollback guard | ✅ |
| Command injection through firewall calls | IP/TTL validation; argument lists only (no shell); metacharacter checks; `utils/subprocess_safe.py` | ✅ |
| Tampered ML model | HMAC-SHA256 model signatures verified at load; CI signature check | ✅ |
| | Asymmetric (Ed25519) signatures so devices hold only a public key | 🔜 |
| Forged sensor data or commands between Pi and Jetson | Mutual TLS with per-device certificates; signed, replay-protected commands | 🔜 |
| Sensor overload / blinding | Bounded queues and flow-table limit | 🟡 |
| | Back-pressure, sampling under load, overload alerting | 🔜 |
| Leaking sensitive data in screenshots/demos | `REDACT_SENSITIVE=1` hashes IPs and MACs in API output | ✅ |
| Vulnerable dependencies | `pip-audit` + Bandit in CI; pinned versions | ✅ |
| | Dependabot, SBOM per release, separate runtime vs dev requirements | 🔜 |
| Evidence tampering | Append-only firewall action log | 🟡 |
| | Tamper-evident (hash-chained) audit log for all user actions | 🔜 |

---

## 3. Security architecture

### Authentication and access (today)
* If `DASHBOARD_API_KEY` is set, every request must carry it as `X-API-Key: <key>` or `Authorization: Bearer <key>`.
* If it is **not** set, the API only answers requests from `127.0.0.1` / `::1`.
* The API binds to `127.0.0.1` by default (`SENTINEL_HOST`). The Docker image binds `0.0.0.0` inside the container but still requires the key or localhost.
* Interactive API docs (`/docs`, `/redoc`) are disabled.
* The health endpoint supports Basic auth via `HEALTH_USER` / `HEALTH_PASS`.

### Authentication and access (target, v1.0)
Accounts are stored on the Jetson with Argon2id password hashes. TOTP MFA is required for Operator and Admin. Short-lived access tokens plus refresh tokens. Every action is written to a hash-chained audit log.

| Role | Can |
|---|---|
| **Viewer** | See dashboards and reports |
| **Analyst** | Viewer + investigate, annotate and acknowledge alerts, export data |
| **Operator** | Analyst + block, unblock, quarantine, and approve pending responses |
| **Admin** | Operator + policy, users, sensors, model promotion, integrations |

### Firewall safety model
1. **Dry-run by default** (`FIREWALL_DRY_RUN=1`). Real enforcement must be turned on explicitly with `deploy/pi/enforcement_ctl.sh enable`.
2. **Response mode `monitor`** by default — detections alert but do not auto-block until policy allows it.
3. **Every block has a TTL** (default 300 s, max 24 h) unless an operator makes it permanent.
4. **Whitelist** checked before any block.
5. **Rollback**: one API call (`/api/firewall/rollback`) or the rollback script removes every SentinelEdgeAI rule. A systemd timer (`sentinel-firewall-rollback-guard`) rolls back automatically if the service is unhealthy.
6. **Fail-open** 🔜: in inline mode, a failure of the appliance must pass traffic, not drop it.

### Model integrity
* `model/isolation_forest.pkl` is signed; the signature (`.pkl.sig`) includes the file's SHA-256 and is verified with HMAC-SHA256 before the model is loaded.
* Loading fails if verification fails, unless `SENTINEL_ALLOW_UNSIGNED_MODELS=1` (development only — never in production).
* Models are Python pickles; **only load models produced by your own signed pipeline**. Pickle files from elsewhere can execute code.

### Data handling
* All data stays on the appliance. No telemetry is sent anywhere.
* Stored: flow metadata (no payloads), alerts, device profiles, firewall actions, logs. Packet payloads are not stored.
* Retention and VACUUM run in the background (`core/db_maintenance.py`).
* Encryption at rest 🔜: LUKS on the SSD, with the key held in the TPM where available or entered at boot.

---

## 4. Secrets management

| Secret | How to provide it | Never |
|---|---|---|
| Model signing key | `SENTINEL_MODEL_SIGNING_KEY_FILE=/etc/sentinel/model_signing.key` (mode `600`, owned by the service user), provisioned by `deploy/pi/provision_key.sh` or Vault Agent (`deploy/pi/VAULT_PROVISION.md`) | Commit it, put it in Docker images, or pass it on the command line |
| API key | systemd `EnvironmentFile` with mode `600` | Put it in URLs or front-end code |
| Health credentials | `/etc/sentinel/health.env` (mode `600`) | Commit `.env` files |
| Database password | `DATABASE_URL` in an `EnvironmentFile` | Log it |
| CI signing key | GitHub Actions secret `SENTINEL_MODEL_SIGNING_KEY` | Echo it in workflow logs |

`.gitignore` blocks `*.key`, `*.pem`, `*.env` and runtime data.

### Incident note: signing key in git history
Earlier commits contained `model_signing.key` at the repository root, and `.ci_test_health.env` with health-check credentials. These files are no longer tracked, but **they remain in git history**, so both are treated as compromised.

| Step | Status |
|---|---|
| Verify the current model against the old key before re-signing (so a tampered model is not re-blessed) | ✅ 2026-10-30 |
| Generate a new 256-bit signing key, stored outside the repository | ✅ 2026-10-30 |
| Re-sign `model/isolation_forest.pkl` and commit the new `.sig` | ✅ 2026-10-30 |
| Update the `SENTINEL_MODEL_SIGNING_KEY` GitHub secret | ✅ 2026-10-30 |
| Install the new key on every device (`deploy/pi/provision_key.sh`) — devices with the old key will refuse the newly signed model | ⏳ per device |
| Change any health-check credentials that match the old `.ci_test_health.env` values | ⏳ per device |
| Optionally purge both files from history (`git filter-repo`) and force-push; everyone must then re-clone | Optional |

The old key no longer verifies any committed model, so a model signed with it will be rejected by updated devices and CI.

---

## 5. Known security issues (v0.9)

| # | Issue | Impact | Tracked in |
|---|---|---|---|
| 1 | ~~Firewall commands rejected by the subprocess wrapper; nftables set never attached to a chain~~ | **Fixed in 0.9.1** — blocks had no effect | — |
| 2 | ~~iptables removal omitted the comment match used at insert~~ | **Fixed in 0.9.1** | — |
| 3 | Bridge-level (layer 2) filtering and MAC quarantine not implemented; `INPUT` and `FORWARD` are covered | Devices on the same bridge segment are not isolated | Phase 3 |
| 4 | Single shared API key, no per-user identity | No accountability; key compromise grants full control | Phase 1 |
| 5 | No TLS on API/WebSocket | Credentials and data readable on the management network | Phase 1 |
| 6 | No rate limiting | Brute force of the API key; API flooding | Phase 1 |
| 7 | HMAC model signing — every verifier holds the signing key | A compromised device can sign models | Phase 4 |
| 8 | Dev tools (pytest, bandit, pip-audit, streamlit) in runtime requirements | Larger attack surface on devices | Phase 0 |
| 9 | Docker image runs as root and includes build tools | Container escape impact is higher | Phase 6 |

---

## 6. Hardening checklist for deployments

Before enabling enforcement on a real network:

- [ ] Running the latest release; `pip-audit` clean.
- [ ] New signing key generated and provisioned; no keys in the repository.
- [ ] `DASHBOARD_API_KEY` set to a random value of 32+ characters (`openssl rand -hex 32`), stored in a mode-600 `EnvironmentFile`.
- [ ] API reachable only from a management VLAN or via a VPN — never from the internet or guest networks.
- [ ] Gateway, DNS servers, management workstations and the appliance's own addresses are whitelisted.
- [ ] Rollback guard installed and tested (`scripts/validate_rollback_guard.py`).
- [ ] Ran at least 7 days in `monitor` mode and reviewed false positives before enabling auto-block.
- [ ] Passive (mirror) placement first; inline only with a bypass in place.
- [ ] SSH key-only login on the Pi and Jetson; default users removed; automatic security updates on.
- [ ] Log rotation configured (`packaging/logrotate`); disk usage alerting via Prometheus.
- [ ] `SENTINEL_ALLOW_UNSIGNED_MODELS` is **not** set.

---

## 7. Secure development practices

* No `shell=True`; subprocess calls take validated argument lists.
* SQL uses parameters; identifiers are validated or quoted (`psycopg2.sql`).
* CI runs unit tests, Bandit, pip-audit and model-signature verification on every push; firewall changes are tested in a privileged container runner.
* Security-sensitive areas need two reviewers: `core/firewall.py`, `security/`, authentication code, installers, `packaging/`, and `.github/workflows/`.
* Secrets in workflows are read at runtime, never interpolated into scripts.
