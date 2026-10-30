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
| `main` / latest `1.2.x` | ✅ |
| `1.1.x` | ✅ until 1.3.0 |
| `1.0.x` and older | ❌ — upgrade to the latest |

The current and previous minor release receive security fixes.

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
| Unauthorised use of the API (block/unblock/policy) | Per-user accounts with Argon2id passwords, four roles enforced on every endpoint, session expiry | ✅ |
| | Rate limiting per client and account lockout on login | ✅ |
| | Two-step sign-in (TOTP authenticator apps) required for Operator and Admin, with single-use recovery codes | ✅ |
| | Scoped, expiring API tokens for automation | ✅ |
| Stolen session token | 15-minute access tokens held in memory; refresh token in an HttpOnly, SameSite=Strict cookie, rotated on every use; reuse of an old refresh token revokes the session | ✅ |
| Cross-site request forgery | Bearer tokens (not cookies) authorise API calls; the refresh/logout endpoints require a custom header; CORS limited to configured origins | ✅ |
| Eavesdropping on the console/API | HTTPS by default with a certificate created at install, or the organisation's own; HSTS; secure WebSocket | ✅ |
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
| | Separate runtime, dev and Streamlit requirement files; devices install runtime only | ✅ |
| | Dependabot, SBOM per release | 🔜 |
| Evidence tampering | Append-only firewall action log | 🟡 |
| | Tamper-evident (hash-chained) audit log for all user actions | 🔜 |

---

## 3. Security architecture

### Authentication and access
Console users sign in with a username and password (`core/auth.py`, `dashboard/auth_routes.py`).

* **Accounts** are stored in `data/auth.db` (`SENTINEL_AUTH_DB`; on devices `/var/lib/sentinel/data/auth.db`, mode `600`, owned by the service user). Passwords are hashed with **Argon2id**; the minimum length is 12 characters.
* **First install:** `sentinelctl` creates the user `admin` with a random one-time password in `/etc/sentinel/initial-admin-password` (root only, mode `600`). The console forces a password change at first sign-in; delete the file afterwards. Users can also be managed on the device with `python -m core.auth` (`create-user`, `reset-password`, `set-role`, `unlock`, `list`, `create-token`, `list-tokens`, `revoke-token`).
* **Sessions:** a login returns a 15-minute access token (`SENTINEL_ACCESS_TOKEN_TTL`) that the console keeps in memory only, and sets a refresh token in an `HttpOnly`, `SameSite=Strict` cookie scoped to `/api/auth` (lifetime `SENTINEL_SESSION_TTL`, default 12 h). The refresh token is rotated on every use; presenting an old one revokes the whole session. Access tokens are checked against the session and the user on every request, so sign-out, disabling a user or changing a role apply immediately. Changing a password signs out the user's other sessions.
* **API rate limits:** every `/api/*` request counts against a per-client sliding window: 600 reads and 60 writes per minute by default (`SENTINEL_RATE_LIMIT_READ`, `SENTINEL_RATE_LIMIT_WRITE`, `0` disables). Excess requests get `429` with `Retry-After`.
* **Brute force:** 10 login attempts per client per 5 minutes, and an account locks for 15 minutes after 5 wrong passwords. Error messages do not reveal whether a username exists.
* **Two-step sign-in (MFA):** users whose role is listed in `SENTINEL_MFA_ROLES` (default `operator,admin`) must enrol an authenticator app (TOTP, RFC 6238: 6 digits, 30-second steps, ±1 step for clock drift) before they can use the console; until then every endpoint except the setup ones returns 403. Each code works once (a code from the same or an earlier time step is refused). Enrolment issues 10 single-use recovery codes, stored as SHA-256 hashes and shown only once. A wrong code counts toward the account lockout like a wrong password. Secrets live in `auth.db` (mode `600`). Lost phone: an Admin uses **Reset MFA** in the Users panel or `python -m core.auth reset-mfa`, which also signs the user out everywhere.
* **WebSocket:** the live stream sends nothing until the client authenticates with its first message; unauthenticated sockets are closed with code `4401`.
* **API key:** `DASHBOARD_API_KEY` still works (`X-API-Key` or `Authorization: Bearer`) for automation and device health checks, with the role in `SENTINEL_API_KEY_ROLE` (default `admin`). It is compared in constant time. Prefer API tokens for new automation; the shared key remains for device health checks and will be retired.
* **API tokens:** admins create per-integration tokens (`sak1.<id>.<secret>`) in the Users panel or with `python -m core.auth create-token`. A token has a role no higher than its owner's (capped again at use, so demoting the owner demotes the token), a required expiry of 1–365 days, and stops working when revoked, expired, or when the owner is disabled or deleted. Only a SHA-256 hash of the secret is stored and the token is shown once. Tokens cannot manage tokens, so a leaked token cannot extend its own life. `last_used` is recorded so unused tokens can be found and revoked.
* **Development mode:** only when no user exists *and* no API key is set, requests from `127.0.0.1` / `::1` act as an Admin. Creating the first user ends this mode.
* **Security headers:** every response carries a strict Content-Security-Policy (`default-src 'self'`, no inline scripts or styles, `img-src 'self' data:` for the MFA QR code, `object-src 'none'`, `frame-ancestors 'none'`), plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy` and `Cross-Origin-Opener-Policy: same-origin`. `SENTINEL_CSP` replaces the policy if the console is hosted elsewhere.
* **HTTPS:** `sentinelctl` creates a self-signed EC P-256 certificate at install (subject alternative names: hostname, `<hostname>.local`, `localhost`, loopback and the device's addresses; 825 days) in `/etc/sentinel/tls/` (key mode `640`, root:sentinel) and turns HTTPS on in `sentinel.env`. Verify it the first time by comparing the fingerprint from `sentinelctl tls show` with what the browser shows, or replace it with a certificate from your own CA: `sudo sentinelctl tls import cert.pem key.pem`. The API refuses to start rather than falling back to HTTP if TLS is half configured. HTTPS responses carry `Strict-Transport-Security: max-age=31536000` (browsers ignore it while they do not trust the certificate, so a self-signed install cannot lock anyone out). The session cookie gets the `Secure` flag automatically over HTTPS.
* **CORS** is limited to `SENTINEL_CORS_ORIGINS` (default: the Vite dev server). The console is normally served by the API itself, so production needs no cross-origin access.
* The API binds to `127.0.0.1` by default (`SENTINEL_HOST`). Interactive API docs (`/docs`, `/redoc`) are disabled and `/openapi.json` requires sign-in.
* The health endpoint supports Basic auth via `HEALTH_USER` / `HEALTH_PASS`.

| Role | Can |
|---|---|
| **Viewer** | See dashboards, alerts, devices, firewall state and reports |
| **Analyst** | Viewer + investigate and explain alerts |
| **Operator** | Analyst + block, unblock, whitelist, expire and roll back; run demos |
| **Admin** | Operator + firewall policy and user management |

Still to come in v1.2: a hash-chained audit log of every sign-in and action, and a first-run setup wizard.

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

### Key moved to the release device (2026-10-30)
Development moved from a PC to the Raspberry Pi, and the only copy of the signing key was on the PC. The key was rotated again from the Pi: the model was first confirmed byte-identical (SHA-256 `6ce839cb…a5a8`) to the one the v1.2.0 release pipeline verified with the previous key, then re-signed with a new 256-bit key generated on the Pi (`~/.sentinel/model_signing.key`, mode `600`). The GitHub secret was updated to match. The PC key no longer verifies the committed model. Releases from v1.2.1 onwards need this key on the device.

The old key no longer verifies any committed model, so a model signed with it will be rejected by updated devices and CI.

---

## 5. Known security issues (v1.2)

| # | Issue | Impact | Tracked in |
|---|---|---|---|
| 1 | ~~Firewall commands rejected by the subprocess wrapper; nftables set never attached to a chain~~ | **Fixed in 1.1.0** — blocks had no effect | — |
| 2 | ~~iptables removal omitted the comment match used at insert~~ | **Fixed in 1.1.0** | — |
| 3 | Bridge-level (layer 2) filtering and MAC quarantine not implemented; `INPUT` and `FORWARD` are covered | Devices on the same bridge segment are not isolated | Phase 3 |
| 4 | ~~Single shared API key, no per-user identity~~ | **Fixed in 1.2.0** — user accounts and roles; the shared key remains for automation until scoped tokens land | Phase 1 |
| 5 | ~~No TLS on API/WebSocket~~ | **Fixed** — HTTPS and WSS by default; self-signed until an organisation certificate is imported | — |
| 6 | ~~No rate limiting on the API~~ | **Fixed** — 600 reads and 60 writes per minute per client on `/api/*` (`SENTINEL_RATE_LIMIT_READ` / `_WRITE`); limits are per address, so clients behind one proxy share them | — |
| 10 | ~~Live WebSocket stream had no authentication~~ | **Fixed in 1.2.0** — anyone who could reach the port could read alerts and flows | — |
| 7 | HMAC model signing — every verifier holds the signing key | A compromised device can sign models | Phase 4 |
| 8 | ~~Dev tools (pytest, bandit, pip-audit, streamlit) in runtime requirements~~ | **Fixed** — split into `requirements-dev.txt` / `requirements-streamlit.txt` | — |
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
