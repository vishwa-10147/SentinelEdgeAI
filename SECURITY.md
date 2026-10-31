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
| `main` / latest `2.9.x` | ✅ |
| `2.8.x` | ✅ until 2.10.0 |
| `2.7.x` and older | ❌ — upgrade with `sudo sentinelctl update` |

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
| Network attacker between sensor and brain, or between sites and the fleet server | Forge flow data or forge "block" commands |

### Key threats and mitigations

| Threat | Mitigation | Status |
|---|---|---|
| Unauthorised use of the API (block, unblock, policy) | Per-user accounts with Argon2id passwords, four roles enforced and tested on every endpoint, session expiry | ✅ |
| | Login throttling and account lockout; API rate limits per client | ✅ |
| | Two-step sign-in (TOTP) required for Operator and Admin, with single-use recovery codes | ✅ |
| | Scoped, expiring API tokens for automation | ✅ |
| Stolen session token | 15-minute access tokens held in memory; rotating refresh token in an HttpOnly, SameSite=Strict cookie; reuse revokes the session | ✅ |
| Cross-site request forgery | Bearer tokens authorise API calls; refresh/logout need a custom header; CORS limited to configured origins | ✅ |
| Eavesdropping on the console/API | HTTPS by default (certificate created at install, or the organisation's own), HSTS, secure WebSocket | ✅ |
| The appliance blocks critical hosts (self-DoS) | Gateway, DNS, DHCP, the appliance and management hosts are found automatically and can never be blocked, quarantined, contained or segmented | ✅ |
| Bad rules lock the network | Dry run by default, TTLs, Operator approval above a risk threshold, rollback in ~100 ms, fail-open watchdog, systemd rollback guard | ✅ |
| Command injection through firewall calls | IP/TTL validation, argument lists only (no shell), allowlisted binaries | ✅ |
| Tampered ML model | Registry models (autoencoder, federated models) are Ed25519-signed and hash-pinned; the release Isolation Forest is HMAC-signed and checked in CI; changed models are refused | ✅ |
| | Asymmetric signature for the release Isolation Forest too, so devices hold only a public key | 🔜 |
| Forged sensor data or commands | Mutual TLS with per-device certificates from a private CA pinned by fingerprint; Ed25519-signed, sequenced, expiring commands | ✅ |
| Forged fleet or brain peers | Separate CAs for brain and fleet; enrolment codes are one-time and expire; revocation is immediate | ✅ |
| **Flood / resource exhaustion (blinding the sensor)** | Flow table capped (`SENTINEL_MAX_FLOWS`, default 100,000), least-recently-active flows evicted; per-source detector state capped (`SENTINEL_MAX_SOURCES`, default 20,000); device and peer tables capped; scoring sheds load instead of queueing without limit; one "capture overloaded" alert with metrics; engine yields CPU and is the first OOM victim. Verified: 3 minutes at ~320,000 spoofed packets/s stays at ~460 MB (was 1.2 GB after 40 s) | ✅ |
| | Memory caps per service (`MemoryMax=`) where the memory cgroup is enabled | 🟡 off on stock Raspberry Pi OS |
| Poisoning what the appliance learns | Flows with findings never train models; federated updates are validated and clipped; OT segmentation uses a frozen snapshot; learning periods are visible | 🟡 an attacker present before installation can hide in the baseline |
| Evasion (slow scans, low-and-slow exfiltration) | Long windows, seasonal baselines, beaconing and exfiltration detectors | 🟡 inherent to network detection |
| Prompt injection / "talking the AI into" an action | Not applicable: no language model; explanations are templates; every action goes through the playbook, policy bounds and approval gate | ✅ |
| Supply chain | Reproducible packages, Sigstore/cosign signatures, CycloneDX SBOM, build provenance; OTA updates verify checksum and signature and roll back on a failed health check | ✅ |
| Vulnerable dependencies | `pip-audit` and Bandit on every push and before every release; pinned versions; runtime-only requirements on devices | ✅ |
| Evidence tampering | Hash-chained audit log of every user, engine and fleet action, with a copy in the system journal | ✅ |
| Leaking sensitive data in screenshots/demos | `REDACT_SENSITIVE=1` hashes IPs and MACs in API output | ✅ |

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
* **Audit log:** a hash-chained log in `data/audit.db` (mode `600`, `SENTINEL_AUDIT_DB`) records sign-ins (success, failure, lockout, throttled), sign-outs, password and MFA changes, user and API-token management, every firewall action through the API, demos, and the engine's automatic blocks, with actor, kind, role, client address, target, outcome and details. Each entry includes the SHA-256 of the previous one; `python -m core.audit verify`, `GET /api/audit/verify` and the console's **Audit log** panel report the first entry that was modified, deleted or reordered. Someone with write access to the file could rebuild the whole chain, so every entry and its hash are also written to the `sentinel.audit` logger (the systemd journal on a device); compare the current head hash with the journal, or ship the journal off the device, to detect that. Secrets such as passwords and API tokens are never written to it. A failure to write an audit entry is logged but never blocks a response action.
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

All Phase 1 features are in place; the remaining Phase 1 work is the exit checks (a role test for every endpoint, an OWASP ZAP baseline scan).

### Firewall safety model
1. **Dry-run by default** (`FIREWALL_DRY_RUN=1`). Real enforcement must be turned on explicitly with `deploy/pi/enforcement_ctl.sh enable`.
2. **Response mode `monitor`** by default — detections alert but do not auto-block until policy allows it.
3. **Every block has a TTL** (default 300 s, max 24 h) unless an operator makes it permanent.
4. **Whitelist** checked before any block.
5. **Rollback**: one API call (`/api/firewall/rollback`) or the rollback script removes every SentinelEdgeAI rule. A systemd timer (`sentinel-firewall-rollback-guard`) rolls back automatically if the service is unhealthy.
6. **Fail-open**: if the engine or API stops while rules are in force, the watchdog removes every rule within about a minute, and any rollback also turns OT segmentation off. In inline mode a hardware bypass should pass traffic if the device loses power.

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

## 5. Known security issues (v2.9)

| # | Issue | Impact | Status |
|---|---|---|---|
| 1 | No external penetration test yet | Unknown issues may remain | Scope in docs/PENTEST_SCOPE.md; planned before the beta |
| 2 | Raspberry Pi OS boots with `cgroup_disable=memory` | `MemoryMax=` limits are not enforced; the in-process caps still apply | Enable with `cgroup_enable=memory` in `/boot/firmware/cmdline.txt` |
| 3 | Updates verify the cosign signature only when cosign is installed | Without it, only the SHA-256 is checked | `apt install cosign`, or `SENTINEL_REQUIRE_SIGNATURE=1` to refuse unsigned updates |
| 4 | A shared API key may still exist for health checks | One secret with a fixed role | Replace with a scoped API token, then remove `DASHBOARD_API_KEY` |
| 5 | Bridged (inline) traffic has no conntrack on stock kernels | Containment stops only new TCP connections and off-profile UDP on the bridge | Documented; routed traffic uses conntrack |
| 6 | Containment and OT segmentation are IPv4 only | IPv6 hosts can only be quarantined or blocked | Planned |
| 9 | The release Isolation Forest is HMAC-signed, so every device holds a key that could also sign it | A compromised device could sign a model for itself | Planned: move it to the Ed25519 registry |
| 7 | ~~Flow table and per-source state unbounded; per-flow coroutines piled up under load~~ | **Fixed in 2.9.2**: a spoofed flood could exhaust memory | — |
| 8 | ~~`health.json` and `live_stats.json` written non-atomically~~ | **Fixed in 2.9.2/2.9.3**: readers could see half-written files and the live statistics reset | — |

Earlier issues (firewall commands, single API key, TLS, WebSocket authentication, rate limits, development tools on devices, the root container) are fixed; see CHANGELOG.md.

---

## 6. Hardening checklist for deployments

Before enabling enforcement on a real network:

- [ ] Running the latest release (`sudo sentinelctl update`); cosign installed so updates verify signatures.
- [ ] Model signing key provisioned on the device; no keys in the repository.
- [ ] Every Operator and Admin has two-step sign-in; the shared API key replaced by a scoped token.
- [ ] Console reachable only from a management VLAN or a VPN, never from the internet or guest networks.
- [ ] Management workstations and OT engineering stations listed in `management_hosts` (check `python -m enforcement protected`).
- [ ] At least 7 days in `monitor` mode, false positives labelled, before automatic response; response tuning left in `recommend` until its evidence looks right.
- [ ] Passive (mirror) placement first; inline only with a hardware bypass.
- [ ] Memory cgroup enabled (`cgroup_enable=memory`) so service memory limits apply.
- [ ] SSH key-only login (`deploy/pi/harden_os.sh`); unattended security upgrades on.
- [ ] Encrypted backups scheduled (`sentinelctl backup`); the compliance report shows the last one.
- [ ] Alerts exported to a SIEM or notification channel.
- [ ] `SENTINEL_ALLOW_UNSIGNED_MODELS` is **not** set.

---

## 7. Secure development practices

* No `shell=True`; subprocess calls take validated argument lists.
* SQL uses parameters; identifiers are validated or quoted (`psycopg2.sql`).
* CI runs unit tests, Bandit, pip-audit and model-signature verification on every push and before every release.
* Real-kernel tests in network namespaces cover enforcement, OT segmentation, containment and flood safety (`tests/firewall_netns/`).
* Security-sensitive areas need two reviewers: `core/firewall.py`, `security/`, authentication code, installers, `packaging/`, and `.github/workflows/`.
* Secrets in workflows are read at runtime, never interpolated into scripts.
