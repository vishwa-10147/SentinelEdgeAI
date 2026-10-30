# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixed
- The engine never started as a service: `main.py` imported a metric (`PROCESS_UP`) that did not exist.
- Every packet failed analysis with `NameError: final_risk`; live statistics are now updated where each flow is scored.
- `sentinelctl install` left the release's Python environment unreadable to the `sentinel` service user (a leaked `umask 027`), so neither service could start.
- `sentinelctl`'s health check accepted a crash-looping service; services must now stay up with no automatic restarts for `SENTINEL_HEALTH_SETTLE` seconds (default 15).

### Upgrade notes
- **The console moves to HTTPS.** Installing or upgrading creates a self-signed certificate for the device (its hostname, `.local` name and current addresses) and turns on HTTPS, so the console is now at `https://<pi-address>:9000`. The browser warns once about the self-signed certificate; compare the SHA-256 fingerprint from `sentinelctl tls show` before accepting it, or install your organisation's certificate with `sudo sentinelctl tls import cert.pem key.pem`. To keep plain HTTP (for example behind a reverse proxy that terminates TLS), set `SENTINEL_TLS_CERT=` and `SENTINEL_TLS_KEY=` to empty values in `/etc/sentinel/sentinel.env`.
- Scripts that call the API on the device must use `https://`. The firewall rollback guard follows the setting automatically.

### Added
- **Two-node architecture (Phase 2).** New `sensor` and `brain` roles: sensors enrol with a one-time code and the brain's CA fingerprint, then send every scored flow over mutual TLS (port 9443) and execute the brain's Ed25519-signed, sequenced, expiring commands. A disk buffer keeps flows through brain outages and replays them when it is back. CLIs: `python -m brain init | code | sensors | revoke | command`, `python -m sensor enroll | run | status`. Console API: `/api/brain/sensors`, `/api/brain/codes`, `/api/brain/sensors/{id}/revoke`, `/api/brain/sensors/{id}/commands`, `/api/brain/commands`, `/api/brain/flows`, `/api/sensor/status`, `/api/sensor/enroll`. Jetson installer `deploy/jetson/install_brain.sh` (untested on hardware).
- **Phase 1 exit checks.** `tests/test_endpoint_roles.py` gives every endpoint a role test and fails when a new route has none. `scripts/zap_baseline.sh` runs an OWASP ZAP baseline scan against a running console; the installed build scans clean (0 FAIL, 0 WARN).
- `Cross-Origin-Embedder-Policy: require-corp`, `Cross-Origin-Resource-Policy: same-origin`, and `Cache-Control: no-cache, no-store, must-revalidate` on API responses and the console page (fingerprinted `/assets/*` are cached for a year).
- **First-run setup wizard.** After the first admin signs in (and sets up two-step sign-in), the console walks them through the device's network role (Standalone now; Sensor and Brain arrive with v1.3), placement (passive mirror port or inline bridge), the capture interface (physical interfaces only, with state, speed and addresses) and the response mode (applied to the firewall policy). Admins can reopen it from **Setup**. Settings are stored in `data/setup.json` (`SENTINEL_SETUP_FILE`) and recorded in the audit log. The engine captures on the chosen interface and restarts itself when it changes; `CAPTURE_IFACE` still overrides it. API: `GET/POST /api/setup` (Admin).
- **Hash-chained audit log** (`data/audit.db`) of sign-ins (including failures, lockouts and throttling), sign-outs, password and MFA changes, user and API-token management, every firewall action (block, unblock, policy, whitelist, expire, rollback), demos, and the engine's automatic blocks. Each entry records who, from where, with which role, what, the outcome and details, and the SHA-256 of the previous entry, so an edited, deleted or reordered entry is detected. Admins see it in the new **Audit log** panel with an integrity check, or via `GET /api/audit` and `GET /api/audit/verify`; on the device, `python -m core.audit verify | tail`. Entries are also written to the system journal with their hash.
- **HTTPS by default.** `sentinelctl` creates an EC P-256 certificate at install (valid 825 days); `sentinelctl tls show | renew | import` inspect, replace or import a certificate (import checks that the key matches and the certificate has not expired). The API is started by the new `python -m dashboard.serve`, which serves HTTPS when `SENTINEL_TLS_CERT` / `SENTINEL_TLS_KEY` are set and refuses to start if only one is set or a file is missing. The live stream uses secure WebSockets (`wss://`) automatically, and HTTPS responses carry `Strict-Transport-Security` (`SENTINEL_HSTS_MAX_AGE`, default one year).
- **Security headers** on every API and console response: a strict Content-Security-Policy (same-origin scripts, styles and connections only, no inline code, `frame-ancestors 'none'`), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Permissions-Policy` and `Cross-Origin-Opener-Policy`. Override the CSP with `SENTINEL_CSP` when the console is hosted on another origin.
- **Scoped, expiring API tokens** for scripts and integrations (`sak1.…`, sent as `Authorization: Bearer` or `X-API-Key`). Each token has a role that cannot exceed its owner's, an expiry of 1–365 days (default 90), and stops working when revoked, expired, or when its owner is disabled, demoted or deleted. Only a SHA-256 hash is stored; the token is shown once. Admins manage them in the **Users** panel, through `GET/POST /api/tokens` and `DELETE /api/tokens/{id}`, or with `python -m core.auth create-token | list-tokens | revoke-token`. Tokens cannot create or revoke tokens.
- **API rate limits** per client address: 600 reads and 60 writes (`POST`, `PUT`, `PATCH`, `DELETE`) per minute on `/api/*`, answered with `429` and `Retry-After`. Tune with `SENTINEL_RATE_LIMIT_READ` / `SENTINEL_RATE_LIMIT_WRITE` (`0` turns a limit off). The stricter login throttle still applies.

## [1.2.0] - 2026-10-30

First Phase 1 release: the console now has its own user accounts, roles and two-step sign-in, and the firewall can block IPv6 addresses. Single-node ("Lite") deployment on a Raspberry Pi.

### Upgrade notes
- Upgrade with `sudo sentinelctl upgrade sentineledgeai-pi-1.2.0.tar.gz`. When no console users exist, the upgrade creates `admin` with a one-time password in `/etc/sentinel/initial-admin-password` (root only).
- The console now **requires sign-in**. At first sign-in, `admin` must choose a new password and set up an authenticator app. Delete the one-time password file afterwards.
- `DASHBOARD_API_KEY` keeps working for scripts and health checks, with the `admin` role by default (`SENTINEL_API_KEY_ROLE`).
- Clients of the live WebSocket (`/ws/packets`) must now send `{"type": "auth", "token": "<access token or API key>"}` as their first message.
- HTTPS is not included yet: keep the console on a trusted management network.

### Added
- **User accounts and roles.** The console now has a sign-in screen. Accounts use Argon2id password hashes and one of four roles, enforced on every API endpoint:
  - **Viewer:** dashboards, alerts, devices, firewall state, reports.
  - **Analyst:** Viewer, plus alert explanations.
  - **Operator:** Analyst, plus block, unblock, whitelist, expire, rollback and demos.
  - **Admin:** Operator, plus firewall policy and user management.
- Sessions use a 15-minute access token held in memory and a 12-hour refresh token in an HttpOnly, SameSite=Strict cookie that is rotated on every use. Replaying an old refresh token revokes the session.
- Sign-out, disabling a user and role changes take effect immediately.
- Login is throttled per client, accounts lock for 15 minutes after 5 wrong passwords, and errors do not reveal whether a username exists.
- Admins manage users in a new **Users** panel. Every user can change their own password, and new or reset accounts must choose a new password at first sign-in.
- `python -m core.auth` manages users on the device: `create-user`, `reset-password`, `set-role`, `unlock`, `list`.
- `sentinelctl install`/`upgrade` creates the first `admin` user with a one-time password in `/etc/sentinel/initial-admin-password` when no users exist.
- **Two-step sign-in (MFA).** Operators and Admins must set up an authenticator app (Google Authenticator, Microsoft Authenticator, 1Password, Aegis and other TOTP apps) at their next sign-in, by scanning a QR code or typing the key. They then enter a 6-digit code after their password. Each code works once, and wrong codes count toward the account lockout. Which roles need it is set by `SENTINEL_MFA_ROLES` (default `operator,admin`).
- 10 single-use recovery codes are shown once at setup, with Copy and Download.
- Admins can reset a user's two-step sign-in from the **Users** panel, which now shows each user's status. On the device: `python -m core.auth reset-mfa --username <name>`.
- Existing account databases are upgraded in place.
- **IPv6 blocking.** IPv6 addresses can be blocked, unblocked, whitelisted and rolled back like IPv4. nftables uses a new `blacklist6` set with `ip6` rules in the `input` and `forward` chains; the iptables backend uses `ip6tables`. Devices upgraded from v1.1.0 get the IPv6 rules added to their existing chains without duplicating the IPv4 ones.
- `::1` is whitelisted by default, and IPv4-mapped addresses (`::ffff:a.b.c.d`) are treated as the IPv4 address they carry.

### Changed
- The project is now licensed under the **Apache License 2.0** (`LICENSE`, `NOTICE`). Previously no licence had been chosen.

### Security
- The live WebSocket stream (`/ws/packets`) and `/api/live_stats` previously had **no authentication**. Both now require sign-in; the WebSocket authenticates with its first message.
- CORS was open to every origin (`*`). It is now limited to `SENTINEL_CORS_ORIGINS`.
- `DASHBOARD_API_KEY` is compared in constant time, and its role is configurable with `SENTINEL_API_KEY_ROLE` (default `admin`).

### Fixed
- The built console called `http://localhost:9000` instead of the device it was loaded from, so it only worked in a browser running on the device itself. It now uses its own origin.

## [1.1.0] - 2026-10-30

First release built by the automated release pipeline. Single-node ("Lite") deployment on a Raspberry Pi.

### Added
- **Release pipeline:** pushing a `vX.Y.Z` tag runs the tests, the model-signature check and a dependency audit, then publishes the Pi package with an offline Python wheelhouse, SHA-256 checksum, CycloneDX SBOM and GitHub build-provenance attestation.
- **`sentinelctl`** device tool: `install`, `upgrade`, `rollback`, `status`, `versions`. Versioned releases under `/opt/sentineledgeai/releases`, atomic switch, health check after every upgrade with automatic rollback, and the last three releases kept.
- **Hardened systemd units:** `sentineledgeai-engine`, `sentineledgeai-api` and the `sentineledgeai-rollback-guard` timer run as an unprivileged `sentinel` user with only `CAP_NET_RAW`/`CAP_NET_ADMIN`, a read-only system and writable state and log directories only.
- **Secure first-run config:** `/etc/sentinel/sentinel.env` is created with a random `DASHBOARD_API_KEY`, dry-run enforcement and the rollback guard off.
- **Documentation:** new README, SECURITY.md (threat model, controls, disclosure policy), PLAN.md (roadmap to v2.0) and EXPLAIN.md (how it works).
- Separate requirement sets: `requirements.txt` (runtime), `requirements-dev.txt`, `requirements-streamlit.txt`.

### Fixed
- **Firewall enforcement never blocked anything:** commands were refused by the subprocess wrapper; the nftables blacklist set was never attached to a chain; iptables unblock did not match the inserted rule. Blocks now cover `INPUT` and `FORWARD`, never create duplicates, and rollback removes every SentinelEdgeAI rule.
- SQLite now creates its data directory on first use (fresh installs and CI failed with `unable to open database file`).
- The Pi package no longer copies untracked files (signing keys, `.env`, databases) from the build machine, and now includes the built web console.
- Upgrading with the old package installer no longer deletes the device's database, firewall state and keys.

### Security
- The model signing key, which had been committed, was **rotated**: the model was re-signed and the CI secret replaced. Devices must receive the new key before upgrading (see SECURITY.md §4).
- Secrets, runtime data and compiled files are no longer tracked in git.
- Development tools (pytest, bandit, pip-audit, Streamlit) are no longer installed on devices.
- `uvicorn` upgraded from 0.23 to 0.54.
- `starlette` upgraded from 1.0.1 to 1.3.1 to fix PYSEC-2026-248, PYSEC-2026-249, PYSEC-2026-2280 and PYSEC-2026-2281 (caught by the release pipeline's dependency audit).

### Changed
- Version numbering continues from `v1.0.0`; the roadmap now runs v1.2 → v2.0 (production).
- Superseded documents moved to `docs/archive/`; empty stub modules removed.

### Known limitations
- Single shared API key and no HTTPS yet (planned for v1.2). Keep the API on a trusted management network.
- The Jetson Orin Nano is not used yet (two-node architecture is planned for v1.3).
- IPv6 addresses cannot be blocked yet.

## [1.0.0] - 2026-02-15
- First prototype release: capture, flow features, Z-score/Isolation Forest/behavioural detection, risk scoring, MITRE mapping, FastAPI backend, React and Streamlit dashboards.
