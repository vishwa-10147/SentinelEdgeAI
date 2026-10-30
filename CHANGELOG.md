# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added
- **User accounts and roles (Phase 1).** The console now has a sign-in screen. Accounts use Argon2id password hashes and one of four roles, enforced on every API endpoint:
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
