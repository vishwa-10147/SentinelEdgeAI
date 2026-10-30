# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

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

### Changed
- Version numbering continues from `v1.0.0`; the roadmap now runs v1.2 → v2.0 (production).
- Superseded documents moved to `docs/archive/`; empty stub modules removed.

### Known limitations
- Single shared API key and no HTTPS yet (planned for v1.2). Keep the API on a trusted management network.
- The Jetson Orin Nano is not used yet (two-node architecture is planned for v1.3).
- IPv6 addresses cannot be blocked yet.

## [1.0.0] - 2026-02-15
- First prototype release: capture, flow features, Z-score/Isolation Forest/behavioural detection, risk scoring, MITRE mapping, FastAPI backend, React and Streamlit dashboards.
