<div align="center">

# SentinelEdgeAI

**Offline network detection and response with an adaptive firewall, for networks that have no security team.**

[![Release](https://img.shields.io/github/v/release/vishwa-10147/SentinelEdgeAI?label=release)](https://github.com/vishwa-10147/SentinelEdgeAI/releases/latest)
[![CI](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/ci.yml)
[![Security Scans](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/security-scans.yml/badge.svg?branch=main)](https://github.com/vishwa-10147/SentinelEdgeAI/actions/workflows/security-scans.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)
![Python](https://img.shields.io/badge/python-3.11%20%7C%203.13-3776AB)
![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%205%20%7C%20Jetson%20Orin%20Nano%20%7C%20Docker-555)
[![Docs](https://img.shields.io/badge/docs-vishwa--10147.github.io-0a7bbb)](https://vishwa-10147.github.io/SentinelEdgeAI/)

[Overview](#overview) ·
[Quick start](#quick-start) ·
[Capabilities](#capabilities) ·
[Architecture](#architecture) ·
[Security model](#security-model) ·
[Status](#status-and-roadmap) ·
[Documentation](#documentation) ·
[Development](#development) ·
[Contributing](#contributing)

</div>

---

## Overview

SentinelEdgeAI is a network appliance for a Raspberry Pi 5 (optionally with an NVIDIA Jetson Orin Nano). It
learns how every device on a network normally behaves, detects attacks and compromised devices in real time,
explains every alert in plain language, and responds within bounds you set, from an alert up to containing,
blocking or quarantining a device. Everything runs on site: no cloud account is needed and no traffic data
leaves the network.

It is built for the organisations that face the same attacks as large enterprises without a security
operations centre: small and medium businesses, factories and OT sites, clinics, schools and guest Wi-Fi,
branch networks, and the managed service providers who look after them.

| | |
|---|---|
| **Current release** | [`v2.18.0`](https://github.com/vishwa-10147/SentinelEdgeAI/releases/tag/v2.18.0) · [all releases](https://github.com/vishwa-10147/SentinelEdgeAI/releases) · [changelog](CHANGELOG.md) |
| **Hardware** | Raspberry Pi 5 (sensor, or everything on one device) · Jetson Orin Nano (optional brain) · any Linux host for the hosted fleet console · about USD 350 for the two-node kit |
| **Supply chain** | Reproducible packages, Sigstore/cosign signatures, SHA-256 checksums, build-provenance attestation, CycloneDX SBOM and VEX per release, Ed25519-signed model and update channels |
| **Quality** | 1,000+ automated tests, real-kernel network-namespace tests for enforcement, live integration tests against Keycloak, Elasticsearch and TheHive, Bandit and pip-audit in CI |
| **Licence** | Apache-2.0 |

> **Status:** every software phase of the [roadmap](PLAN.md) is built. What remains is field proof (an external
> penetration test, a 30-day beta, a 72-hour inline soak, Jetson hardware validation); see
> [Status and roadmap](#status-and-roadmap). Do not rely on it as your only protection before then.

---

## Quick start

### Raspberry Pi appliance

Raspberry Pi 5 or 4, 64-bit Raspberry Pi OS Bookworm (Python 3.11) or Trixie (Python 3.13). The package bundles
every dependency, so the Pi needs no internet access.

```bash
# 1. Download the package and its checksum from the latest release, then verify both
sha256sum -c sentineledgeai-pi-2.18.0.tar.gz.sha256
gh attestation verify sentineledgeai-pi-2.18.0.tar.gz --repo vishwa-10147/SentinelEdgeAI   # optional: build provenance

# 2. Install (versioned, health-checked, rolls back automatically on failure)
tar -xzf sentineledgeai-pi-2.18.0.tar.gz
sudo bash sentineledgeai-pi-2.18.0/packaging/sentinelctl install sentineledgeai-pi-2.18.0.tar.gz
```

Open `https://<pi-address>:9000`. The certificate is self-signed: compare its fingerprint with
`sentinelctl tls show`, or install your own with `sudo sentinelctl tls import cert.pem key.pem`. Sign in as
`admin` with the one-time password from `sudo cat /etc/sentinel/initial-admin-password`, choose a new password,
enrol an authenticator app, then follow the setup wizard (placement, capture interface, response mode).

The appliance starts in **dry run**: it records what it would do without blocking anything. When the alerts look
right, set `FIREWALL_DRY_RUN=0` and `ENABLE_ROLLBACK_GUARD=1` in `/etc/sentinel/sentinel.env` and restart the
services (read [SECURITY.md §6](SECURITY.md) first).

```bash
sudo sentinelctl update --check && sudo sentinelctl update   # signed stable channel, verified, auto-rollback
sudo sentinelctl rollback                                     # previous version
sudo sentinelctl backup /root/sentinel.seab                   # encrypted backup of configuration and data
```

### Other ways to run it

| Target | How |
|---|---|
| One-command install with a preset | `sudo bash scripts/install.sh --preset office` ([admin guide](docs/ADMIN_GUIDE.md)) |
| Sensor + Jetson brain | [deploy/jetson/README.md](deploy/jetson/README.md) |
| Hosted fleet console (any Linux host / cloud VM) | [deploy/fleet-hosted/README.md](deploy/fleet-hosted/README.md) |
| API and console in Docker (evaluation, dry run) | `docker compose up -d --build` |
| Development machine | [Development](#development) |

---

## Capabilities

### Detection

| Area | What it does |
|---|---|
| **Capture** | AF_PACKET fast path (~121k packets/s on a Pi 5), flow assembly, bounded memory and a capture-overload alert under floods; Zeek or Suricata can front busy links |
| **Behaviour** | Per-device, per-protocol and hour-of-day baselines; Isolation Forest and autoencoder (signed, shadow → canary → active); port scan, host sweep, brute force, beaconing, **jittered encrypted check-ins** (session rhythm), exfiltration, new devices |
| **DNS and encrypted traffic** | DNS tunnelling and DGA; JA3/JA4/JA4S, SNI, ALPN, certificate anomalies; **JA4H** for plain HTTP, PowerShell/certutil download cradles, cleartext credentials. No decryption |
| **Windows and Active Directory** | SMB, DCE-RPC, Kerberos and **LDAP** metadata: admin shares, PsExec-style service control, remote tasks, DCSync, pass-the-hash fan-out, Kerberoasting / AS-REP roasting, BloodHound-style enumeration |
| **Industrial (OT)** | Modbus/TCP, DNP3, BACnet/IP, OPC UA, IEC 60870-5-104, S7comm, EtherNet/IP, MQTT; per-controller learning of masters and functions; restart/stop commands; unit-id sweeps |
| **Assets** | MAC identity, vendor and DHCP fingerprint, **passive OS and device-type fingerprinting**, criticality, offline CVE matching |
| **Intelligence** | STIX 2.1 / TAXII 2.1 / list feeds; **community sharing** between your sites and between fleets (signed, anonymised, opt-in) |
| **Fusion** | Calibrated confidence, multi-signal confirmation, MITRE ATT&CK (and ATT&CK for ICS) on every finding, an explanation on every alert, analyst feedback that recalibrates detectors |
| **Extensions** | Third-party detectors and response hooks, Ed25519-signed and sandboxed ([docs/EXTENSIONS.md](docs/EXTENSIONS.md)) |

### Response

| Area | What it does |
|---|---|
| **Actions** | Block and unblock (IPv4 and IPv6), rate limit, **contain** (keep only a device's normal peers), quarantine with a notice page, **quarantine VLAN** on managed switches (Arista eAPI, Cisco RESTCONF, webhook) |
| **Playbook** | Graduated: alert → rate limit → contain → block → quarantine; Operator approval above a risk threshold; **response tuning** learns the least disruptive response that works, never beyond the playbook |
| **Segmentation** | Zero-trust peer profiles and trust scores (0–100, with reasons); OT micro-segmentation from learned allow-lists |
| **Safety** | Protected hosts (gateway, DNS, DHCP, the appliance, management hosts) are never restricted; dry run by default; every restriction expires; full rollback in ~100 ms; a watchdog fails open; response policy as code with a checked diff |
| **Placement** | Passive (mirror port) or inline (bridge or routed), with a fail-open watchdog and optional hardware bypass |

### Operations

| Area | What it does |
|---|---|
| **Console** | React console: topology, devices, incidents with a timeline and "what to do now", approvals, restrictions, policy, trust, OT, models and evaluation, fleet, compliance, users, audit |
| **Incidents and assistant** | Alerts grouped into incidents; an optional **local** assistant (Ollama / llama.cpp, off by default) that explains incidents and can never act |
| **Accounts** | Argon2id passwords, four roles, TOTP two-step sign-in, scoped API tokens, lockout; **single sign-on** with OpenID Connect and **SAML 2.0**; **LDAP / Active Directory** sign-in |
| **Notifications** | Approval requests by e-mail, Slack, Teams, webhook or **Web Push** to the phone; daily or weekly digests |
| **Integrations** | Syslog RFC 5424 and CEF (UDP/TCP/TLS), signed webhooks, JSON lines for Filebeat ([tested config](deploy/elastic/filebeat.yml)); Jira, ServiceNow and TheHive tickets both ways; Suricata and Zeek input |
| **Two-node and HA** | Pi sensor + brain over mutual TLS with signed, sequenced, expiring commands and an offline disk buffer; active/standby brains on PostgreSQL with sensor failover |
| **Fleet** | Many sites in one console: templates, staged rollouts that pause on failure, remote actions, fleet-wide alert search, federated learning; **multi-tenant for MSPs** (customers, scoped roles, branding, usage reports); self-hosted or as a [hosted console](deploy/fleet-hosted/README.md) |
| **Compliance and reporting** | Live evidence packs for ISO/IEC 27001, IEC 62443-3-3 and NIS2 (JSON and PDF); daily/weekly PDF reports; Prometheus metrics, Grafana dashboard, alert rules |
| **Lifecycle** | `sentinelctl` install / upgrade / rollback / backup / restore; signed **stable** and **beta** update channels; hardened systemd units; encrypted backups |

---

## Architecture

```text
                         ┌──────────────────────────────────────────────┐
   Admin / Analyst  ───► │  BRAIN  (Jetson Orin Nano, or the Pi itself) │
   (browser, HTTPS)      │  Console · REST API (176 endpoints) · stream │
                         │  Accounts, roles, MFA, SSO, audit log        │
                         │  Detection fusion · playbook · policy        │
                         │  Database · model registry · integrations    │
                         └───────────────▲───────────────┬──────────────┘
                     flow features,      │  mutual TLS   │  signed, sequenced,
                     sensor health       │               │  expiring commands
                         ┌───────────────┴───────────────▼──────────────┐
   Network traffic  ───► │  SENSOR  (Raspberry Pi 5)                    │
   (mirror port or       │  Capture → flows → features → detectors      │
    inline bridge)       │  Enforcement (nftables) · watchdog · buffer  │
                         └──────────────────────────────────────────────┘
          many sites ──► optional fleet server (self-hosted or hosted, multi-tenant)
```

| Profile | Hardware | For |
|---|---|---|
| **Lite** | 1 × Raspberry Pi 5 | Small offices, home labs, evaluation (most installs) |
| **Standard** | Pi 5 + Jetson Orin Nano | SMBs, clinics, OT cells |
| **Multi-sensor / HA** | N × Pi 5 + 1–2 brains (+ PostgreSQL) | Several segments; sites that cannot lose their brain |
| **Fleet** | Many sites + a fleet server | MSPs, branch networks |

More detail: [EXPLAIN.md](EXPLAIN.md) (how it works, in plain language) and [PLAN.md](PLAN.md#2-architecture).

---

## Security model

- **Local by default.** No telemetry, no vendor cloud. The assistant's model server must be on the appliance
  or the private network, and community sharing is opt-in and sends only anonymised internet indicators.
- **Bounded automation.** Models never act on their own: every response passes the playbook, your policy and
  the protected-host list, expires, and above a risk threshold waits for an Operator.
- **Untrusted input stays data.** Text from the network is cleaned and fenced; text that addresses the
  assistant is removed before any model sees it. Extensions run in a sandbox and their findings are capped.
- **Signed everything.** Packages (Sigstore), the release model and update channels (Ed25519, key pinned on
  each device at first install), commands between brain and sensors, extension packages, shared intel.
- **Hardened management plane.** HTTPS, strict security headers, rate limits, MFA for Operators and Admins,
  a hash-chained audit log, and a role check on every endpoint enforced by a test.

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md).

---

## Status and roadmap

```text
Phase 0   Correctness, hygiene, release pipeline   ████████████████████  done
Phase 1   Secure management plane                  ████████████████████  done
Phase 2   Two-node architecture (Pi + Jetson)      ██████████████████░░  built; Jetson hardware run pending
Phase 3   Enforcement you can trust                ██████████████████░░  built; 72 h inline soak pending
Phase 4   Detection quality                        ██████████████████░░  built; GPU models, public datasets pending
Phase 5   Integrations and operations              ████████████████████  done (Elastic verified live)
Phase 6   Production release                       ████████████████░░░░  released; OS images, pen test, beta pending
Phase 7   Scale and advanced intelligence          ████████████████████  done
Phase 8   Proven in the field                      ████████░░░░░░░░░░░░  software done; field proof pending
Phase 9   Deeper visibility                        ████████████████████  done (field captures pending)
Phase 10  Assisted operations                      ████████████████████  done (live IdP / AD runs partly pending)
Phase 11  Platform and ecosystem                   ████████████████░░░░  software done; hardware kits, certification
```

**What is verified, and how**

| Evidence | Where |
|---|---|
| Enforcement on the real kernel: block, quarantine, rate limit, containment, OT segmentation, IPv6, flood safety | `tests/firewall_netns/` |
| CIC-IDS2017: brute force, port scan and infiltration detected; 0.02–0.05% false positives per flow | [docs/EVALUATION.md](docs/EVALUATION.md) |
| Same-traffic comparison with Suricata 7 + ET Open on a lab capture: 9/11 vs 3/11, complementary | [docs/EVALUATION.md](docs/EVALUATION.md) |
| OIDC and SAML against Keycloak 26; alerts into Elasticsearch 8.15; tickets into TheHive 5.4; LDAP against OpenLDAP 2.6 | `tests/live/` |
| Throughput and decision latency on a Pi 5 | [docs/PERFORMANCE.md](docs/PERFORMANCE.md) |

**Still to come** (needs hardware, a lab or outside people): external penetration test
([scope](docs/PENTEST_SCOPE.md)), 30-day beta at 3–5 sites ([plan](docs/BETA_PROGRAM.md)), 72-hour inline soak
with a bypass NIC, Jetson validation and GPU models, pre-built OS images, captures from real PLCs and Windows
domains, live Active Directory / Entra ID / Okta / Jira / ServiceNow / Splunk runs, IEC 62443-4 and CE/FCC
certification. Full plan and exit criteria: [PLAN.md](PLAN.md).

### Known limitations

1. **Self-signed certificate by default:** browsers warn until you import your own (`sentinelctl tls import`).
   Web Push needs a certificate the phone trusts.
2. **Passive placement cannot stop traffic.** On a mirror port it alerts; blocking needs inline placement.
3. **Inline bridge without conntrack** (stock Pi kernel): containment stops new TCP connections and off-profile
   UDP, but packets of existing connections pass.
4. **Floods degrade detection.** Memory stays bounded and you get an overload alert, but stopping a flood needs
   your router, switch or the inline rate limit.
5. **Throughput:** about 120,000 packets/s on a Pi 5 (~0.5–1 Gb/s of typical traffic).
6. **Systemd memory limits** need `cgroup_enable=memory` on stock Raspberry Pi OS; in-process limits apply anyway.
7. **Sealed LDAP** (the Windows default after Kerberos/NTLM) is not readable; AD reconnaissance detection sees
   plain LDAP only.

---

## Documentation

**Documentation site: <https://vishwa-10147.github.io/SentinelEdgeAI/>**

| For | Read |
|---|---|
| Understanding the product | [EXPLAIN.md](EXPLAIN.md) · [PLAN.md](PLAN.md) |
| Installing and operating | [Admin guide](docs/ADMIN_GUIDE.md) · [Runbooks](docs/RUNBOOKS.md) · [Troubleshooting](docs/TROUBLESHOOTING.md) |
| Integrating | [API reference](docs/API.md) (generated) · [Extensions](docs/EXTENSIONS.md) · [Elastic](deploy/elastic/filebeat.yml) |
| Deploying | [Pi](deploy/pi/README.md) · [Jetson](deploy/jetson/README.md) · [Hosted fleet](deploy/fleet-hosted/README.md) · [Monitoring](deploy/monitoring/README.md) · [Hardware](hardware/sentineledge-duo/BUILD_GUIDE.md) |
| Evidence | [Evaluation](docs/EVALUATION.md) · [Performance](docs/PERFORMANCE.md) · [Pen-test scope](docs/PENTEST_SCOPE.md) · [Beta programme](docs/BETA_PROGRAM.md) |
| Security | [SECURITY.md](SECURITY.md) · [CHANGELOG.md](CHANGELOG.md) |

---

## Configuration

Detection tuning lives in [`config.yaml`](config.yaml); runtime settings in `/etc/sentinel/sentinel.env` on a
device. The most used:

| Variable | Default | Purpose |
|---|---|---|
| `FIREWALL_DRY_RUN` | `1` | `1` records actions only; `0` applies real firewall rules |
| `SENTINEL_FIREWALL_BACKEND` | `auto` | `auto`, `nft` or `iptables` |
| `SENTINEL_CAPTURE` | `auto` | `auto` (AF_PACKET when permitted), `afpacket`, `scapy` or `zeek` |
| `SENTINEL_UPDATE_CHANNEL` | `stable` | `stable` or `beta` for `sentinelctl update` |
| `SENTINEL_MFA_ROLES` | `operator,admin` | Roles that must use two-step sign-in |
| `SENTINEL_TLS_CERT` / `_KEY` | set by `sentinelctl` | HTTPS certificate and key |
| `SENTINEL_RATE_LIMIT_READ` / `_WRITE` | `600` / `60` | API requests per client per minute |
| `DATABASE_URL` / `SENTINEL_BRAIN_DATABASE_URL` | unset | PostgreSQL instead of SQLite |
| `SENTINEL_MAX_FLOWS` / `_SOURCES` / `_DEVICES` | `100000` / `20000` / `20000` | Flood-safety bounds |
| `SENTINEL_INTERNAL_PREFIXES6` | unset | Global IPv6 prefixes used internally |

Ports: console and API `9000`, engine metrics `9101`, brain link `9443`, fleet server `9444`. All other settings
are documented in the [admin guide](docs/ADMIN_GUIDE.md).

---

## Development

Requirements: Python 3.11+, Node.js 20.19+, Linux or macOS (packet capture needs root or `CAP_NET_RAW`).

```bash
git clone https://github.com/vishwa-10147/SentinelEdgeAI.git && cd SentinelEdgeAI
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
(cd frontend && npm ci && npm run build)
python dashboard/dashboard_api.py            # API and console on http://127.0.0.1:9000 (dry run)
```

| Task | Command |
|---|---|
| Unit and integration tests | `PYTHONPATH=. pytest -q` |
| Real-kernel enforcement tests | `sudo bash tests/firewall_netns/run_enforcement_netns.sh` (and the other `run_*_netns.sh`) |
| Live tests (Docker) | `bash tests/live/run_keycloak_sso.sh`, `run_elastic.sh`, `run_thehive.sh` |
| Simulated attack → alert → dry-run block | `python scripts/demo_attack.py --ip 192.168.1.50 --block` |
| Evaluate on a capture (and against Suricata) | `python -m evaluation.pcap capture.pcap --truth truth.json [--suricata eve.json]` |
| Build a Pi package | `bash scripts/build_pi_package.sh` |

```text
capture/       packet capture (AF_PACKET fast path, Scapy for deep inspection)
flow/ features/  flow table and per-flow features
detection/     baselines, models, detectors (DNS, TLS, HTTP, lateral movement, OT), fusion, registry, packet dispatch
enforcement/   playbook, tuning, policy as code, protected hosts, identity and OS fingerprinting, trust, segmentation, VLAN
core/          engine, firewall, auth (local, OIDC, SAML, LDAP), audit, storage, incidents, assistant
brain/ sensor/ common/   two-node link: PKI, enrolment, signed commands, buffering, HA
fleet/         fleet server, site agent, rollouts, federated learning, multi-tenancy
integrations/  SIEM, notifications and Web Push, ticketing, Suricata, Zeek
intel/         threat-intelligence feeds and community sharing
extensions/    extension SDK, packaging and sandbox
evaluation/    dataset harness, pcap evaluator, lab capture generator
ops/ security/ backup, signed update channels, release model signing
dashboard/ frontend/     FastAPI backend and React console
packaging/ deploy/ scripts/   sentinelctl and systemd units; Pi, Jetson, Elastic, hosted fleet; installers and tools
tests/         unit tests, real-kernel tests (tests/firewall_netns/), live tests (tests/live/)
```

Releases are built by CI when a `vX.Y.Z` tag matching `VERSION` is pushed.

---

## Contributing

1. Open an issue describing the change.
2. Add tests. `pytest`, Bandit and pip-audit must pass; capture or enforcement changes also need the real-kernel
   tests in `tests/firewall_netns/`.
3. Update [CHANGELOG.md](CHANGELOG.md) and the documentation the change affects.
4. Changes to the firewall, authentication, signing or the update path need a second reviewer.

Security issues: do not open a public issue; follow [SECURITY.md](SECURITY.md).

## License

Licensed under the [Apache License 2.0](LICENSE); see [NOTICE](NOTICE). Contributions are accepted under the
same terms.
