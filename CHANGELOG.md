# Changelog

All notable changes to this project are documented in this file.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security
- **The release model is signed with Ed25519; devices and CI hold no secret** (Phase 8). The Isolation Forest shipped in `model/` used to carry an HMAC-SHA256 signature, so every device and CI job needed the same secret key (and anyone holding one device's key could sign a model all devices accepted). It is now signed with an Ed25519 key that exists only on the maintainer's machine (`scripts/sign_model.py --generate-key`); the public key ships in `security/release_model.pub`. The first install pins it in `/etc/sentinel/release_signing.pub` and every later install refuses a package whose model does not verify against the pinned key. CI (release, model-signing, check-model-signature workflows) verifies with the public key only; the `SENTINEL_MODEL_SIGNING_KEY` secret is no longer used. HMAC (version 1) signatures are refused. `sentinelctl install` and `scripts/install.sh` no longer require a key (`--signing-key` and `deploy/pi/provision_key.sh` are accepted and ignored); the Vault key-delivery files moved to `docs/archive/hmac_model_key/`. Devices can delete `/etc/sentinel/model_signing.key`. The model itself is unchanged (same SHA-256).

### Added
- **SAML 2.0 sign-in** (Phase 10, `core/saml.py`): SP-initiated Web Browser SSO for ADFS, Shibboleth, Entra ID / Okta SAML apps. XML signatures checked by `signxml` (new dependency, with `lxml`), never by hand; every value read from the signed element only; exactly one, unencrypted, assertion; issuer, audience, recipient, validity window, `InResponseTo` bound to this browser's request (unsolicited responses refused), one-time assertion ids, DTDs refused, comments stripped (NameID truncation). Roles from mapped groups, MFA from the authentication context (or trust_idp_mfa), accounts pinned to (IdP, NameID). `GET /api/auth/saml/login`, `POST /api/auth/saml/acs`, `GET /api/auth/saml/metadata`, `GET/PUT /api/saml`; **Users → Single sign-on (SAML 2.0)** and a sign-in button. Tested with signed responses and the known attacks (signature wrapping, tampering, comment truncation, replay); not yet against a live IdP.
- **LDAP / Active Directory sign-in** (Phase 10, `core/ldap_auth.py`, `ldap3`): the normal sign-in form checks non-local usernames against the directory. LDAPS or StartTLS only with certificate and host-name verification; empty passwords refused (anonymous bind); filter escaping; exactly one entry; roles from `memberOf`, groups listing the user and nested AD groups; local TOTP still required for Operator/Admin; lockout applies; accounts pinned to `objectGUID`/`entryUUID`, never taking over a local account. `GET/PUT /api/ldap`, `POST /api/ldap/test` (look a user up without a password); **Users → Directory sign-in**. Verified against OpenLDAP 2.6 in a container over LDAPS and StartTLS; not yet against a live AD.
- **Web Push notifications** (Phase 10, `integrations/webpush.py`): Operators and Admins turn on push per phone or browser (**Operations → Notifications → Push on this device**) and get each approval request as a notification that opens the phone approval page (no credentials in the message). Standard Web Push without a new dependency: RFC 8291 aes128gcm encryption (verified against the RFC's Appendix A test vector) and RFC 8292 VAPID (ES256, key created on first use, mode 600). Subscriptions may only point at the browser push services (SENTINEL_WEBPUSH_HOSTS adds more), so they cannot make the appliance call other hosts; push goes only to accounts that are enabled Operators/Admins when it is sent; gone subscriptions (404/410) are removed. `GET /api/push`, `POST /api/push/subscriptions`, `DELETE /api/push/subscriptions/{id}`, `POST /api/push/test`; service worker `/sw.js` and `/manifest.webmanifest` (add to home screen on iOS). Needs a trusted HTTPS certificate on the console.
- **Signed update channels** (Phase 8, `ops/channels.py`): `stable` and `beta` manifests (`channels/*.json`) name one release and the SHA-256 of its exact package, signed with the Ed25519 release key the device pinned at its first install. `sentinelctl update` follows `SENTINEL_UPDATE_CHANNEL` (new installs: `stable`) or `--channel stable|beta`, installs only the named release, and only if the downloaded package matches the signed SHA-256, so a compromised CI job or a replaced GitHub release cannot reach devices on a channel. Manifests expire after 120 days (re-signed with `python -m ops.channels refresh`), and a device refuses a manifest older than the one it last accepted (rollback/freeze protection). Maintainer commands: `sign`, `promote --from beta --to stable`, `refresh`. Both channels start at v2.16.0. Without a channel setting `update` behaves as before; fleet rollouts (`--to X.Y.Z`) are unchanged.
- **JA4H and plain-HTTP metadata** (Phase 9, `detection/http.py`): the first segment of every plain-HTTP request (any port) gives its JA4H (FoxIO layout) from the request line and header names; only Host, User-Agent and the first Accept-Language tag are read, never the path, cookie values or credentials. Findings: `http_known_bad` (JA4H, full or first two parts, on the blocklist or in threat intel, which now accepts `ja4h` / STIX `x-ja4h` indicators), `http_lolbin` (PowerShell or certutil fetching from an internet host, T1105), `http_basic_auth` (a password in HTTP Basic over plain HTTP; low probability, never a response on its own), `http_new_client` (new HTTP client fingerprint on a device after its first day). Zeek's `http.log` feeds the same detector (JA4H when the JA4 package is loaded).
- **Session rhythm** (Phase 9, `SessionRhythmDetector`): small encrypted sessions (TLS ports) to one internet host that carry near-identical byte counts at irregular intervals, the jittered check-in that defeats the interval-based beaconing detector. Reported only when the timing is irregular, so the two detectors do not report the same thing.

## [2.16.0] - 2026-11-01

Phase 9: passive OS fingerprinting and LDAP / Active Directory reconnaissance.

### Added
- **Passive OS and device-type fingerprinting** (Phase 9, asset context, `enforcement/os_fingerprint.py`): the SYN of every connection an internal host opens is fingerprinted (initial TTL and hop count, window and scale, MSS, TCP option order, quirks; a p0f-v3-style signature with our own rules) on both the AF_PACKET fast path and the scapy path, IPv4 and IPv6. Windows, Linux/Android, macOS/iOS, FreeBSD and minimal embedded/network stacks are told apart. The result is combined with what the device announced (DHCP vendor class and option 55, OUI vendor, hostname) into one OS and device-type guess with a confidence and the evidence behind it. Nothing is sent to the device. Flood-safe: one parse per source per minute, a bounded table and a database write budget. `GET /api/assets/{ip}/profile`, `GET /api/assets/profiles` (Viewer), `python -m enforcement osfp list|show`, and OS / device type / evidence in the console's device detail.

- **LDAP metadata and Active Directory reconnaissance** (Phase 9, lateral movement, `detection/lateral.py`): BER parsing of LDAP requests on 389, the global catalog 3268 and CLDAP: the bind method (simple / SASL and mechanism; a simple bind's password is never read beyond "present"), and for searches the base, scope, attribute names in the filter and the requested attributes. New findings: `ldap_recon`, a reconnaissance search new for its source after the learning period (accounts with SPNs T1558.003, without pre-authentication T1558.004, delegation T1087.002, domain trusts T1482, LAPS passwords T1552, privileged groups T1069.002); `ldap_enumeration`, three or more of those within ten minutes, as BloodHound/PowerView do, at any time (T1087.002); `ldap_cleartext_bind`, a password sent in a plain simple bind (low probability: never triggers a response on its own). Zeek's `ldap.log` and `ldap_search.log` feed the same detector. Bounded: 16 messages per segment, filter depth 16 and 64 terms, requests over 1,200 bytes stay on the fast path. Incident checklist steps for both. Sealed LDAP (the Windows default after a Kerberos/NTLM bind) is not readable.

### Fixed
- The console's Lateral Movement panel only matched alerts by port or by text, so the detector's own `dcsync`, `remote_service`, `remote_task` and `kerberos_burst` findings (and the new LDAP ones) were left out.
- Device detail showed a stray "0" under Asset Context when a device had no CVE matches.

## [2.15.0] - 2026-11-01

Phase 9 complete: IPv6 parity for containment and OT segmentation.

### Added
- **IPv6 containment and OT segmentation** (Phase 9 IPv6 parity): per-family nftables sets (`contain6`, `contain_peers6`, `contain_ext6`, `ot_guarded6`, `ot_allowed6`) in the inet and bridge tables; peer profiles for IPv6 devices; IPv6 controllers guarded with same-family masters only. Internal IPv6 = unique-local, link-local and `SENTINEL_INTERNAL_PREFIXES6`, one definition shared by the profiles and the firewall. New real-kernel test `tests/firewall_netns/run_ipv6_netns.sh` (20/20).

### Fixed
- **IPv6 quarantine cut the host off completely.** The quarantine rules allowed DNS and DHCPv4 but dropped ICMPv6 neighbour discovery, without which an IPv6 host cannot reach anything on the link, including the quarantine notice page. Restricted IPv6 hosts now keep neighbour/router discovery and DHCPv6 (udp/547). Shown on the real kernel: with the rule removed, 3 of the new test's checks fail.

## [2.14.1] - 2026-11-01

### Security
- `core/assistant.py` and its test held literal invisible bidirectional characters (U+200B-U+200F, U+202A-U+202E, U+2066-U+2069) inside the assistant's text-cleaning pattern and an injection sample, the "Trojan Source" pattern Bandit flags as high severity (B613). Behaviour was correct, but source must never contain characters that display differently from how they run; both now use ASCII escape sequences only. No other file added since v2.9.3 contains such characters (checked).

## [2.14.0] - 2026-11-01

Phase 10: the optional local assistant. With it, every main Phase 10 item is built.

### Added
- **Optional local assistant** (Phase 10, `core/assistant.py`): explains an incident or answers a question about it (or about the open incidents) in plain language. Off by default. Read-only by construction: no tools, no API access, the answer is plain text and never acted on. Network-derived text is cleaned (control and bidi characters, data-delimiter tags, length) and fenced in one `<data>` block the system prompt declares untrusted. Local only: the model server must resolve to loopback or the private network, checked when saved and before every call (`allow_remote` to override). One question at a time (others get 429), timeouts, audited. Backends: `template` (no model, factual summary), `ollama`, `openai` (OpenAI-compatible such as llama.cpp `llama-server`). `GET /api/assistant`, `GET/PUT /api/assistant/config`, `POST /api/assistant/ask`; **Ask the assistant** in incident detail, **Operations → Assistant**. `deploy/assistant/`: an Ollama systemd drop-in and a hardened `sentineledgeai-llm.service` with CPU, memory and priority limits.

## [2.13.0] - 2026-11-01

Phase 10: notifications.

### Added
- **Notifications** (Phase 10, `integrations/notify.py`): approval requests are sent the moment the playbook holds an action for an Operator, to chosen e-mail / Slack / Teams / webhook integrations, with a link to a new phone-friendly approval page (`#approve/<id>`, sign-in required: the link carries no credentials); daily or weekly digests of open incidents, approvals waiting and tuning suggestions. Background queue (the engine never waits on SMTP or Slack), one failing destination does not stop the others, no catch-up message when the digest is first enabled. `GET/PUT /api/notifications`, `POST /api/notifications/test`, `GET /api/notifications/digest/preview`, `POST /api/notifications/digest/send`, `GET /api/playbook/pending/{id}`; **Operations → Notifications**. Notification links (`#approve/…`, `#incidents`) survive sign-in, including SSO.
- Integrations: e-mail, Slack, Teams and webhook destinations can carry plain notifications (`Sink.message`).

## [2.12.0] - 2026-11-01

Phase 10: guided tuning.

### Added
- **Guided tuning** (Phase 10, `detection/guided_tuning.py`): suggestions from analysts' false-positive labels, grouped per detector by source host, source subnet or destination (at least 5 false alarms in 14 days, none confirmed; a subnet only when several hosts share the noise), each with a proposed scoped rule. Rules downgrade (shown, severity −25, half confidence, so no automatic response; Analyst) or suppress (dropped; Operator; never for DCSync, OT stop, threat intel), always expire (7–180 days), need a src/dst scope of /16 or narrower, are audited, and apply in one place for every detector including Zeek and Suricata. `/api/guided-tuning/suggestions[/{id}/accept|dismiss]`, `/api/guided-tuning/rules`; console **Tuning** panel.

## [2.11.0] - 2026-11-01

Phase 10: single sign-on.

### Added
- **Single sign-on with OpenID Connect** (Phase 10, `core/sso.py`): Entra ID, Google, Okta, Keycloak or any OIDC provider; authorization-code flow with PKCE, state/nonce/verifier in a signed 10-minute cookie, ID tokens verified against the IdP's JWKS (RS256/ES256 only; `none` and HMAC refused), issuer/audience/azp/expiry checks. Roles come from IdP groups (highest wins, optional default role, otherwise refused) and follow the groups at every sign-in. Operator/Admin need MFA asserted in `amr` unless the IdP is trusted to enforce it. SSO accounts are pinned to the IdP's issuer + subject: they never take over a local account with the same name, have no local password, and skip local TOTP. `GET /api/auth/oidc/login`, `GET /api/auth/oidc/callback`, `GET/PUT /api/sso` (Admin); "Sign in with …" button and plain-language refusal messages on the sign-in screen; SSO settings and SSO tags in the Users panel. No new dependency (verification uses `cryptography`).

## [2.10.0] - 2026-11-01

Phase 8 work that does not need hardware or other people, most of Phase 9 (deeper visibility) and the first two items of Phase 10 (assisted operations). The pen test and field beta are still pending, so this is not v3.0.

### Documentation
- **Roadmap beyond v2.9** (PLAN.md):
  - Phase 8, proven in the field: pen test, beta, soak, Jetson, OS images
  - Phase 9, deeper visibility: lateral-movement protocols, more OT, a forensic packet buffer, IPv6
  - Phase 10, assisted operations: incidents, an optional read-only local assistant with strict rules, SSO, mobile
  - Phase 11, platform: multi-tenant MSP fleet, x86 10 Gb/s, certification

  PLAN.md also says how far each hardware option scales and who the product is for.
- README: who it is for, how the "AI" works (no language model), roadmap phases 8–11, current configuration variables and ports, updated known limitations.
- EXPLAIN.md, SECURITY.md (threat model, supported versions, known issues, deployment checklist), the admin guide (capacity and flood safety), runbooks (containment, capture overload, paused rollouts, brain failover, federated rounds), troubleshooting, performance (flood results), pen-test scope and beta plan brought up to date.
- Deploy, dashboard, frontend, packaging and scripts READMEs now describe the current `sentinelctl` setup and mark the older development helpers as legacy. `updates.md` is now a how-to for putting the Pi inline between the router and the switch.
- Archived superseded documents (old release notes, agent notes, project history and snapshot, a May PR draft, Render secrets, the first runner guide) in `docs/archive/`, and removed the `update_project_history` workflow, whose push to `main` had silently failed on every release.

### Added
- Prometheus alert `SentinelCaptureOverloaded`.
- **Fleet remote actions and fleet-wide alert search** (Phase 8): block, unblock, quarantine, rate-limit, contain or release on one site from the fleet console or CLI; actions ride with the site's next 5-minute report, run through the site's own whitelist, protected hosts and TTLs, and report their outcome. Sites can opt out (`SENTINEL_FLEET_REMOTE_ACTIONS=off`). Alert summaries are searchable across sites. Fleet panel controls.
- **Evaluation loaders for UNSW-NB15 and CIC-IoT2023** (Phase 8), following the CIC-IDS2017 loader; categories the flow detectors do not cover count as benign for false-positive purposes.
- **Signed update channels** (Phase 8): sensor upgrades staged from a `stable` or `beta` channel; `SENTINEL_REQUIRE_SIGNATURE=1` requires an Ed25519 signature over the package SHA-256.
- **Forensic packet buffer** (Phase 9, `capture/packet_buffer.py`): recent packets per source kept in a bounded ring; a PCAP is written when an alert fires; `GET /api/pcaps`, download, delete (Admin); console Forensics panel.
- **Asset context** (Phase 9, `core/asset_context.py`): device criticality (critical / important / standard) and offline CVE matching by device type and OS keywords (no network lookups); `/api/assets/*`; shown in device detail. The CVE matching is keyword-based and indicative only.
- **More OT protocols** (Phase 9, `detection/ot.py`): IEC 60870-5-104 (control-direction ASDUs; reset process is a restart), S7comm (job functions; PLC stop, program download), EtherNet/IP CIP (services incl. write tag, reset, stop; Unconnected Send unwrapped once) and MQTT (connect/publish/subscribe; publish is the write). They feed the existing per-controller learning, so new masters, first-time writes and stop/restart commands are reported for them too. Capture routes the new ports to inspection; segmentation knows their ports; the OT console names them.
- **Lateral movement** (Phase 9, `detection/lateral.py`): SMB2 headers (tree-connect share, NTLM authentication, DCE-RPC binds on named pipes), DCE-RPC on 135 and the Kerberos message type; no payload kept. Findings: admin share use (T1021.002), remote service control/PsExec (T1569.002), remote scheduled tasks (T1053.005), DCSync from a non-replicator (T1003.006), NTLM fan-out / pass-the-hash pattern (T1550.002), Kerberos ticket bursts (T1558.003 / T1110.003) and admin-service fan-out to new hosts over SMB/RDP/WinRM/RPC/SSH (T1021). Learning (7 days) persists in `data/lateral.db` (`SENTINEL_LATERAL_DB`). Only small SMB segments (≤ 1200 bytes, the control messages) take the slow path, so file transfers stay on the fast path.
- **Server-side TLS** (Phase 9, `detection/tls.py`): JA4S fingerprints (matched against the blocklist and threat intel) and, for TLS ≤ 1.2 to external servers, certificate anomalies: self-signed, valid under 3 days, expired / not yet valid, or not issued for the SNI the client asked for. The server handshake is reassembled over up to 8 segments; the fast path follows a ServerHello for its next segments.

- **Zeek as a sensor engine** (Phase 9, `integrations/zeek.py`): the engine follows Zeek's JSON logs (`SENTINEL_ZEEK_LOGS`, rotation-safe) and feeds conn/dns/ssl/notice/smb_mapping/ntlm/dce_rpc/kerberos/modbus/dnp3 to the existing detectors; `SENTINEL_CAPTURE=zeek` makes Zeek the only engine. The Suricata tailer is now reusable (`EveTailer(parse=…)`, `step()`).
- **Incidents** (Phase 10, `core/incidents.py`): related alerts, devices and responses grouped into one incident (shared internal device within 2 h; incidents that meet are merged; external addresses never link), with a timeline of alerts and firewall responses, a severity, and a "what to do now" checklist chosen by the kinds of detection. Analysts acknowledge, resolve or reopen with a note (audited, `data/incidents.json`); new activity reopens a resolved incident. `GET /api/incidents`, `GET /api/incidents/{id}`, `POST /api/incidents/{id}/status`; console **Incidents** panel.
- **Ticketing and SOAR** (Phase 10, `integrations/ticketing.py`): incidents open one ticket per target in Jira, ServiceNow, TheHive 5 or a signed webhook (per-target minimum severity); new alerts become comments / work notes; resolving the incident resolves the ticket. Ticket systems report back through `POST /api/tickets/inbound/<target>` (Bearer inbound token or HMAC signature), which can only change an incident's status. Sync every minute in the API process, `POST /api/tickets/sync`, `GET /api/tickets`, `python -m integrations.ticketing sync|status`; incident detail lists its tickets.
- **SentinelEdge Duo hardware** (`hardware/sentineledge-duo/`): parametric enclosure for a Pi 5 sensor + Jetson brain in one box, STL files, diagrams, interactive viewer and a build and product guide.

### Changed
- **The release Isolation Forest moved to the Ed25519 model registry** (Phase 8): it is verified by signature and pinned SHA-256 before loading, and unsigned models are refused (`SENTINEL_ALLOW_UNSIGNED_MODELS=1` for development). A device without a model starts untrained, trains on its own traffic and signs the result with its own registry key; the old HMAC-signed `model/isolation_forest.pkl` is no longer loaded.
- Topology view renders IPv6 addresses; lateral-movement indicators panel in the console.

### Fixed
- The release model-signature check failed on every clean checkout after the registry move (the registry is device data, not in git). On a checkout without a registry it now runs a signing self-test (register, verify, load, refuse a tampered model); with a registry it verifies the active model as before.
- `docs/API.md` regenerated: the forensics and asset-context endpoints were missing, which failed the API reference test.

## [2.9.3] - 2026-10-31

### Fixed
- 2.9.2 regression: on a device, `health.json` and `live_stats.json` stopped updating. The atomic write put its temporary file next to the symlink, in the read-only release directory, instead of next to the real file in `/var/lib/sentinel`. The write now goes beside the link's target (`utils/atomic.py`), with a regression test for the read-only, symlinked layout.

## [2.9.2] - 2026-10-31

### Security
- **Flood safety.** A flood of spoofed source addresses could exhaust the appliance's memory: v2.9.1 grew from 246 MB to 1.2 GB in 40 seconds at 300,000 packets/s. Now:
  - The flow table is capped (`SENTINEL_MAX_FLOWS`, default 100,000) and kept in order of last activity, so the least recently active flows are evicted first. Evicted flows are scored within a per-second budget, and the timeout scan stops at the first active flow.
  - Per-source state in every detector, baseline and fingerprint is capped (`SENTINEL_MAX_SOURCES`, default 20,000). The adaptive baseline stores 4 numbers per flow instead of whole feature dicts, and fingerprint profiles keep at most 256 destinations and ports.
  - The device registry, peer profiles and OT controller table are capped, so spoofed ARP/DHCP or BACnet floods can't grow them.
  - Finished flows are handed to scoring once per pass and shed when the queue is full. One asyncio coroutine per flow had piled up tens of thousands of waiting tasks.
  - A new overload monitor raises one `capture_overload` alert per 10 minutes, adds a `capture` section to the health file and exports `sentinel_capture` metrics.
  - systemd units set `CPUWeight`, `TasksMax` and `OOMScoreAdjust`, so the engine yields CPU and is the first OOM victim. They also set `MemoryHigh`/`MemoryMax`, which apply where the memory cgroup is enabled.

  Verified against the real engine in network namespaces: 3 minutes at 322,000 spoofed packets/s levels off at about 460 MB (`tests/firewall_netns/run_flood_netns.sh`).

### Fixed
- `health.json` and `live_stats.json` were written non-atomically, so readers could see half-written files, and a truncated `live_stats.json` reset the live statistics. Both are now written atomically: the live statistics at most once a second instead of for every flow, with `unique_ips` capped at the 5,000 most recent sources.
- The health file was rewritten once per finished flow instead of once per pass.
- Reading a baseline count for an unknown source created an empty entry.

## [2.9.1] - 2026-10-31

### Added
- **CIC-IDS2017 results** (docs/EVALUATION.md) on four capture days. Brute force was detected in 114 s, the port scan within a minute of the scan starting and the infiltration in 846 s; 4 of 8 bots were found. False positives were 0.02–0.05% per benign flow.

### Fixed
- The CIC-IDS2017 loader read afternoon timestamps as morning (the files use a 12-hour clock without AM/PM), which replayed attacks out of order, and gave every flow of a minute the same time. Hours 1–7 are now afternoon, and flows within a minute are spread in file order. The MachineLearningCVE variant (no IPs or timestamps) is refused with a clear message instead of silently yielding no events. Infiltration counts any compromise behaviour from the victim, not only exfiltration.

## [2.9.0] - 2026-10-31

### Added
- **Compliance packs (Phase 7).** Evidence reports for ISO/IEC 27001:2022 Annex A, IEC 62443-3-3 and NIS2 (Art. 21(2) and 23). Each control is mapped to live evidence from the appliance: audit-log integrity, roles and MFA, TLS, device links, monitoring, detection and evaluation, response readiness, asset and OT inventory, segmentation, threat intelligence, SIEM export, backups, high availability, signed updates, policy history and reports. Each control gets a status of met, partial, gap, manual (organisational controls) or n/a, plus a one-line explanation of how to close any gap. JSON and PDF, `GET /api/compliance`, `/api/compliance/{pack}`, `/api/compliance/{pack}/pdf` (Admin), `python -m compliance report iso27001 --pdf out.pdf`, **Operations → Compliance**. These are documentation support, not a certification, and control descriptions are our own summaries.
- Backups are now recorded (`data/backup_log.json`), so the last backup date can be shown as evidence.

## [2.8.0] - 2026-10-31

### Added
- **High availability (Phase 7).** Two brains can run as an active/standby pair. They share their key material through an encrypted pairing bundle (`python -m brain ha export|import`, scrypt + AES-256-GCM), and each brain gets its own server certificate from the shared CA. They share state through one PostgreSQL. A leader lease in the database, renewed every 10 s with a 30 s takeover, decides which brain issues commands; the standby refuses to. Sensors can know several brains (`python -m sensor add-brain URL`, accepted only if the brain's certificate comes from the pinned CA) and fail over on their own. Sensors watching the same segment can be grouped (`python -m brain segment`), and segment commands go to the sensor heard from most recently. New: `GET /api/brain/ha`, `POST /api/brain/sensors/{id}/segment`, `POST /api/brain/segments/{segment}/commands`, `GET /v1/status` on the brain link.

## [2.7.0] - 2026-10-31

### Added
- **Response tuning (Phase 7).** A contextual bandit learns, per kind of incident, which response resolves it with the least disruption (alert < rate limit < contain < block < quarantine). "Resolved" means the source was not detected again within an hour, and an analyst's false-positive label counts as "an alert was enough". It works only inside the bounds people set:
  - never stronger than the playbook's step
  - never gentler than `min_action` (default rate limit)
  - always stronger after a response that failed for the same incident
  - the approval gate is unchanged

  Gentler responses start from a pessimistic prior, so they are tried rarely without evidence. The default mode `recommend` only shows and audits its choice, and `apply` acts on it. `GET/POST /api/tuning`, `python -m enforcement tuning status|set`, **Operations → Response**.
- `contain` is a playbook action, and can be used as an explicit step in the response policy.

## [2.6.0] - 2026-10-31

### Added
- **Federated learning (Phase 7).** Sites keep a reservoir sample of their normal flows (`data/samples.db`, flows that raised no finding), train the flow autoencoder locally, starting from the current global model, and send the fleet server only model weights, input-scaler statistics and counts. Flows and feature vectors never leave the site. The server validates each update (layer shapes, finite values, matching features) and aggregates a round by FedAvg weighted by samples, with an exact mean/variance merge. Every site rebuilds the global model, recalibrates its threshold on its own traffic and registers it as a signed **shadow** model: it is scored but never acted on until an Admin promotes it. Updates are clipped around the global model, and noise can be added. Start rounds from **Fleet → Federated learning**, `POST /api/fleet/federated` or `python -m fleet federated start --min-sites N`.

## [2.5.1] - 2026-10-31

### Fixed
- The 2.5.0 event bus read live statistics and events only from the database. It now also reads the engine's `live_stats.json` and tails `live_events.jsonl` (`ENABLE_FILE_FALLBACK`, on by default), as the old stream did, picking up half-written lines and file rotation correctly.

## [2.5.0] - 2026-10-31

### Added
- **Operations console** with tabs for the APIs that had no screen yet: approvals and active restrictions (approve, deny, release), the response policy as YAML with a checked diff before apply, two-node sensors (enrolment code, revoke, health), the model registry (promote, roll back), analyst feedback precision and the latest evaluation.
- **Event bus for the live stream** (`core/events.py`). One poller reads alerts and live events by row id and fans them out to every WebSocket. Events are numbered, so a reconnecting console resumes from its cursor and gets exactly what it missed, or a `resync` after an API restart. Heartbeats come every 15 s, and the console reconnects after 45 s of silence. A stalled client is dropped instead of slowing the others.
- **PostgreSQL for the brain store** (`SENTINEL_BRAIN_DATABASE_URL`, or `DATABASE_URL` as for the engine), tested against a real PostgreSQL 16.
- **Sensor upgrades through the brain.** `python -m brain upgrade stage --version X.Y.Z` (or `--file`) and `POST /api/brain/upgrade` stage a verified release. Sensors download it over the mutual-TLS link, check the announced SHA-256 and stage it, and the root update timer installs it with the usual health check and rollback. Sensors now report their version.

### Fixed
- Live events stopped reaching the console after the first 200: the stream read the *oldest* 200 rows every second.
- Two alerts in the same second could be dropped from the live stream (deduplication used whole-second timestamps).
- Events published by the demo endpoints reached at most one connected console (a shared queue drained by whichever connection read it first).

## [2.4.1] - 2026-10-31

### Fixed
- An upgrade only enabled the systemd units that the *previous* version's `sentinelctl` knew about, so units new in the upgraded release (the fleet path units and update timer in 2.4.0) were installed but left disabled. `install_units` now hands enabling to the new release's own script (`sentinelctl enable-units`).

## [2.4.0] - 2026-10-31

### Added
- **Fleet manager (Phase 7).** Any appliance can be a fleet server (`python -m fleet init`): own CA, mutual TLS on port 9444, one-time enrolment codes bound to a group. Sites pin the CA by fingerprint and report a compact status every 5 minutes (`sentineledgeai-fleet-agent.timer`): version, health, alerts by severity, trust levels, restrictions, OT and segmentation state, never flows or packets. Groups carry a configuration template (response policy or preset, validated on both ends) and a target version that rolls out in stages: stable-hash canaries, by default 10% at once, 50% after 24 h and 100% after 48 h. A failed site update pauses the rollout. The unprivileged agent records the target, and the root `sentineledgeai-fleet-update.timer` installs it with the verified, health-checked `sentinelctl fleet-update`. Console **Fleet** panel, `/api/fleet/*` (9 endpoints), CLI `python -m fleet init|code|sites|revoke|template|group|groups|rollout|enroll|report|status`.
- `sentinelctl update --to X.Y.Z` installs a specific release (downgrades are refused).

## [2.3.1] - 2026-10-31

### Fixed
- Trust scores were too harsh on real traffic: repeats of one alert kind stacked until a device hit 0. Each kind now counts once, at its strongest decayed value, and kinds add up to −80.
- Loopback is no longer scored. Protected hosts (gateway, the appliance, ...) are marked as such and never get a recommended response.
- Randomised MACs no longer earn the vendor bonus, and alerts without an attack type count as `anomaly` rather than `NONE`.

## [2.3.0] - 2026-10-31

### Added
- **Device trust and containment (Phase 7, zero-trust).** The engine learns each internal device's peer profile (`data/peers.db`, `SENTINEL_PEERS_DB`): internal peers exactly, internet destinations as protocol and port, capped per device. A trust score from 0 to 100 combines identity, tenure, recent alerts (decaying, with analyst false positives ignored) and active restrictions into a level (trusted / watch / untrusted), with reasons and a recommended response (`GET /api/trust`, `python -m enforcement trust`, new **Trust** console panel). The new `contain` response (`POST /api/firewall/contain`, Operator) keeps an untrusted IPv4 device to its learned profile plus DNS and DHCP instead of cutting it off. It is refused for protected hosts and for devices without a 7-day profile, expires with its TTL, and is cleared by any rollback. `GET /api/devices/{ip}/peers` shows the profile. Real-kernel test: `tests/firewall_netns/run_containment_netns.sh`.

### Changed
- README rewritten for v2.x: current capabilities, releases, API overview, repository layout and known limitations.

## [2.2.0] - 2026-10-31

### Added
- **OT micro-segmentation (Phase 7).** The OT detector's learned allow-lists can be enforced: only the hosts seen commanding a controller (plus management and whitelisted hosts, and Admin exceptions) may open connections to its industrial ports. Modes `off`, `monitor` and `enforce` (Admin, inline placement only). Enforcement uses a frozen snapshot, so newly learned hosts are not allowed silently. Protected hosts are never guarded, and replies are never cut. The plan is re-applied at boot, and any rollback or watchdog fail-open turns it off. CLI `python -m enforcement segment status|off|monitor|enforce|allow|refresh`; API `GET/POST /api/ot/segmentation`, `POST /api/ot/segmentation/allow`, `POST /api/ot/segmentation/refresh`; controls in the **OT devices** panel; every change is audited. Real-kernel test: `tests/firewall_netns/run_segmentation_netns.sh`.

## [2.1.0] - 2026-10-31

### Added
- **OT asset inventory (Phase 7).** What the OT detector learns (controllers, the hosts that command them and their functions) is kept in `data/ot.db` (`SENTINEL_OT_DB`), so an engine restart no longer begins a new 7-day learning period. `GET /api/ot/assets` (Viewer) and a new **OT devices** console panel show the inventory.

## [2.0.1] - 2026-10-31

### Fixed
- The Pi package bundled wheels for Python 3.11 only, so it could not install offline on Raspberry Pi OS Trixie (Python 3.13). It now carries wheels for both 3.11 and 3.13 (`WHEEL_PYTHON_VERSION` takes a space-separated list).

## [2.0.0] - 2026-10-31

First production-candidate release (Phases 2–6, plus the first Phase 7 feature: OT protocol awareness). The external penetration test, the 30-day beta, pre-built OS images and the Jetson hardware validation are still pending; see PLAN.md.

### Security
- `cryptography` upgraded 46.0.3 → 50.0.2 (PYSEC-2026-35, -36, -2141, -3552, -3553, -3554; GHSA-537c-gmf6-5ccf).

### Fixed
- The console index route `GET /` is registered even when the console is not built, so the route table (and its tests) is the same in CI and on a device.
- Flows idle for more than a day never expired (`timedelta.seconds` ignores days).
- The expired-flow scan ran on every packet (12 ms per scan at 20,000 flows); it now runs once per second.
- `policy.validate` accepted TTLs up to 30 days that the firewall then rejected; both now use the firewall's 1-day limit.
- The engine's Prometheus endpoint served the library's empty default registry instead of SentinelEdgeAI's metrics; it now also listens on 9101 (`app__metrics_port`) instead of 8001.
- The logger added an invalid handler when the log file could not be opened.
- The engine never started as a service: `main.py` imported a metric (`PROCESS_UP`) that did not exist.
- Every packet failed analysis with `NameError: final_risk`; live statistics are now updated where each flow is scored.
- `sentinelctl install` left the release's Python environment unreadable to the `sentinel` service user (a leaked `umask 027`), so neither service could start.
- `sentinelctl`'s health check accepted a crash-looping service; services must now stay up with no automatic restarts for `SENTINEL_HEALTH_SETTLE` seconds (default 15).

### Upgrade notes
- **The console moves to HTTPS.** Installing or upgrading creates a self-signed certificate for the device (its hostname, `.local` name and current addresses) and turns on HTTPS, so the console is now at `https://<pi-address>:9000`. The browser warns once about the self-signed certificate; compare the SHA-256 fingerprint from `sentinelctl tls show` before accepting it, or install your organisation's certificate with `sudo sentinelctl tls import cert.pem key.pem`. To keep plain HTTP (for example behind a reverse proxy that terminates TLS), set `SENTINEL_TLS_CERT=` and `SENTINEL_TLS_KEY=` to empty values in `/etc/sentinel/sentinel.env`.
- Scripts that call the API on the device must use `https://`. The firewall rollback guard follows the setting automatically.

### Added
- **OT protocol awareness (Phase 7).** Modbus/TCP, DNP3, BACnet/IP and OPC UA requests are parsed (`detection/ot.py`) from both capture paths. A per-controller learning period records which hosts command each controller and which functions they use; afterwards a new master (`ot_new_master`) or a first-time write/control function (`ot_new_write`) is reported. Restart, stop, listen-only and communication-control commands (`ot_device_stop`), OT traffic to or from the internet (`ot_external`) and Modbus unit-id sweeps (`ot_scan`) are always reported. Findings carry MITRE ATT&CK for ICS techniques.
- **Production readiness (Phase 6).** One-command installer (`scripts/install.sh`) and presets (`sentinelctl preset home|office|ot|enterprise`); over-the-air updates (`sentinelctl update`, verified and health-checked with automatic rollback); reproducible, Sigstore-signed release packages; OS hardening script; minimal non-root container image; AF_PACKET fast-path capture and a compiled Isolation Forest scorer (capture ~25×, decisions ~31× faster on a Pi 5); admin guide, runbooks, troubleshooting, generated API reference, pen-test scope and beta plan.
- **Integrations and operations (Phase 5).** SIEM export (syslog RFC 5424/CEF over UDP/TCP/TLS, signed webhooks, JSON lines, Slack, Teams, email) through a non-blocking dispatcher (`/api/integrations`); threat intelligence from STIX 2.1/TAXII 2.1 and plain lists, updated daily and matched on flows, DNS and TLS (`/api/intel`, `python -m intel`); Suricata `eve.json` as a detector input; new engine metrics, JSON logs, a Grafana operations dashboard and Prometheus alert rules; daily/weekly PDF summaries, per-device history and compliance exports (`/api/reports/summary`, `/api/devices/{ip}/history`, `/api/export/compliance`); encrypted backup and restore (`sentinelctl backup|restore`).
- **Detection quality (Phase 4).** Detectors for port scans, internal host sweeps, brute force, beaconing, exfiltration, new devices, DNS tunnelling and DGA; JA3/JA4 and SNI from TLS ClientHellos; fusion with calibrated confidence, multi-stage confirmation before automatic response, and an explanation on every alert; per-protocol hour-of-day baselines; an Ed25519-signed model registry (shadow, canary, active, rollback, hot reload) with a CPU autoencoder; analyst feedback (`/api/alerts/feedback`) that recalibrates detectors; an evaluation harness (`python -m evaluation.harness`) with a labelled synthetic dataset and a CIC-IDS2017 loader. APIs: `/api/models`, `/api/models/{name}/{version}/stage`, `/api/models/{name}/rollback`, `/api/eval/latest`.
- **Enforcement you can trust (Phase 3).** Protected hosts (gateway, DNS, DHCP, the appliance, management hosts) can never be blocked; quarantine (only DNS, DHCP and a `/quarantined` page) and per-source rate limiting; inline bridge rules; a graduated playbook (alert → rate-limit → block → quarantine) with escalation and an Operator approval gate; MAC-based device identity with vendor and DHCP fingerprints; response policy as versioned YAML with validation, dry-run diff and history; a fail-open watchdog. New APIs under `/api/firewall/{quarantine,ratelimit,release,restrictions}`, `/api/playbook/pending`, `/api/policy`, `/api/enforcement/protected`, `/api/devices/identity`; CLI `python -m enforcement`. Real-kernel test: `tests/firewall_netns/run_enforcement_netns.sh`.
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
