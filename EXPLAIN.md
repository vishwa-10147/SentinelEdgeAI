# How SentinelEdgeAI Works

This document explains SentinelEdgeAI in plain language — first the big picture, then each step in more detail, then a full example of an attack being caught. You do not need a security background to follow it.

Status legend: ✅ works today · 🟡 partial · 🔜 planned (see [PLAN.md](PLAN.md))

---

## 1. The idea in one minute

Every device on a network has habits. A printer talks to a few laptops. A camera sends video to one recorder. An accounting PC uses the internet during office hours. When a device is hacked, its habits change: it suddenly scans other machines, connects to strange servers at 3 a.m., or uploads gigabytes of data.

SentinelEdgeAI is a small box that:

1. **Watches** all network traffic (who talks to whom, how much, how often) — never the content.
2. **Learns** each device's normal habits.
3. **Spots** behaviour that does not fit, using statistics and AI.
4. **Explains** what it saw and how dangerous it looks (a risk score of 0–100).
5. **Responds** — it alerts you, and if you allow it, blocks or isolates the device automatically, always in a reversible way.

All of this happens inside the building. Nothing is sent to the cloud.

---

## 2. The two devices

| | Raspberry Pi 5 — the **Sensor** | Jetson Orin Nano — the **Brain** |
|---|---|---|
| Think of it as | The eyes and hands | The mind and the control room |
| Does | Captures traffic, turns packets into summaries, carries out blocks | Runs all AI models, decides risk, stores history, hosts the website, manages users |
| Why this device | Cheap, low-power, good network I/O | Has a GPU for fast AI |
| If the other one fails | Keeps basic detection running, saves data to disk, never blocks the network by mistake | Shows the sensor as offline and raises an alert |

> **Today (v1.1)** the whole system runs on one device (normally the Pi), and the Jetson link is still being built. The "Lite" profile — one Pi only — will remain available for small sites.

**What gets installed?**
* On the **Pi:** the sensor and enforcer software (Python services managed by systemd that start on boot).
* On the **Jetson:** the brain software — AI models, database, API and the web console.
* On **your computer:** nothing. You open the console in a normal web browser over HTTPS.

---

## 3. Where the box sits on the network

**Passive mode (start here).** Your switch sends a *copy* of all traffic to the Pi through a "mirror port". The Pi sees everything but is not in the path, so if it crashes the network does not notice. It can alert, and it can block traffic to and from itself, but it cannot stop traffic between other machines.

```
Internet ── Router ── Switch ──── PCs, cameras, printers …
                        │ (mirror copy)
                        └──── Pi Sensor ── Jetson Brain
```

**Inline mode 🔜 (full protection).** Traffic flows *through* the Pi, which has two network ports and acts like a smart cable. Now it can block or quarantine any device. A bypass makes sure traffic keeps flowing even if the Pi loses power.

```
Internet ── Router ── [WAN] Pi Sensor [LAN] ── Switch ── devices
                                 │
                            Jetson Brain
```

---

## 4. The pipeline, step by step

```
 packets → flows → features → detectors → risk score → decision → response
                                                 └──────────► dashboard, alerts, reports
```

### Step 1 — Capture ✅ (`capture/sniffer.py`)
The sensor reads packets from the network card. It looks only at headers — addresses, ports, sizes, timing, TCP flags. It does **not** store message contents.

### Step 2 — Build flows ✅ (`flow/flow_table.py`)
Packets are grouped into **flows**: one conversation between two endpoints, identified by the 5-tuple *(source IP, destination IP, source port, destination port, protocol)*. A flow ends after 30 seconds of silence (`flow.idle_timeout` in `config.yaml`). The table holds at most 10,000 open flows so memory stays bounded.

### Step 3 — Extract features ✅ (`features/feature_extractor.py`)
Each finished flow becomes a row of numbers that describe its *shape*: bytes and packets in each direction, duration, packets per second, average packet size, time between packets, TCP flag counts, and so on. Numbers like these are what AI models can learn from.

### Step 4 — Detect ✅ / 🔜 (`detection/`)
Several independent detectors look at each flow. Using several is deliberate: each one catches different things, and agreement between them raises confidence.

| Detector | Question it answers | Status |
|---|---|---|
| **Adaptive baseline + Z-score** (`adaptive_baseline.py`, `anomaly_engine.py`) | "Is this flow unusually large, fast or long *for this device and protocol*?" It learns from the last 500 flows and stays quiet for the first 50 (warm-up). A Z-score above 3 means "more than 3 standard deviations from normal". | ✅ |
| **Isolation Forest** (`ml_engine.py`) | "Is this flow easy to separate from everything else?" Anomalies are rare and different, so the algorithm isolates them in few steps. Needs no labelled attack data. | ✅ |
| **Behavioural fingerprint and drift** (`behavioral_fingerprint.py`) | "Is this device behaving differently from its own long-term profile — new ports, new peers, different volumes?" | ✅ |
| **Attack classifier** (`attack_classifier.py`) | "What kind of attack does this look like?" (exfiltration, flood, port scan, suspicious long session) | 🟡 simple rules |
| **Protocol detectors** | Port scans, brute force, DNS tunnelling, beaconing, new rogue devices | 🔜 |
| **GPU deep models on the Jetson** | Autoencoder (subtle anomalies), sequence model (multi-step attacks over time), graph model (lateral movement between devices) | 🔜 |

### Step 5 — Risk score ✅ (`detection/risk_engine.py`)
Detector outputs are combined into one **risk score from 0 to 100**:

| Score | Severity | Default meaning |
|---|---|---|
| 0–24 | Normal | Logged only |
| 25–49 | Medium | Shown on the dashboard |
| 50–74 | High | Alert raised; block if policy allows |
| 75–100 | Critical | Alert; block (quarantine 🔜) if policy allows |

🔜 Each alert will also get a **confidence** value (how sure the system is) and a plain-language **explanation**, and strong actions will need **multi-stage confirmation**: the same device must look bad repeatedly or across several detectors before it is blocked.

### Step 6 — Map to MITRE ATT&CK ✅ (`detection/mitre_mapper.py`)
Each alert is labelled with the matching technique from MITRE ATT&CK — the industry's shared catalogue of attacker behaviour — such as *T1595 Active Scanning* for a port scan. This lets security professionals and other tools understand the alert immediately.

### Step 7 — Decide and respond ✅ / 🔜 (`core/firewall.py`)
The firewall policy decides what happens:

* **Response mode `monitor`** (default) or **`alert`**: record and alert only.
* **Response mode `auto_block`:** block automatically when risk ≥ `auto_block_min_risk` (default 75).
* Every block has a **time-to-live** (default 5 minutes, maximum 24 hours) and then expires on its own.
* **Whitelisted** addresses are never blocked.
* **Dry-run** (`FIREWALL_DRY_RUN=1`, the default) records what *would* have been blocked without touching the network — ideal for the first weeks.

Blocks are applied with the Linux firewall (nftables or iptables). 🔜 In inline mode, the system will add graduated responses: rate-limit → block → quarantine, where quarantine lets a device reach only DNS/DHCP and a "you are quarantined" page.

### Step 8 — Store ✅ (`core/storage_sqlite.py`, `core/storage_postgres.py`)
Alerts, flows, device profiles and firewall actions are saved to a database — SQLite on a single device, PostgreSQL for larger setups. Old data is cleaned up automatically.

### Step 9 — Show and share ✅ / 🔜
* **Web console** ✅ (`frontend/`): live network map coloured by risk, device detail panels with block/whitelist buttons, analytics, firewall activity, and a presenter demo.
* **Live stream** ✅: the browser receives new alerts instantly over a WebSocket.
* **Metrics** ✅: Prometheus/Grafana graphs of flows, alerts and health.
* **SIEM export** 🔜: send alerts to Splunk, ELK, Microsoft Sentinel, syslog, Slack/Teams.

---

## 5. Safety nets — why it will not break your network

| Safety net | What it does |
|---|---|
| Dry-run by default | Nothing is blocked until an administrator turns enforcement on |
| Monitor mode by default | Even with enforcement on, auto-blocking needs a policy change |
| Whitelist | Critical machines can never be blocked (gateway/DNS auto-detected 🔜) |
| Time-to-live | Blocks expire by themselves |
| One-click rollback | Removes every rule SentinelEdgeAI added |
| Rollback guard | A systemd timer removes all rules automatically if the service becomes unhealthy |
| Signed AI models | The system refuses to load a model that was tampered with |
| Fail-open 🔜 | In inline mode, a crash lets traffic through instead of cutting it off |
| Approval gates 🔜 | High-impact actions can require a human Operator to approve them |

---

## 6. Worked example — a hacked camera

1. **Normal life.** For two weeks, camera `192.168.1.40` sends about 2 Mbit/s of video to the recorder `192.168.1.10`, and otherwise only talks to the time server and its update server. Its baseline and fingerprint learn this.
2. **Compromise.** An attacker exploits the camera's old firmware.
3. **Reconnaissance.** The camera starts connecting to ports 22, 23, 445 and 3389 on dozens of local machines.
   * The **fingerprint** detector sees brand-new peers and ports → behavioural deviation.
   * The **Z-score** detector sees flow counts far outside normal.
   * The **classifier** labels it `POSSIBLE_PORT_SCAN` → MITRE *T1595 Active Scanning*.
4. **Risk.** The combined score crosses 75 → **Critical**.
5. **Alert.** The camera turns red on the network map; the alert lists its reasons (`UNUSUAL_DESTINATION`, `UNUSUAL_DESTINATION_PORT`, packet-rate deviation) and the MITRE technique. (🔜 A fuller explanation, e.g. "37 new hosts, ports 22/23/445/3389; normal peers: 3", comes with Phase 4.)
6. **Response.** With `auto_block` enabled, the camera is blocked for 5 minutes (TTL). Each new critical alert re-applies the block and restarts its timer. 🔜 In inline mode it is quarantined instead, so it can no longer reach any other device.
7. **Human follow-up.** An operator opens the device panel, sees the timeline, makes the block permanent, and schedules a firmware reset. If it was a false alarm, one click unblocks it — and 🔜 that feedback improves the model.

---

## 7. How the AI learns

* **No labelled attack data needed.** The models learn what *normal* looks like on *your* network and flag what does not fit. That is why the first period (warm-up) is quieter and why running in monitor mode first is recommended.
* **Offline training** ✅: `scripts/train_model.py` trains the Isolation Forest from stored flows and `scripts/sign_model.py` signs it.
* **Model lifecycle** 🔜: new models will first run in *shadow mode* (scoring without acting), then be promoted after review, with one-click rollback.
* **Feedback** 🔜: analysts marking alerts as real or false will be used in the next training round.

---

## 8. Glossary

| Term | Meaning |
|---|---|
| **Flow** | One conversation between two endpoints, summarised as numbers |
| **Feature** | A number describing a flow (bytes, duration, rate, …) |
| **Baseline** | What is normal for a device, learned from its history |
| **Z-score** | How many standard deviations a value is from the average |
| **Isolation Forest** | An ML method that finds rare, unusual data points |
| **Drift** | A slow, lasting change in a device's behaviour |
| **Risk score** | 0–100 summary of how dangerous an event looks |
| **MITRE ATT&CK** | Public catalogue of attacker techniques |
| **TTL** | Time-to-live — how long a block lasts before it expires |
| **Dry-run** | Record what would happen without doing it |
| **Inline / passive** | Traffic flows through the box / the box watches a copy |
| **Quarantine** | Isolating a device so it can only reach minimal services |
| **mTLS** | Mutual TLS — both sides prove their identity with certificates |
| **SIEM** | Security Information and Event Management — a central alert/log system |
| **NDR** | Network Detection and Response |

---

## 9. Frequently asked questions

**Does it read my emails or web pages?** No. It looks only at traffic metadata (who, when, how much), never contents. Encrypted traffic stays encrypted.

**Does it need the internet?** No. Internet access is only needed if you choose to download updates or threat-intelligence feeds.

**Will it slow down my network?** In passive mode, not at all. In inline mode the Pi forwards traffic; published throughput numbers will come with v2.0.

**What if it blocks the wrong device?** Blocks expire automatically, can be undone with one click, and whitelisted machines are never blocked. Start in dry-run and monitor mode to tune it first.

**Can it replace my antivirus or firewall?** No. It adds the network layer: it sees what endpoints and perimeter firewalls miss, such as a hacked camera talking to a PC inside the network.

**How many devices can it watch?** It is designed for small and medium networks (tens to a few hundred devices per sensor). Larger networks use several sensors with one brain 🔜.
