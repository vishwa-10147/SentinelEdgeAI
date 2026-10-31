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

> **Today (v2.9)** most installs run everything on one Pi (the "Lite" profile). The sensor/brain split is built and tested, with mutual TLS, signed commands, offline buffering, brain-distributed upgrades and an optional standby brain, but has not yet run on a real Jetson. Several sites can also report to one **fleet** console.

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

**Inline mode (full protection).** Traffic flows *through* the Pi, which has two network ports and acts like a smart cable. Now it can block or quarantine any device. A bypass makes sure traffic keeps flowing even if the Pi loses power.

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

### Step 4 — Detect ✅ (`detection/`)
Several independent detectors look at each flow. Using several is deliberate: each one catches different things, and agreement between them raises confidence.

| Detector | Question it answers | Status |
|---|---|---|
| **Adaptive baseline + Z-score** (`adaptive_baseline.py`, `anomaly_engine.py`) | "Is this flow unusually large, fast or long *for this device and protocol*?" It learns from the last 500 flows and stays quiet for the first 50 (warm-up). A Z-score above 3 means "more than 3 standard deviations from normal". | ✅ |
| **Isolation Forest** (`ml_engine.py`) | "Is this flow easy to separate from everything else?" Anomalies are rare and different, so the algorithm isolates them in few steps. Needs no labelled attack data. | ✅ |
| **Behavioural fingerprint and drift** (`behavioral_fingerprint.py`) | "Is this device behaving differently from its own long-term profile — new ports, new peers, different volumes?" | ✅ |
| **Attack detectors** (`detectors.py`, `dns_analysis.py`, `tls.py`) | Port scans, host sweeps, brute force, beaconing, exfiltration to new places, new devices, DNS tunnelling, DGA domains, known-bad TLS fingerprints | ✅ |
| **Autoencoder** (`autoencoder.py`) | "Can a small neural network that learned normal flows rebuild this one?" If not, it is unusual. Signed, versioned, and trained across sites with federated learning | ✅ |
| **Industrial protocols** (`ot.py`) | Who commands each PLC over Modbus, DNP3, BACnet or OPC UA, and with which functions; restart/stop commands; new masters | ✅ |
| **Threat intelligence** (`intel/`) | Is this address, domain or TLS fingerprint on a feed you trust? | ✅ |
| **GPU deep models on the Jetson** | Sequence model (multi-step attacks over time), graph model (lateral movement between devices) | 🔜 hardware |

### Step 5 — Risk score ✅ (`detection/risk_engine.py`)
Detector outputs are combined into one **risk score from 0 to 100**:

| Score | Severity | Default meaning |
|---|---|---|
| 0–24 | Normal | Logged only |
| 25–49 | Medium | Shown on the dashboard |
| 50–74 | High | Alert raised; block if policy allows |
| 75–100 | Critical | Alert; block, contain or quarantine if policy allows |

Each alert also carries a **confidence** (how sure the system is) and a plain-language **explanation** listing the evidence. Strong actions need **confirmation**: two independent signals, a repeated finding, or one very reliable detector. One odd flow never blocks anything.

### Step 6 — Map to MITRE ATT&CK ✅ (`detection/mitre_mapper.py`)
Each alert is labelled with the matching technique from MITRE ATT&CK — the industry's shared catalogue of attacker behaviour — such as *T1595 Active Scanning* for a port scan. This lets security professionals and other tools understand the alert immediately.

### Step 7 — Decide and respond ✅ (`enforcement/`, `core/firewall.py`)
The firewall policy decides what happens:

* **Response mode `monitor`** (default) or **`alert`**: record and alert only.
* **Response mode `auto_block`:** block automatically when risk ≥ `auto_block_min_risk` (default 75).
* Every block has a **time-to-live** (default 5 minutes, maximum 24 hours) and then expires on its own.
* **Whitelisted** addresses are never blocked.
* **Dry-run** (`FIREWALL_DRY_RUN=1`, the default) records what *would* have been blocked without touching the network — ideal for the first weeks.

Blocks are applied with the Linux firewall (nftables or iptables). On top of that:

* **Graduated playbook:** alert → rate-limit → contain → block → quarantine. A device that keeps misbehaving moves up a step, and steps above a risk threshold wait for an Operator's approval.
* **Containment:** an untrusted device keeps only the peers and ports it normally uses. That's far less disruptive than cutting it off.
* **Quarantine:** the device can reach only DNS, DHCP and a "you are quarantined" page.
* **OT micro-segmentation:** only the machines that normally command a PLC can reach its industrial ports.
* **Response tuning:** it learns which gentle response actually ends each kind of incident, and never goes beyond what the playbook allows.
* **Protected hosts:** the gateway, DNS, DHCP, the appliance and your management machines can never be restricted, whatever the AI thinks.

### Step 8 — Store ✅ (`core/storage_sqlite.py`, `core/storage_postgres.py`)
Alerts, flows, device profiles and firewall actions are saved to a database — SQLite on a single device, PostgreSQL for larger setups. Old data is cleaned up automatically.

### Step 9 — Show and share ✅
* **Web console** ✅ (`frontend/`): live network map coloured by risk, device detail, analytics, firewall activity, **Operations** (approvals, restrictions, policy, sensors, models, compliance), **Trust**, **OT devices**, **Fleet**, users, audit log, and a presenter demo.
* **Live stream** ✅: the browser receives new alerts instantly over a WebSocket.
* **Metrics** ✅: Prometheus/Grafana graphs of flows, alerts and health.
* **SIEM export** ✅: syslog/CEF, signed webhooks and JSON lines for Splunk, ELK and Microsoft Sentinel; Slack, Teams and email.
* **Reports and compliance** ✅: daily and weekly PDF summaries, plus evidence for ISO 27001, IEC 62443 and NIS2.

---

## 5. Safety nets — why it will not break your network

| Safety net | What it does |
|---|---|
| Dry-run by default | Nothing is blocked until an administrator turns enforcement on |
| Monitor mode by default | Even with enforcement on, auto-blocking needs a policy change |
| Protected hosts | The gateway, DNS, DHCP, the appliance and your management machines are found automatically and can never be blocked |
| Time-to-live | Blocks expire by themselves |
| One-click rollback | Removes every rule SentinelEdgeAI added |
| Rollback guard | A systemd timer removes all rules automatically if the service becomes unhealthy |
| Signed AI models | The system refuses to load a model that was tampered with |
| Fail-open | If the engine or API stops while rules are in force, a watchdog removes them all, so a crash lets traffic through instead of cutting it off |
| Approval gates | High-impact actions wait for a human Operator to approve them (by default for the first 30 days, from risk 75) |

---

## 6. Worked example — a hacked camera

1. **Normal life.** For two weeks, camera `192.168.1.40` sends about 2 Mbit/s of video to the recorder `192.168.1.10`, and otherwise only talks to the time server and its update server. Its baseline and fingerprint learn this.
2. **Compromise.** An attacker exploits the camera's old firmware.
3. **Reconnaissance.** The camera starts connecting to ports 22, 23, 445 and 3389 on dozens of local machines.
   * The **fingerprint** detector sees brand-new peers and ports → behavioural deviation.
   * The **Z-score** detector sees flow counts far outside normal.
   * The **classifier** labels it `POSSIBLE_PORT_SCAN` → MITRE *T1595 Active Scanning*.
4. **Risk.** The combined score crosses 75 → **Critical**.
5. **Alert.** The camera turns red on the network map; the alert lists its reasons (`UNUSUAL_DESTINATION`, `UNUSUAL_DESTINATION_PORT`, packet-rate deviation) and the MITRE technique. The explanation also says what was unusual, e.g. "probed 37 new hosts on ports 22/23/445/3389; normal peers: 3", and the camera's trust score drops.
6. **Response.** With `auto_block` enabled, the camera is blocked for 5 minutes (TTL). Each new critical alert re-applies the block and restarts its timer. In inline mode it can instead be contained to the recorder it normally talks to, or quarantined, so it can no longer reach any other device.
7. **Human follow-up.** An operator opens the device panel, sees the timeline, makes the block permanent, and schedules a firmware reset. If it was a false alarm, one click unblocks it, and marking it as a false alarm recalibrates the detector and restores the camera's trust.

---

## 7. How the AI learns

* **No labelled attack data needed.** The models learn what *normal* looks like on *your* network and flag what does not fit. That is why the first period (warm-up) is quieter and why running in monitor mode first is recommended.
* **Offline training** ✅: `scripts/train_model.py` trains the Isolation Forest from stored flows and `scripts/sign_model.py` signs it.
* **Model lifecycle** ✅: new models run first in *shadow mode* (scored, never acted on), then in *canary* mode for a share of devices, then *active*, with one-click rollback. A model whose signature does not match is refused.
* **Feedback** ✅: marking an alert as a real or false alarm recalibrates that detector at once, raises or restores the device's trust score, and teaches response tuning that an alert alone was enough.
* **Federated learning** ✅: several sites can train the autoencoder together. Each one sends only model numbers, never its traffic, and the combined model arrives back as a shadow model.

### What the AI is, and is not

The "AI" is a set of small, classical machine-learning models (an Isolation Forest, a little autoencoder neural network), learned statistics (baselines per device and hour), rules for known attack patterns, and arithmetic that combines them. Each decision takes well under a millisecond on a Raspberry Pi.

There is **no large language model** and nothing that writes text: alert explanations are fixed sentences filled in with the evidence. So it cannot be "talked into" anything, and prompt injection does not apply. The models cannot act on their own, either: every action goes through the playbook, your policy, the protected-host list and the approval gate.

A hacker can try to *evade* it (scanning very slowly), to *poison* what it learns (being present before it is installed), or to *overload* it (a flood of fake addresses). Against the last, every table it keeps has a size limit: under a flood it forgets the oldest entries, tells you it is overloaded, and keeps running instead of running out of memory.

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
| **Containment** | Limiting a device to the peers and ports it normally uses |
| **Trust score** | 0–100 summary of how much a device can be trusted, with the reasons |
| **Shadow model** | A model that is scored but never acted on, to compare before promoting |
| **Federated learning** | Training one model across sites by sharing model updates, not data |
| **Micro-segmentation** | Only allowing the connections each device actually needs |

---

## 9. Frequently asked questions

**Does it read my emails or web pages?** No. It looks only at traffic metadata (who, when, how much), never contents. Encrypted traffic stays encrypted.

**Does it need the internet?** No. Internet access is only needed if you choose to download updates or threat-intelligence feeds.

**Will it slow down my network?** In passive mode, not at all. In inline mode the Pi forwards traffic. Capture handles about 120,000 packets per second (roughly 0.5–1 Gb/s of typical traffic, see docs/PERFORMANCE.md); faster links need the Jetson brain or a bigger box.

**What if it blocks the wrong device?** Blocks expire automatically, can be undone with one click, and whitelisted machines are never blocked. Start in dry-run and monitor mode to tune it first.

**Can it replace my antivirus or firewall?** No. It adds the network layer: it sees what endpoints and perimeter firewalls miss, such as a hacked camera talking to a PC inside the network.

**How many devices can it watch?** It is designed for small and medium networks: tens to a few hundred devices per sensor (it tracks up to 100,000 conversations and 20,000 devices at once). Larger networks use several sensors with one brain, and many sites can share one fleet console.

**Does it use ChatGPT or another chatbot?** No. There is no language model at all; see *What the AI is, and is not* above.

**Can a hacker crash it by flooding it?** Not by running it out of memory any more. Under a flood of fake addresses it stays within its limits, raises one "capture overloaded" alert, and detection is degraded until the flood stops. Stopping the flood itself needs your router or switch, or the inline rate limit.

**Can it help with an audit?** Yes. Operations → Compliance shows which ISO 27001, IEC 62443 and NIS2 controls this appliance can evidence, and exports a PDF. It supports an audit; it is not a certification.
