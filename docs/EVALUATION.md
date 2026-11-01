# Detection evaluation

How well the flow detectors find real attacks, measured on public data with the evaluation harness (`python -m evaluation.harness`). Numbers are from **v2.9 on a Raspberry Pi 5** (2026-10-31).

## CIC-IDS2017 (Canadian Institute for Cybersecurity)

Four capture days whose attacks the flow detectors cover. The data is the *TrafficLabelling* variant (`GeneratedLabelledFlows.zip`, which has IP addresses and timestamps). The *MachineLearningCVE* variant has neither, so the loader refuses it.

| Day | Attack (CIC label → our class) | Detected | Time to detect | False positives per benign flow | Benign sources alerted |
|---|---|---|---|---|---|
| Tuesday | FTP-/SSH-Patator → brute force | 1/1 | 114 s | 0.041% | 114 / 7,191 (1.6%) |
| Friday afternoon | PortScan → port scan | 1/1 | under 1 min after the scan starts (see note 2) | 0.024% | 17 / 3,666 (0.5%) |
| Thursday afternoon | Infiltration → compromised host | 1/1 | 846 s | 0.049% | 28 / 5,100 (0.5%) |
| Friday morning | Bot (Ares) → beaconing | 4/8 hosts | median 67 min | 0.021% | 14 / 4,456 (0.3%) |

Decisions take 0.04 ms (p50) and 0.2 ms (p99) per flow on the Pi.

### How to read these numbers

1. **Detected:** a finding of the matching class from the attacking source, after the attack started. For *Infiltration*, the victim's later behaviour counts: port scan, host sweep, beaconing, exfiltration or a threat-intel hit.
2. **PortScan delay.** CIC labels an ordinary port-80 flow from the attacker as "PortScan" at 13:05, and that label is what sets the attack start. The actual scan (about 1,000 ports in 10 minutes) begins at 14:50, and the first finding comes at 14:50:42. The harness reports 6,337 s; the meaningful figure is under a minute.
3. **Timestamps.** The CSV timestamps have minute resolution and a 12-hour clock without AM/PM. The loader therefore reads hours 1–7 as afternoon (the capture ran 08:00–17:00), and spreads each minute's flows evenly over that minute in file order. This is an approximation. It especially hurts **beaconing**, which depends on sub-minute regularity, and is the main reason only 4 of 8 bots are found. On live traffic the engine has exact packet times.
4. **False positives** are findings for sources that never attack. Per flow they are rare (0.02–0.05%). Per source, 0.3–1.6% of benign hosts raise at least one finding over a whole day; most are low-severity `new_device` and single-signal findings. Automatic response needs a *confirmed* finding (confidence ≥ 0.8 with two signals, a repeat, or a high-precision detector), and analyst false-positive labels recalibrate each detector.
5. Not covered by flow detectors and so not evaluated here: DoS/DDoS (Wednesday, Friday afternoon: volume, handled by rate limits and the anomaly models) and web attacks (Thursday morning: they need payload inspection, i.e. Suricata as an input).

### Reproduce

The data comes from the public CIC-IDS2017 release ([UNB](https://www.unb.ca/cic/datasets/ids-2017.html)). We used the Hugging Face mirror `bencorn/CICIDS2017` (`csvs/GeneratedLabelledFlows.zip`, SHA-256 `7bdbef286f8893f3…`, matching the mirror's LFS record).

```bash
unzip GeneratedLabelledFlows.zip
python -m evaluation.harness --cicids "TrafficLabelling /Tuesday-WorkingHours.pcap_ISCX.csv"
```

Reports are written to `reports/eval/`. The latest one is shown in **Operations → Models & evaluation** and used as compliance evidence.

## Synthetic set

`python -m evaluation.harness` without arguments replays a labelled synthetic network: 42 attacks across 8 classes and 73,000 events. Every attack is detected, with no false positives. It is a regression test for the detectors rather than evidence of real-world accuracy, which is what the CIC numbers above are for.

## Same traffic as Suricata (lab capture)

`python -m evaluation.lab_pcap lab.pcap` builds a reproducible two-hour capture (117,370 packets, seed 11): five office machines browsing over TLS 1.3, resolving names and using a file server, plus eleven attacks. It is built packet by packet with real TCP handshakes, acknowledgements, sequence numbers and checksums, a real ClientHello, DNS, HTTP and Kerberos. Both systems read the same file:

* this engine: `python -m evaluation.pcap lab.pcap --truth lab.truth.json --suricata eve.json`. It replays the capture in packet time through the same flow table and per-packet dispatch (`detection/packets.py`) as the live engine; the ML models are left out, as in the dataset harness;
* Suricata 7.0.17 with the Emerging Threats Open ruleset (53,307 rules enabled, default configuration, 2026-11-01): `suricata -r lab.pcap -k none`.

| Attack | This engine | Suricata + ET Open |
|---|---|---|
| Port scan (400 ports) | detected, 1 s | – |
| Host sweep (port 445 on 100 hosts) | detected, 3 s | – |
| SSH password guessing (60 sessions, internal) | detected, 20 s | – |
| HTTPS beaconing every 60 s (1% jitter) | detected, 7 min | – |
| Jittered check-ins of constant size (±50% timing) | detected, 10 min (session rhythm) | – |
| DNS tunnelling (150 TXT queries) | detected, 15 s | – |
| Kerberoasting (40 service-ticket requests in 30 s) | detected, 22 s | – |
| 8 MB upload to a new internet host | detected, 4 s | – |
| PowerShell download over plain HTTP | detected, at once | detected, at once (3 ET INFO rules) |
| Log4Shell attempt from the internet | – | detected, at once (4 ET EXPLOIT/HUNTING rules) |
| SQL injection (sqlmap) from the internet | – | detected, at once (2 rules) |
| **Total** | **9 / 11** | **3 / 11** |
| Benign machines alerted on | 0 | 0 |

Suricata also raised 450 protocol-anomaly events (`SURICATA ...`: malformed SMB and TLS records in the synthetic traffic); they are not counted as detections either way.

**How to read this.** The capture is synthetic and was written by the same project as the detectors, so it is a fair test of *what each system is built to see*, not of accuracy on a real network. The two are complementary: this engine finds behaviour (scans, guessing, beaconing, tunnelling, bursts, exfiltration) without signatures, and Suricata finds known-bad payloads (exploits, attack tools) that behaviour alone does not reveal. That is why Suricata's `eve.json` can be fed into this engine as one more detector (Integrations), and Zeek or Suricata can front busy links. Run both.

## UNSW-NB15 and CIC-IoT2023

* **UNSW-NB15:** `python -m evaluation.harness --unswnb15 UNSW-NB15_1.csv` reads the published per-flow files (no header, 49 columns, real `stime`/`ltime`), parts 1 to 4. Covered categories: Reconnaissance and Analysis (scans) and Backdoor (beaconing); DoS, Exploits, Fuzzers, Generic, Shellcode and Worms need payload signatures and are neither scored as detections nor counted as benign. The training/testing set files have no addresses or times and are refused. **Not run yet:** the dataset is distributed through a web form, not a scriptable download.
* **CIC-IoT2023:** the published CSVs hold per-window features without addresses, which flow detectors cannot use; the loader says so. Evaluate on the dataset's PCAP files with `python -m evaluation.pcap` instead. **Not run yet**, for the same reason.

## Not done yet

- UNSW-NB15 and CIC-IoT2023 runs (loaders ready, data to be fetched by hand).
- A Suricata comparison on real captures (CIC-IDS2017 or UNSW-NB15 PCAPs), beyond the lab capture above.
- GPU models (pending Jetson hardware).
