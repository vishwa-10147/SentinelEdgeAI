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

## Not done yet

- UNSW-NB15 and CIC-IoT2023 (same harness; loaders not written yet).
- A side-by-side Suricata comparison on the same days.
- GPU models (pending Jetson hardware).
