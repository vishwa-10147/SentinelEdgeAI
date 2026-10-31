# Performance

Measured on a **Raspberry Pi 5 (8 GB), Python 3.13**, with `scripts/benchmark_capture.py` (synthetic mixed traffic: 85% TCP/443, 12% UDP, 3% DNS). Reproduce:

```bash
SENTINEL_MODEL_SIGNING_KEY_FILE=/etc/sentinel/model_signing.key .venv/bin/python scripts/benchmark_capture.py --markdown
```

| Stage | Before Phase 6 | Now |
|---|---|---|
| Frame parsing | 4,869 packets/s (scapy) | 511,768 packets/s (AF_PACKET fast path) |
| Effective capture on mixed traffic | ~4,900 packets/s | **~121,000 packets/s** (3.1% of packets still need scapy: DNS, DHCP, TLS ClientHello, ARP) |
| Flow-table updates | — | 573,268 packets/s |
| Expired-flow scan | every packet (12 ms per scan at 20,000 active flows) | once per second |
| Full decision per flow (features + baselines + Isolation Forest + detectors + fusion) | 124 flows/s (8 ms) | **3,843 flows/s (0.26 ms)** |
| Detection pipeline alone (detectors + fusion) | — | p99 0.15 ms per event |

What changed:

* **AF_PACKET capture** (`capture/afpacket.py`): a raw socket with an 8 MB buffer and `struct` header parsing feeds the flow table directly; scapy is used only for packets that need deep inspection. `SENTINEL_CAPTURE=scapy` restores the old path.
* **Compiled Isolation Forest** (`detection/fast_iforest.py`): scikit-learn's per-sample `predict()` spent ~7 ms in joblib dispatch; the fitted forest is flattened into arrays and walked directly. It is verified against scikit-learn at load (identical labels on 3,000 test flows with the production model) and falls back to scikit-learn on any mismatch.
* **Throttled timeout scan**: once per second instead of per packet; since 2.9.2 the table is kept in order of last activity, so the scan stops at the first active flow.

What this means: a Pi 5 sensor keeps up with roughly 100k packets/s of typical traffic (~0.5–1 Gb/s at average packet sizes) and scores a few thousand finished flows per second. Very busy links (sustained 1 Gb/s of small packets) should use the Jetson brain for scoring, or put a Suricata/Zeek front end on the sensor. A sustained-load test on a real mirror port is part of the beta programme.

## Under a flood (2.9.2)

A spoofed-source TCP SYN flood from a second network namespace into the real engine (AF_PACKET capture, firewall in dry run), every packet a new flow. Reproduce with `sudo SENTINEL_MODEL_SIGNING_KEY_FILE=… bash tests/firewall_netns/run_flood_netns.sh 180`.

| | v2.9.1 | v2.9.2 |
|---|---|---|
| Flood rate | 307,000 packets/s | 322,000 packets/s |
| Engine memory | 246 MB → **1,218 MB after 40 s**, still rising | 244 MB → **~460 MB after 180 s**, levelling off |
| Flow table | unbounded | at its cap (100,000), 18.5 million flows evicted |
| Visible to the operator | nothing | one "capture overloaded" alert, `capture` section in the health file, `sentinel_capture` metrics |

Where the memory went before: an unbounded flow table, per-source detector state, and above all one asyncio coroutine per finished flow waiting for space in the scoring queue (tasks, futures and waiters by the tens of thousands). Now finished flows are handed to the scoring loop once per pass and shed when the queue is full, and every per-source structure has a cap.

What a flood still does: detection is degraded while it lasts. Evicted flows are only partly scored (500 per second), and new devices are forgotten sooner. The overload alert says so. The flood traffic itself reaches the appliance's network interface; stopping it upstream (a switch ACL, a firewall, or the inline rate limit) is still needed.

| Setting | Default | Memory at the cap (approx.) |
|---|---|---|
| `SENTINEL_MAX_FLOWS` | 100,000 active flows | ~85 MB (860 bytes per flow) |
| `SENTINEL_MAX_SOURCES` | 20,000 sources in each detector (40,000 source pairs) | ~150 MB in total |
| `SENTINEL_MAX_DEVICES` | 20,000 rows in the device registry | on disk |
