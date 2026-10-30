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
* **Throttled timeout scan**: the expired-flow scan walks every active flow; it now runs once per second instead of per packet.

What this means: a Pi 5 sensor keeps up with roughly 100k packets/s of typical traffic (~0.5–1 Gb/s at average packet sizes) and scores a few thousand finished flows per second. Very busy links (sustained 1 Gb/s of small packets) should use the Jetson brain for scoring, or put a Suricata/Zeek front end on the sensor. A sustained-load test on a real mirror port is part of the beta programme.
