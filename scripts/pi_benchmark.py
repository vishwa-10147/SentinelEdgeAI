#!/usr/bin/env python3
"""Small Raspberry Pi benchmark for flow and feature processing.

Use `--pcap sample.pcap` for replay, or omit it for a synthetic benchmark that
does not need packet capture privileges.
"""
import argparse
import json
import os
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from features.feature_extractor import FeatureExtractor
from flow.flow_table import FlowTable


def synthetic_benchmark(packets, output_csv=None):
    table = FlowTable(idle_timeout=30)
    extractor = FeatureExtractor(output_file=output_csv or os.devnull)
    start = time.perf_counter()

    for idx in range(packets):
        src = f"10.0.{(idx // 250) % 255}.{(idx % 250) + 1}"
        dst = f"198.51.100.{(idx % 200) + 1}"
        sport = 10000 + (idx % 40000)
        dport = 443 if idx % 3 else 53
        proto = "TCP" if dport == 443 else "UDP"
        size = 64 + (idx % 1400)
        table.process_packet(src, sport, dst, dport, proto, size)

    flows = table.expire_all()
    for flow in flows:
        extractor.extract(flow)

    elapsed = time.perf_counter() - start
    return {
        "mode": "synthetic",
        "packets": packets,
        "flows": len(flows),
        "elapsed_seconds": round(elapsed, 6),
        "packets_per_second": round(packets / elapsed, 2) if elapsed else 0,
        "flows_per_second": round(len(flows) / elapsed, 2) if elapsed else 0,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--pcap", help="Replay this PCAP instead of synthetic packets")
    parser.add_argument("--packets", type=int, default=10000, help="Synthetic packet count")
    parser.add_argument("--output-csv", help="Optional feature CSV output path")
    args = parser.parse_args()

    if args.pcap:
        from scripts.replay_pcap import replay_pcap

        result = replay_pcap(args.pcap, output_csv=args.output_csv)
        result.pop("features", None)
        result["mode"] = "pcap"
    else:
        result = synthetic_benchmark(args.packets, output_csv=args.output_csv)

    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
