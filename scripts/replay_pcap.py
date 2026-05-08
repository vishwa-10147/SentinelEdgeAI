#!/usr/bin/env python3
"""Replay a PCAP through SentinelEdgeAI flow building and feature extraction.

This intentionally avoids live sniffing so tests and Pi benchmarks can use
repeatable packet captures without raw socket permissions.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from scapy.all import IP, TCP, UDP, rdpcap

from features.feature_extractor import FeatureExtractor
from flow.flow_table import FlowTable


def replay_pcap(path, output_csv=None, limit=None):
    table = FlowTable(idle_timeout=30)
    extractor = FeatureExtractor(output_file=output_csv or os.devnull)
    packet_count = 0
    start = time.perf_counter()

    for packet in rdpcap(str(path)):
        if limit is not None and packet_count >= limit:
            break
        if IP not in packet:
            continue

        ip_layer = packet[IP]
        src_port = 0
        dst_port = 0
        protocol = "OTHER"
        if TCP in packet:
            src_port = int(packet[TCP].sport)
            dst_port = int(packet[TCP].dport)
            protocol = "TCP"
        elif UDP in packet:
            src_port = int(packet[UDP].sport)
            dst_port = int(packet[UDP].dport)
            protocol = "UDP"

        table.process_packet(ip_layer.src, src_port, ip_layer.dst, dst_port, protocol, len(packet))
        packet_count += 1

    flows = table.expire_all()
    features = [extractor.extract(flow) for flow in flows]
    elapsed = time.perf_counter() - start

    return {
        "pcap": str(path),
        "packets": packet_count,
        "flows": len(flows),
        "elapsed_seconds": round(elapsed, 6),
        "packets_per_second": round(packet_count / elapsed, 2) if elapsed else 0,
        "flows_per_second": round(len(flows) / elapsed, 2) if elapsed else 0,
        "features": features,
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("pcap", help="Path to a PCAP file")
    parser.add_argument("--output-csv", help="Optional feature CSV output path")
    parser.add_argument("--limit", type=int, help="Maximum packets to replay")
    args = parser.parse_args()

    result = replay_pcap(Path(args.pcap), output_csv=args.output_csv, limit=args.limit)
    print(json.dumps({k: v for k, v in result.items() if k != "features"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
