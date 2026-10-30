#!/usr/bin/env python3
"""Measure the capture and decision path on this machine (Phase 6 performance).

    SENTINEL_MODEL_SIGNING_KEY_FILE=/etc/sentinel/model_signing.key python scripts/benchmark_capture.py

Stages, each measured on synthetic traffic:
  1. frame parsing: scapy vs the AF_PACKET fast path (capture/afpacket.py)
  2. flow-table updates per packet
  3. full decision per finished flow: features + engine (baselines, Isolation
     Forest, risk) + Phase 4 detectors and fusion
Prints JSON; --markdown prints a table for docs/PERFORMANCE.md.
"""
import argparse
import json
import os
import platform
import random
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
sys.path.insert(0, ROOT)


def frames(n, seed=1):
    from scapy.all import Ether, IP, TCP, UDP, Raw, DNS, DNSQR
    rng = random.Random(seed)
    out = []
    for i in range(n):
        r = rng.random()
        ip = IP(src=f'192.168.1.{rng.randint(2, 250)}', dst=f'52.{rng.randint(0, 255)}.{rng.randint(0, 255)}.10')
        if r < 0.85:
            p = Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb') / ip / TCP(sport=rng.randint(32768, 60999), dport=443) / Raw(b'\x17' + b'x' * rng.randint(50, 1400))
        elif r < 0.97:
            p = Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb') / ip / UDP(sport=rng.randint(32768, 60999), dport=443) / Raw(b'q' * 1200)
        else:
            p = Ether(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb') / ip / UDP(sport=50000, dport=53) / DNS(rd=1, qd=DNSQR(qname='example.com'))
        out.append(bytes(p))
    return out


def rate(fn, items):
    t = time.perf_counter()
    for x in items:
        fn(x)
    return len(items) / (time.perf_counter() - t)


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument('--packets', type=int, default=20000)
    parser.add_argument('--flows', type=int, default=2000)
    parser.add_argument('--markdown', action='store_true')
    args = parser.parse_args(argv)
    import logging
    logging.disable(logging.WARNING)

    from scapy.all import Ether, IP, TCP, UDP
    from capture import afpacket
    data = frames(args.packets)

    def scapy_parse(b):
        p = Ether(b)
        if IP in p:
            return p[IP].src, p[IP].dst, (p[TCP].sport if TCP in p else p[UDP].sport if UDP in p else 0)

    results = {'machine': f'{platform.machine()} {platform.processor() or ""}'.strip(),
               'python': platform.python_version()}
    results['scapy_parse_pps'] = round(rate(scapy_parse, data[:5000]))
    results['fast_parse_pps'] = round(rate(afpacket.parse, data))
    slow = sum(1 for b in data if afpacket.parse(b)[6])
    results['slow_path_share'] = round(slow / len(data), 3)
    # effective capture rate: fast path for most packets, scapy for the slow share
    per_pkt = (1 - results['slow_path_share']) / results['fast_parse_pps'] + results['slow_path_share'] / results['scapy_parse_pps']
    results['capture_pps_estimate'] = round(1 / per_pkt)

    from flow.flow_table import FlowTable
    ft = FlowTable(idle_timeout=30)
    parsed = [afpacket.parse(b) for b in data]
    results['flow_table_pps'] = round(rate(lambda p: ft.process_packet(p[0], p[2], p[1], p[3], p[4], p[5]), parsed))
    results['active_flows'] = len(ft.flows)
    t = time.perf_counter()
    ft.check_timeouts()
    results['timeout_scan_ms'] = round((time.perf_counter() - t) * 1000, 2)

    try:
        from capture import sniffer
        from common.protocol import flow_record
        from detection.pipeline import DetectionPipeline
        pipe = DetectionPipeline(models=False)
        ft2 = FlowTable(idle_timeout=0)
        for p in parsed[:args.flows * 3]:
            ft2.process_packet(p[0], p[2], p[1], p[3], p[4], p[5])
        time.sleep(1.1)
        flows = ft2.check_timeouts()[:args.flows]

        def decide(flow):
            feats = sniffer.feature_extractor.extract(flow)
            result = sniffer.sentinel_engine.process_flow(flow, feats)
            pipe.observe_flow(flow_record(flow, result, feats), result)

        n = len(flows)
        t = time.perf_counter()
        for f in flows:
            decide(f)
        elapsed = time.perf_counter() - t
        results['decisions_per_s'] = round(n / elapsed)
        results['decision_ms_avg'] = round(elapsed / n * 1000, 3)
        results['flows_measured'] = n
    except Exception as exc:          # e.g. no model signing key in this environment
        results['decision_error'] = str(exc)[:200]

    if args.markdown:
        print('| Stage | Result |\n|---|---|')
        labels = [('scapy_parse_pps', 'scapy frame parsing', 'packets/s'),
                  ('fast_parse_pps', 'AF_PACKET fast-path parsing', 'packets/s'),
                  ('slow_path_share', 'share of packets needing scapy (DNS, DHCP, TLS hello, ARP)', ''),
                  ('capture_pps_estimate', 'effective capture rate (mixed traffic)', 'packets/s'),
                  ('flow_table_pps', 'flow-table updates', 'packets/s'),
                  ('decisions_per_s', 'full decisions (features + engine + detectors + fusion)', 'flows/s'),
                  ('decision_ms_avg', 'average decision time', 'ms per flow')]
        for key, label, unit in labels:
            if key in results:
                v = results[key]
                print(f"| {label} | {v:,} {unit} |" if isinstance(v, int) else f'| {label} | {v} {unit} |')
    else:
        print(json.dumps(results, indent=2))
    return 0


if __name__ == '__main__':
    sys.exit(main())
