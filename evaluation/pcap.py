"""Evaluate on a packet capture, through the same packet path as the live engine, and compare with Suricata.

    python -m evaluation.pcap capture.pcap --truth truth.json [--suricata eve.json]

The capture is replayed in packet time: every packet goes through the flow table and the shared
per-packet dispatch (detection.packets: DNS, TLS, HTTP, SMB/RPC/Kerberos/LDAP, OT), finished flows
through the flow detectors, exactly as capture.sniffer does live. The ML models are left out
(they need a trained baseline), as in evaluation.harness.

truth.json lists the attacks in the capture:
    [{"id": "scan-1", "kind": "port_scan", "src": "10.0.0.66", "start": 1700000000.0}, ...]
`kind` is matched with the same aliases as the dataset harness (a host sweep counts for a scan).

With --suricata, Suricata's eve.json alerts for the same capture (suricata -r capture.pcap) are scored
on the same truth: an attack counts as detected by Suricata when any alert has the attacker as source
or destination after the attack started. Sources that are in no truth entry give each system's
false-positive count (distinct sources alerted on).
"""
import argparse
import json
import os
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone

from common.protocol import flow_record
from detection.packets import dispatch
from detection.pipeline import DetectionPipeline
from evaluation.harness import ALERT_RISK, CLASS_ALIASES, write_report
from features.feature_extractor import FeatureExtractor
from flow.flow_table import FlowTable


class Clock:
    def __init__(self, now=0.0):
        self.now = now

    def __call__(self):
        return self.now


def _flow_findings(pipe, flows, extractor):
    out = []
    for flow in flows:
        record = flow_record(flow, {}, extractor.extract(flow))
        record['ts'] = flow.end_time.timestamp()
        fused = pipe.observe_flow(record)
        out += [(record['ts'], f) for f in fused['new_findings']]
    return out


def replay(path, pipe=None):
    """[(ts, finding dict)] for every finding the engine raises on the capture."""
    from scapy.utils import PcapReader
    clock = Clock()
    pipe = pipe or DetectionPipeline(clock=clock, models=False)
    table, extractor = FlowTable(idle_timeout=30), FeatureExtractor()
    findings, last_scan, packets = [], None, 0
    with PcapReader(path) as reader:
        for pkt in reader:
            ts = float(pkt.time)
            clock.now = ts
            packets += 1
            now = datetime.fromtimestamp(ts, timezone.utc)
            from scapy.layers.inet import IP, TCP, UDP
            if IP not in pkt:
                continue
            findings += [(ts, f.as_dict()) for f in dispatch(pipe, pkt, ts=ts)]
            ip = pkt[IP]
            if TCP in pkt:
                sport, dport, proto = pkt[TCP].sport, pkt[TCP].dport, 'TCP'
            elif UDP in pkt:
                sport, dport, proto = pkt[UDP].sport, pkt[UDP].dport, 'UDP'
            else:
                sport = dport = 0
                proto = 'OTHER'
            table.process_packet(ip.src, sport, ip.dst, dport, proto, len(pkt), now=now)
            if last_scan is None or ts - last_scan >= 1.0:
                last_scan = ts
                findings += _flow_findings(pipe, table.check_timeouts(now=now), extractor)
    end = clock.now
    findings += _flow_findings(pipe, table.expire_all(), extractor)
    return findings, {'packets': packets, 'end': end}


def suricata_alerts(eve_path, anomalies=False):
    """[(ts, src, dst, signature)] from a Suricata eve.json.

    Suricata's own protocol-anomaly events ("SURICATA ..." decoder, stream and app-layer events) say a packet
    looked malformed, not that an attack happened; they are left out unless `anomalies`.
    """
    out = []
    with open(eve_path, encoding='utf-8') as f:
        for line in f:
            try:
                ev = json.loads(line)
            except ValueError:
                continue
            if ev.get('event_type') != 'alert':
                continue
            if not anomalies and str(ev.get('alert', {}).get('signature', '')).startswith('SURICATA '):
                continue
            ts = datetime.fromisoformat(ev['timestamp'].replace('Z', '+00:00')).timestamp()
            out.append((ts, ev.get('src_ip'), ev.get('dest_ip'), ev.get('alert', {}).get('signature', '')))
    return out


def score(truth, engine, suricata=None):
    attackers = {t['src'] for t in truth}
    by_src = defaultdict(list)
    for t in truth:
        by_src[t['src']].append(t)
    hit = {}
    engine_fp = set()
    for ts, f in engine:
        matched = False
        for t in by_src.get(f['src'], ()):
            if ts >= t['start'] - 1 and f['kind'] in CLASS_ALIASES.get(t['kind'], {t['kind']}):
                hit.setdefault(t['id'], ts)
                matched = True
        if not matched and f['src'] not in attackers and f.get('severity', 0) >= ALERT_RISK:
            engine_fp.add(f['src'])
    result = {'attacks': len(truth), 'engine': _summary(truth, hit), 'engine_false_positive_sources': sorted(engine_fp),
              'engine_findings': len(engine)}
    if suricata is not None:
        shit, sfp, sigs = {}, set(), defaultdict(int)
        for ts, src, dst, sig in suricata:
            sigs[sig] += 1
            matched = False
            for t in truth:
                if t['src'] in (src, dst) and ts >= t['start'] - 1:
                    shit.setdefault(t['id'], ts)
                    matched = True
            if not matched:
                sfp.add(src)
        result['suricata'] = _summary(truth, shit)
        result['suricata_false_positive_sources'] = sorted(s for s in sfp if s)
        result['suricata_alerts'] = len(suricata)
        result['suricata_signatures'] = dict(sorted(sigs.items(), key=lambda kv: -kv[1])[:20])
    return result


def _summary(truth, hit):
    per = defaultdict(lambda: {'instances': 0, 'detected': 0, 'delays': []})
    for t in truth:
        c = per[t['kind']]
        c['instances'] += 1
        if t['id'] in hit:
            c['detected'] += 1
            c['delays'].append(max(0.0, hit[t['id']] - t['start']))
    return {k: {'instances': c['instances'], 'detected': c['detected'],
                'median_delay_s': round(statistics.median(c['delays']), 1) if c['delays'] else None}
            for k, c in sorted(per.items())}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m evaluation.pcap', description=__doc__.split('\n')[0])
    parser.add_argument('pcap')
    parser.add_argument('--truth', required=True, help='JSON list of {id, kind, src, start}')
    parser.add_argument('--suricata', help="Suricata eve.json for the same capture")
    parser.add_argument('--name', help='report name (default: the capture file name)')
    args = parser.parse_args(argv)
    with open(args.truth, encoding='utf-8') as f:
        truth = json.load(f)
    findings, info = replay(args.pcap)
    result = score(truth, findings, suricata_alerts(args.suricata) if args.suricata else None)
    if args.suricata:
        result['suricata_anomaly_events'] = len(suricata_alerts(args.suricata, anomalies=True)) - result['suricata_alerts']
    result.update(info)
    kinds = defaultdict(int)
    for _, f in findings:
        kinds[f['kind']] += 1
    result['finding_kinds'] = dict(kinds)
    name = args.name or 'pcap-' + os.path.basename(args.pcap).rsplit('.', 1)[0]
    result['dataset'] = name
    print(json.dumps(result, indent=2))
    print(f'report: {write_report(result, name)}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
