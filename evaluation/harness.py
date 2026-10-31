"""Replay a labelled dataset through the detection pipeline and measure it.

    python -m evaluation.harness                      # synthetic set, writes reports/eval/
    python -m evaluation.harness --cicids path.csv    # a CIC-IDS2017 CSV (flow detectors only)

Metrics:
  detection rate  per attack class: share of attack instances with a matching
                  finding (same class, same source) after the attack started
  false positives share of benign events that produced an alert-level result
                  (fused risk >= 50) and share of benign sources ever alerted on
  latency         processing time per event (p50 / p99) and detection delay
"""
import argparse
import csv
import json
import os
import statistics
import time
from collections import defaultdict
from datetime import datetime

from detection.detectors import BeaconingDetector, BruteForceDetector, ExfiltrationDetector, PortScanDetector
from detection.pipeline import DetectionPipeline
from evaluation import synthetic

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ALERT_RISK = 50
CLASS_ALIASES = {'host_sweep': {'host_sweep', 'port_scan'}, 'port_scan': {'port_scan', 'host_sweep'},
                 # a compromised internal host: any compromise behaviour from it counts
                 'infiltration': {'port_scan', 'host_sweep', 'beaconing', 'exfiltration', 'threat_intel', 'tls_known_bad'}}


class SimClock:
    def __init__(self):
        self.now = synthetic.BASE

    def __call__(self):
        return self.now


def evaluate(events, truth):
    clock = SimClock()
    pipe = DetectionPipeline(clock=clock, models=False)
    first_hit = {}
    benign_events = benign_alerts = 0
    benign_sources, alerted_benign_sources = set(), set()
    attacker_sources = {t['src'] for t in truth}
    timings = []
    by_src_truth = defaultdict(list)
    for t in truth:
        by_src_truth[t['src']].append(t)

    for ev in events:
        ts = ev['record']['ts'] if ev['type'] == 'flow' else ev['ts']
        clock.now = ts
        t0 = time.perf_counter()
        if ev['type'] == 'flow':
            fused = pipe.observe_flow(dict(ev['record']))
            src, new = ev['record']['src'], fused['new_findings']
            risk = fused['risk']
        else:
            new = [f.as_dict() for f in pipe.observe_dns(ev['src'], ev['qname'], ev['nx'], ts)]
            src = ev['src']
            risk = max([f['severity'] for f in new], default=0)
        timings.append(time.perf_counter() - t0)
        for f in new:
            for t in by_src_truth.get(f['src'], ()):
                if t['id'] not in first_hit and ts >= t['start'] and \
                        f['kind'] in CLASS_ALIASES.get(t['kind'], {t['kind']}):
                    first_hit[t['id']] = ts
        if ev['label'] == 'benign':
            benign_events += 1
            if src not in attacker_sources:
                benign_sources.add(src)
            if risk >= ALERT_RISK and new:
                benign_alerts += 1
                if src not in attacker_sources:
                    alerted_benign_sources.add(src)

    per_class = defaultdict(lambda: {'instances': 0, 'detected': 0, 'delays': []})
    for t in truth:
        c = per_class[t['kind']]
        c['instances'] += 1
        if t['id'] in first_hit:
            c['detected'] += 1
            c['delays'].append(first_hit[t['id']] - t['start'])
    classes = {}
    for kind, c in sorted(per_class.items()):
        classes[kind] = {'instances': c['instances'], 'detected': c['detected'],
                         'detection_rate': round(c['detected'] / c['instances'], 3),
                         'median_delay_s': round(statistics.median(c['delays']), 1) if c['delays'] else None}
    total = sum(c['instances'] for c in per_class.values())
    detected = sum(c['detected'] for c in per_class.values())
    timings.sort()
    return {
        'events': len(events),
        'attack_instances': total,
        'detection_rate': round(detected / total, 3) if total else None,
        'classes': classes,
        'benign_events': benign_events,
        'false_positive_rate': round(benign_alerts / benign_events, 5) if benign_events else None,
        'benign_sources': len(benign_sources),
        'benign_sources_alerted': len(alerted_benign_sources),
        'latency_ms': {'p50': round(timings[len(timings) // 2] * 1000, 3),
                       'p99': round(timings[int(len(timings) * 0.99)] * 1000, 3)},
    }


# ---------- CIC-IDS2017 ----------

CIC_LABELS = {'portscan': 'port_scan', 'ftp-patator': 'brute_force', 'ssh-patator': 'brute_force',
              'bot': 'beaconing', 'infiltration': 'infiltration'}


def _cic_time(text):
    """(epoch seconds, has_seconds) of a CIC-IDS2017 timestamp.

    The TrafficLabelling files write 'd/m/Y H:M' (some 'd/m/Y H:M:S') on a 12-hour clock
    without AM/PM; the capture ran during office hours (08:00-17:00), so hours 1-7 are
    afternoon and get 12 hours added.
    """
    text = text.strip()
    for fmt, has_s in (('%d/%m/%Y %H:%M:%S', True), ('%d/%m/%Y %H:%M', False)):
        try:
            t = datetime.strptime(text, fmt)
            break
        except ValueError:
            continue
    else:
        return float(text), True
    if 1 <= t.hour <= 7:
        t = t.replace(hour=t.hour + 12)
    return t.timestamp(), has_s


def load_cicids(path):
    """Flow events from a CIC-IDS2017 'TrafficLabelling' CSV (the variant with IPs and timestamps).

    Timestamps have minute resolution in most files: the flows of one minute are spread evenly
    over that minute in file order, so detectors that look at timing see a plausible sequence
    instead of bursts of identical timestamps. This is an approximation, stated in the report.
    """
    rows, per_minute = [], defaultdict(int)
    with open(path, newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [h.strip() for h in reader.fieldnames]
        if 'Source IP' not in reader.fieldnames:
            raise ValueError('this is the MachineLearningCVE variant (no IPs or timestamps); use TrafficLabelling')
        for row in reader:
            try:
                ts, has_s = _cic_time(row['Timestamp'])
                label = row['Label'].strip().lower()
                rec = {'ts': ts, 'src': row['Source IP'].strip(), 'dst': row['Destination IP'].strip(),
                       'dport': int(float(row['Destination Port'])), 'sport': int(float(row.get('Source Port') or 0)),
                       'proto': {'6': 'TCP', '17': 'UDP'}.get(row.get('Protocol', '').strip(), 'OTHER'),
                       'duration': float(row['Flow Duration']) / 1e6,
                       'forward_bytes': int(float(row['Total Length of Fwd Packets'])),
                       'backward_bytes': int(float(row['Total Length of Bwd Packets']))}
            except (KeyError, ValueError, TypeError):
                continue
            slot = None if has_s else int(ts)
            index = per_minute[slot] if slot is not None else 0
            if slot is not None:
                per_minute[slot] += 1
            rows.append((rec, label, slot, index))
    events, truth, seen = [], [], {}
    for rec, label, slot, index in rows:
        if slot is not None:
            rec['ts'] = slot + 60.0 * index / per_minute[slot]
        kind = CIC_LABELS.get(label.split(' ')[0]) if label != 'benign' else None
        if label == 'benign' or kind is None:
            events.append({'type': 'flow', 'label': 'benign' if label == 'benign' else label, 'attack': None,
                           'record': rec})
            continue
        key = (kind, rec['src'])
        if key not in seen:
            seen[key] = f'{kind}-{len(truth)}'
            truth.append({'id': seen[key], 'kind': kind, 'src': rec['src'], 'start': rec['ts']})
        else:
            t = next(x for x in truth if x['id'] == seen[key])
            t['start'] = min(t['start'], rec['ts'])
        events.append({'type': 'flow', 'label': kind, 'attack': seen[key], 'record': rec})
    events.sort(key=lambda e: e['record']['ts'])
    return events, truth


# ---------- UNSW-NB15 ----------

UNSW_LABELS = {'reconnaissance': 'port_scan', 'analysis': 'port_scan',
               'backdoors': 'beaconing', 'worms': 'beaconing',
               'exploits': 'brute_force'}


def _unsw_time(index, per_second=10.0):
    """Synthetic timestamp for UNSW-NB15 rows, which ship without timestamps.

    Rows are spaced `per_second` apart starting at the harness clock base so the
    pipeline sees a plausible sequence instead of identical timestamps.
    """
    return synthetic.BASE + index * per_second


def load_unswnb15(path):
    """Flow events from a UNSW-NB15 CSV.

    Columns used: srcip, dstip, sport, dsport, proto, dur, sbytes, dbytes, attack_cat, label.
    The standard release has no timestamps, so rows are spaced 10s apart in file order.
    Attack categories our flow detectors can cover are mapped to detector classes;
    the rest (DoS, fuzzers, generic, shellcode) are not covered and count as benign
    events for false-positive purposes, matching the CIC-IDS2017 treatment of uncovered attacks.
    """
    rows = []
    with open(path, newline='', encoding='utf-8', errors='ignore') as f:
        reader = csv.DictReader(f)
        reader.fieldnames = [h.strip() for h in reader.fieldnames]
        required = {'srcip', 'dstip', 'sport', 'dsport', 'proto', 'dur', 'sbytes', 'dbytes',
                    'attack_cat', 'label'}
        missing = required - set(reader.fieldnames)
        if missing:
            raise ValueError(f'UNSW-NB15 CSV missing columns: {sorted(missing)}')
        for index, row in enumerate(reader):
            try:
                rec = {'ts': _unsw_time(index), 'src': row['srcip'].strip(), 'dst': row['dstip'].strip(),
                       'dport': int(float(row['dsport'])), 'sport': int(float(row.get('sport') or 0)),
                       'proto': str(row.get('proto', '')).strip().upper() or 'OTHER',
                       'duration': float(row['dur']), 'forward_bytes': int(float(row['sbytes'])),
                       'backward_bytes': int(float(row['dbytes']))}
            except (KeyError, ValueError, TypeError):
                continue
            attack_cat = str(row.get('attack_cat', '')).strip().lower()
            label = str(row.get('label', '')).strip()
            if attack_cat == 'normal' or label == '0':
                rows.append((rec, 'benign', None))
                continue
            kind = UNSW_LABELS.get(attack_cat)
            if kind is None:
                rows.append((rec, attack_cat, None))
                continue
            rows.append((rec, kind, kind))
    events, truth, seen = [], [], {}
    for rec, label, kind in rows:
        if kind is None:
            events.append({'type': 'flow', 'label': label, 'attack': None, 'record': rec})
            continue
        key = (kind, rec['src'])
        if key not in seen:
            seen[key] = f'{kind}-{len(truth)}'
            truth.append({'id': seen[key], 'kind': kind, 'src': rec['src'], 'start': rec['ts']})
        else:
            t = next(x for x in truth if x['id'] == seen[key])
            t['start'] = min(t['start'], rec['ts'])
        events.append({'type': 'flow', 'label': kind, 'attack': seen[key], 'record': rec})
    events.sort(key=lambda e: e['record']['ts'])
    return events, truth


def write_report(result, name):
    out_dir = os.path.join(ROOT, 'reports', 'eval')
    os.makedirs(out_dir, exist_ok=True)
    stamp = time.strftime('%Y%m%d-%H%M%S')
    path = os.path.join(out_dir, f'{name}-{stamp}.json')
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
    return path
def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m evaluation.harness')
    parser.add_argument('--cicids', help='CIC-IDS2017 CSV file')
    parser.add_argument('--unswnb15', help='UNSW-NB15 CSV file')
    parser.add_argument('--seed', type=int, default=7)
    parser.add_argument('--hours', type=float, default=6)
    args = parser.parse_args(argv)
    if args.cicids:
        events, truth = load_cicids(args.cicids)
        name = 'cicids-' + os.path.basename(args.cicids).split('.')[0]
    elif args.unswnb15:
        events, truth = load_unswnb15(args.unswnb15)
        name = 'unswnb15-' + os.path.basename(args.unswnb15).split('.')[0]
    else:
        events, truth = synthetic.dataset(args.seed, args.hours)
        name = f'synthetic-seed{args.seed}'
    result = evaluate(events, truth)
    result['dataset'] = name
    print(json.dumps(result, indent=2))
    print(f'report: {write_report(result, name)}')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
