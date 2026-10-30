"""Daily and weekly security summaries, per-device history, compliance exports.

    python -m reporting.summary daily  [--out reports/]   # writes PDF + JSON
    python -m reporting.summary weekly [--out reports/]

The summary covers alerts by severity and type, top sources, MITRE ATT&CK
techniques, enforcement actions, audit activity and audit-chain integrity.
"""
import argparse
import csv
import io
import json
import os
import sys
import time
from collections import Counter
from datetime import datetime, timezone

from reporting.pdf import PDF, text_width

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PERIODS = {'daily': 86400, 'weekly': 7 * 86400}


def _alert_time(alert):
    for key in ('logged_at', 'timestamp'):
        value = alert.get(key)
        if not value:
            continue
        try:
            return datetime.fromisoformat(str(value).replace('Z', '+00:00')).timestamp()
        except ValueError:
            try:
                return time.mktime(time.strptime(str(value)[:19], '%Y-%m-%d %H:%M:%S'))
            except ValueError:
                continue
    return None


def load_alerts(path=None):
    try:
        with open(path or os.path.join(ROOT, 'alerts.json'), 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _risk(a):
    try:
        return int(a.get('final_risk_score') or 0)
    except (TypeError, ValueError):
        return 0


def build(period='daily', now=None, alerts=None):
    now = now or time.time()
    start = now - PERIODS[period]
    alerts = [a for a in (alerts if alerts is not None else load_alerts()) if (_alert_time(a) or 0) >= start]
    sev = Counter(str(a.get('severity') or 'UNKNOWN').upper() for a in alerts)
    types = Counter(a.get('attack_type') or 'anomaly' for a in alerts)
    sources = Counter(a.get('initiator_ip') for a in alerts if a.get('initiator_ip'))
    techniques = Counter(a.get('mitre_technique_id') for a in alerts if a.get('mitre_technique_id'))
    report = {
        'period': period, 'from': start, 'to': now,
        'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'alerts': len(alerts),
        'by_severity': dict(sev), 'by_type': dict(types.most_common(10)),
        'top_sources': [{'ip': ip, 'alerts': n, 'max_risk': max(_risk(a) for a in alerts if a.get('initiator_ip') == ip)}
                        for ip, n in sources.most_common(10)],
        'techniques': dict(techniques.most_common(10)),
        'enforcement': {}, 'audit': {}, 'audit_chain': None,
    }
    try:
        import core.audit as audit
        entries = [e for e in audit.get_log().entries(limit=1000) if e['ts'] >= start]
        report['audit'] = dict(Counter(e['action'] for e in entries))
        report['enforcement'] = dict(Counter(e['action'] for e in entries if e['action'].startswith(
            ('firewall_', 'playbook', 'sensor_command', 'whitelist_'))))
        report['audit_chain'] = audit.get_log().verify()
    except Exception:
        pass
    return report


def to_pdf(report):
    pdf = PDF()
    y = 50

    def line(text, size=10, bold=False, gap=None, x=50, gray=0.0):
        nonlocal y
        if y > 790:
            pdf.add_page()
            y = 50
        pdf.text(x, y, text, size, bold, gray)
        y += gap or size + 6

    fmt = lambda ts: datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M')
    pdf.rect(0, 0, pdf.w, 34, rgb=(0.06, 0.09, 0.16))
    pdf.text(50, 22, 'SentinelEdgeAI', 13, True, 1.0)
    pdf.text(170, 22, f"{report['period'].capitalize()} security summary", 11, False, 0.85)
    y = 60
    line(f"{fmt(report['from'])}  to  {fmt(report['to'])}", 10, gray=0.35, gap=26)

    line('Overview', 13, True)
    cards = [('Alerts', report['alerts']), ('Critical', report['by_severity'].get('CRITICAL', 0)),
             ('High', report['by_severity'].get('HIGH', 0)),
             ('Actions', sum(report['enforcement'].values()) if report['enforcement'] else 0)]
    for i, (label, value) in enumerate(cards):
        x = 50 + i * 125
        pdf.rect(x, y, 115, 46, gray=0.94)
        pdf.text(x + 10, y + 18, label, 9, False, 0.4)
        pdf.text(x + 10, y + 38, str(value), 16, True)
    y += 66

    def table(title, rows, headers, widths):
        nonlocal y
        if not rows:
            return
        line(title, 13, True, gap=20)
        x = 50
        for h, w in zip(headers, widths):
            pdf.text(x, y, h, 9, True, 0.35)
            x += w
        y += 6
        pdf.line(50, y, 545, y)
        y += 14
        for row in rows:
            if y > 790:
                pdf.add_page()
                y = 50
            x = 50
            for cell, w in zip(row, widths):
                s = str(cell)
                while s and text_width(s, 9) > w - 8:
                    s = s[:-2] + '…' if len(s) > 2 else ''
                pdf.text(x, y, s, 9)
                x += w
            y += 15
        y += 12

    def bars(title, counts):
        nonlocal y
        if not counts:
            return
        line(title, 13, True, gap=20)
        top = max(counts.values())
        for name, n in sorted(counts.items(), key=lambda kv: -kv[1]):
            if y > 790:
                pdf.add_page()
                y = 50
            pdf.text(50, y + 9, str(name)[:28], 9)
            pdf.rect(210, y, max(2, 280 * n / top), 11, rgb=(0.0, 0.62, 0.78))
            pdf.text(500, y + 9, str(n), 9, True)
            y += 16
        y += 12

    bars('Alerts by type', report['by_type'])
    table('Top sources', [(s['ip'], s['alerts'], s['max_risk']) for s in report['top_sources']],
          ['Source', 'Alerts', 'Highest risk'], [200, 120, 120])
    table('MITRE ATT&CK techniques', list(report['techniques'].items()), ['Technique', 'Alerts'], [200, 120])
    table('Enforcement and administration', sorted(report['audit'].items(), key=lambda kv: -kv[1]),
          ['Audited action', 'Count'], [260, 120])
    chain = report.get('audit_chain')
    if chain:
        line('Audit log integrity', 13, True, gap=20)
        line(f"{'Intact' if chain['ok'] else 'BROKEN at entry ' + str(chain['first_bad_seq'])}: "
             f"{chain['entries']} entries, head {chain['head'][:16]}", 10)
    pdf.text(50, 820, f"Generated {report['generated_at']} by SentinelEdgeAI", 8, False, 0.5)
    return pdf.output()


def device_history_csv(ip, alerts=None):
    rows = [a for a in (alerts if alerts is not None else load_alerts()) if ip in (a.get('initiator_ip'), a.get('responder_ip'))]
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(['time', 'direction', 'peer', 'protocol', 'risk', 'severity', 'type', 'technique', 'explanation'])
    for a in rows:
        outbound = a.get('initiator_ip') == ip
        w.writerow([a.get('logged_at') or a.get('timestamp'), 'source' if outbound else 'target',
                    a.get('responder_ip') if outbound else a.get('initiator_ip'), a.get('protocol'),
                    a.get('final_risk_score'), a.get('severity'), a.get('attack_type'),
                    a.get('mitre_technique_id'), ' | '.join(a.get('explanation') or [])])
    return buf.getvalue()


def compliance_export(start, end, alerts=None):
    """Alerts and audit entries in [start, end): evidence for auditors."""
    alerts = [a for a in (alerts if alerts is not None else load_alerts()) if start <= (_alert_time(a) or 0) < end]
    audit_entries, chain = [], None
    try:
        import core.audit as audit
        log = audit.get_log()
        before = None
        while True:
            page = log.entries(limit=1000, before=before)
            if not page:
                break
            audit_entries += [e for e in page if start <= e['ts'] < end]
            if page[-1]['ts'] < start:
                break
            before = page[-1]['seq']
        chain = log.verify()
    except Exception:
        pass
    return {'from': start, 'to': end, 'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
            'alerts': alerts, 'audit': sorted(audit_entries, key=lambda e: e['seq']), 'audit_chain': chain}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m reporting.summary')
    parser.add_argument('period', choices=list(PERIODS))
    parser.add_argument('--out', default=os.path.join(ROOT, 'reports'))
    args = parser.parse_args(argv)
    report = build(args.period)
    os.makedirs(args.out, exist_ok=True)
    stamp = time.strftime('%Y%m%d')
    base = os.path.join(args.out, f'security-{args.period}-{stamp}')
    with open(base + '.pdf', 'wb') as f:
        f.write(to_pdf(report))
    with open(base + '.json', 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, default=str)
    print(base + '.pdf')
    return 0


if __name__ == '__main__':
    sys.exit(main())
