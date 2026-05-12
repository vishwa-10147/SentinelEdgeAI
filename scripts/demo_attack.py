#!/usr/bin/env python3
"""Demo script: simulate an alert and optionally call the local firewall API to block an IP.

Usage:
  python scripts/demo_attack.py --ip 192.0.2.5 [--block]
"""
import os
import json
import time
import argparse
import requests

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ALERTS = os.path.join(ROOT, 'alerts.json')
LIVE_EVENTS = os.path.join(ROOT, 'live_events.jsonl')

def append_alert(alert):
    data = []
    if os.path.exists(ALERTS):
        try:
            with open(ALERTS, 'r') as f:
                data = json.load(f) or []
        except Exception:
            data = []
    data.append(alert)
    with open(ALERTS, 'w') as f:
        json.dump(data, f, indent=2)

def append_event(evt):
    with open(LIVE_EVENTS, 'a') as f:
        f.write(json.dumps(evt) + "\n")

def main():
    p = argparse.ArgumentParser()
    p.add_argument('--ip', required=True)
    p.add_argument('--block', action='store_true')
    args = p.parse_args()

    alert = {
        'src_ip': args.ip,
        'dst_ip': '192.0.2.1',
        'protocol': 'TCP',
        'port': 4444,
        'risk_score': 85,
        'type': 'simulated-attack',
        'reason': 'demo script generated',
        'ts': int(time.time())
    }
    append_alert(alert)

    evt = {'type': 'alert', 'payload': alert}
    append_event(evt)

    print('Wrote demo alert and live event for', args.ip)

    if args.block:
        api_key = os.environ.get('DASHBOARD_API_KEY')
        url = os.environ.get('DASHBOARD_API_URL', 'http://127.0.0.1:9000')
        headers = {}
        if api_key:
            headers['X-API-Key'] = api_key
        try:
            r = requests.post(url + '/api/firewall/block', json={'ip': args.ip, 'ttl': 300, 'reason': 'demo'}, headers=headers, timeout=5)
            print('Firewall API response:', r.status_code, r.text)
        except Exception as e:
            print('Failed to call firewall API:', e)

if __name__ == '__main__':
    main()
