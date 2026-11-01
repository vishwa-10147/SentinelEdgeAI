"""Send three alerts through the real sinks (JSON lines, syslog RFC 5424 and CEF over TCP), then find them
in Elasticsearch. Run by tests/live/run_elastic.sh."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
import requests  # noqa: E402
from integrations import sinks  # noqa: E402

ES, JSONL = sys.argv[1], sys.argv[2]
run = str(int(time.time()))
alerts = [{'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'initiator_ip': '10.0.0.66', 'responder_ip': '10.0.0.5',
           'protocol': 'TCP', 'final_risk_score': 82, 'severity': 'CRITICAL', 'attack_type': f'port_scan_{run}_{n}',
           'confidence': 0.91, 'mitre_technique_id': 'T1046', 'explanation': [f'400 ports probed (live test {run})']}
          for n in ('jsonl', 'rfc5424', 'cef')]
sinks.build({'type': 'jsonl', 'path': JSONL}).send(alerts[0])
sinks.build({'type': 'syslog', 'host': '127.0.0.1', 'port': 5514, 'transport': 'tcp', 'format': 'rfc5424'}).send(alerts[1])
sinks.build({'type': 'syslog', 'host': '127.0.0.1', 'port': 5514, 'transport': 'tcp', 'format': 'cef'}).send(alerts[2])
hits = []
for _ in range(90):                                   # Filebeat scans files every 10 s
    requests.post(f'{ES}/sentineledgeai*/_refresh')
    # Filebeat's template limits default query fields to ECS ones, so match the run id here, not in a query
    r = requests.get(f'{ES}/sentineledgeai*/_search', json={'size': 100, 'query': {'match_all': {}}})
    hits = [h for h in (r.json().get('hits', {}).get('hits', []) if r.ok else []) if run in json.dumps(h['_source'])]
    if len(hits) >= 3:
        break
    time.sleep(2)
for h in hits:
    s = h['_source']
    if 'sentinel' in s:
        print('jsonl  ->', {k: s['sentinel'].get(k) for k in ('initiator_ip', 'attack_type', 'final_risk_score', 'mitre_technique_id')})
    elif 'cef' in s:
        print('cef    ->', {'src': s.get('source', {}).get('ip'), 'dst': s.get('destination', {}).get('ip'),
                            'name': s['cef'].get('name'), 'risk': s['cef'].get('extensions', {}).get('deviceCustomNumber1')})
    else:
        print('rfc5424->', s.get('message', '')[:80], '| structured data:', json.dumps(s.get('log', {}).get('syslog', {}).get('structured_data', {}))[:200])
print(f'{len(hits)} of 3 alerts indexed')
sys.exit(0 if len(hits) == 3 else 1)
