"""SentinelEdgeAI extension SDK (standard library only; available inside the sandbox).

A detector extension reads events and answers with findings:

    from sentinel_sdk import Finding, run

    def on_flow(flow):          # flow: src, dst, sport, dport, proto, duration, forward_bytes, backward_bytes, ts
        if flow['dport'] == 4444:
            return [Finding('metasploit_port', flow['src'], 70, 0.6, 'T1571',
                            f"{flow['src']} connected to {flow['dst']}:4444 (default Metasploit port)")]

    run(on_flow=on_flow)

Handlers: on_flow(flow), on_dns(event: src, qname, nxdomain, ts), on_http(event: src, dst, host, user_agent,
ja4h, method, ts), on_action(event: action, ip, reason, ts; response-action extensions). Each returns a list of
Finding (or None). The appliance checks every finding: its device must be one in the event, severity is capped
at 80 and probability at 0.7, and extension findings never trigger an automatic response on their own.
"""
import json
import sys


class Finding(dict):
    def __init__(self, kind, src, severity, probability, technique, evidence, details=None):
        super().__init__(kind=str(kind), src=str(src), severity=severity, probability=probability,
                         technique=str(technique or ''), evidence=str(evidence), details=details or {})


def run(on_flow=None, on_dns=None, on_http=None, on_action=None):
    handlers = {'flow': on_flow, 'dns': on_dns, 'http': on_http, 'action': on_action}
    sys.stdout.write(json.dumps({'ready': [k for k, v in handlers.items() if v]}) + '\n')
    sys.stdout.flush()
    for line in sys.stdin:
        try:
            msg = json.loads(line)
            handler = handlers.get(msg.get('type'))
            findings = (handler(msg['event']) or []) if handler else []
        except Exception as exc:             # one bad event must not stop the extension
            sys.stdout.write(json.dumps({'id': None, 'error': str(exc)[:200]}) + '\n')
            sys.stdout.flush()
            continue
        if findings:
            sys.stdout.write(json.dumps({'id': msg.get('id'), 'findings': list(findings)}) + '\n')
            sys.stdout.flush()
