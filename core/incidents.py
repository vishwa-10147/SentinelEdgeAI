"""Incidents (Phase 10): related alerts, devices and responses grouped into one story.

The people this product is for have no analyst. An incident answers four
questions on one screen: what happened (a timeline), which devices are
involved (source, targets), what the appliance already did (blocks,
quarantines, rate limits), and what to do now (a short checklist chosen by
the kinds of detection involved).

Grouping is deterministic and cheap, so it runs on every request:
  * alerts are taken in time order;
  * an alert joins an open incident when it shares an internal device with it
    (its source, or an internal target) and arrives within GAP seconds of the
    incident's last alert; otherwise it starts a new incident;
  * two incidents that come to share a device are merged (an attacker that
    moves from host A to host B stays one story).
External addresses never link incidents: two devices talking to the same CDN
are not related.

Analysts acknowledge or resolve incidents (data/incidents.json, SENTINEL_INCIDENTS);
a resolved incident that gets a new alert reopens.
"""
import ast
import hashlib
import json
import os
import threading
import time
from datetime import datetime

from detection.detectors import is_external

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
GAP = 2 * 3600                      # an alert more than 2 h after the last one starts a new incident
STATUSES = ('open', 'acknowledged', 'resolved')
_lock = threading.Lock()


# ---------------- alert normalisation ----------------

def _ts(value):
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        for fmt in ('%Y-%m-%d %H:%M:%S.%f', '%Y-%m-%d %H:%M:%S', '%Y-%m-%dT%H:%M:%S.%f', '%Y-%m-%dT%H:%M:%S'):
            try:
                return datetime.strptime(value[:26], fmt).timestamp()
            except ValueError:
                continue
        try:
            return float(value)
        except ValueError:
            return None
    return None


def _details(raw):
    """The details column holds the alert dict as JSON or as a Python repr (older engines)."""
    if isinstance(raw, dict):
        return raw
    if not isinstance(raw, str) or not raw:
        return {}
    try:
        value = json.loads(raw)
    except ValueError:
        try:
            value = ast.literal_eval(raw)          # literals only: never executes code
        except (ValueError, SyntaxError, MemoryError, RecursionError):
            return {}
    return value if isinstance(value, dict) else {}


def normalize(alert):
    """One alert (database row or alerts.json entry) as {id, ts, src, dst, kind, risk, ...} or None."""
    if not isinstance(alert, dict):
        return None
    d = dict(_details(alert.get('details')))
    d.update({k: v for k, v in alert.items() if k != 'details' and v is not None})
    src = d.get('initiator_ip') or d.get('src_ip') or d.get('src')
    ts = _ts(d.get('timestamp') or d.get('ts'))
    if not src or ts is None:
        return None
    dst = d.get('responder_ip') or d.get('dst_ip') or d.get('dst')
    risk = d.get('final_risk_score', d.get('score', d.get('final_risk', 0))) or 0
    kind = d.get('attack_type') or 'anomaly'
    explanation = d.get('explanation') or []
    if isinstance(explanation, str):
        explanation = [explanation]
    out = {'ts': ts, 'src': str(src), 'dst': str(dst) if dst else None, 'kind': str(kind),
           'risk': float(risk), 'technique': d.get('mitre_technique_id'), 'protocol': d.get('protocol'),
           'dst_port': d.get('dst_port') or d.get('responder_port'),
           'evidence': [str(e) for e in explanation][:3], 'confidence': d.get('confidence')}
    out['id'] = hashlib.sha256(f'{ts}|{src}|{dst}|{kind}'.encode()).hexdigest()[:12]
    return out


def _internal(ip):
    return bool(ip) and not is_external(ip)


# ---------------- grouping ----------------

def group(alerts, gap=GAP):
    """Incidents (lists of normalised alerts, oldest first) from normalised alerts."""
    incidents = []                 # each: {'alerts': [...], 'devices': set, 'last': ts}
    by_device = {}                 # device -> index of its latest incident
    for a in sorted((a for a in alerts if a), key=lambda a: a['ts']):
        devices = {a['src']} | ({a['dst']} if _internal(a['dst']) else set())
        devices = {d for d in devices if _internal(d)} or {a['src']}
        hits = {by_device[d] for d in devices
                if d in by_device and incidents[by_device[d]] is not None
                and a['ts'] - incidents[by_device[d]]['last'] <= gap}
        if not hits:
            incidents.append({'alerts': [a], 'devices': set(devices), 'last': a['ts']})
            idx = len(incidents) - 1
        else:
            idx = min(hits)
            inc = incidents[idx]
            for other in sorted(hits - {idx}):              # merge incidents that now share a device
                o = incidents[other]
                inc['alerts'] += o['alerts']
                inc['devices'] |= o['devices']
                inc['last'] = max(inc['last'], o['last'])
                incidents[other] = None
                for dev, i in list(by_device.items()):
                    if i == other:
                        by_device[dev] = idx
            inc['alerts'].append(a)
            inc['devices'] |= devices
            inc['last'] = max(inc['last'], a['ts'])
        for d in devices:
            by_device[d] = idx
    out = []
    for inc in incidents:
        if inc is not None:
            inc['alerts'].sort(key=lambda a: a['ts'])
            out.append(inc['alerts'])
    return out


# ---------------- what to do now ----------------

CHECKLISTS = [
    (('port_scan', 'host_sweep', 'scan'), [
        'Find out what {src} is. If it is not an IT scanner or monitoring tool you know, treat it as compromised.',
        'If it is a known scanner, mark these alerts "false positive" so the detector learns.']),
    (('brute', 'password', 'kerberos_burst'), [
        'Check the targets\' login logs for a successful login from {src} after the failures.',
        'If any account logged in, reset its password and end its sessions.',
        'Keep {src} blocked or rate-limited until you know who is behind it.']),
    (('beacon', 'threat_intel', 'tls_known_bad', 'http_known_bad', 'session_rhythm', 'dga', 'dns_tunnel', 'c2'), [
        '{src} is probably infected: it keeps calling out to a suspicious server.',
        'Contain {src} (Operations → Trust → Contain) so it can only reach what it normally does.',
        'Run an anti-malware scan on {src}, or reinstall it if it is a kiosk, camera or other appliance.']),
    (('exfil',), [
        'Find out what data {src} could reach and who owns it; large uploads to new destinations are the signal.',
        'Block the destination if nobody recognises it, and keep the alert evidence for your records.']),
    (('admin_share', 'remote_service', 'remote_task', 'ntlm_fanout', 'lateral_fanout', 'dcsync'), [
        '{src} is using administrator tools on other machines. Ask your IT admin if this was them, right now.',
        'If not: contain {src} and every target listed above, and reset the passwords of any admin account '
        'used from {src}.',
        'For a DCSync alert, assume all domain passwords are exposed: reset the krbtgt password twice and the '
        'admin accounts.']),
    (('ldap_recon', 'ldap_enumeration'), [
        '{src} is mapping Active Directory the way attackers do before Kerberoasting or taking over admin '
        'accounts. Ask your IT admin whether they ran an audit tool (BloodHound, PingCastle) from {src}.',
        'If not: contain {src}, and give the service accounts it could have targeted (those with SPNs, or '
        'without pre-authentication) long new passwords.']),
    (('http_lolbin',), [
        'A Windows tool on {src} (PowerShell or certutil) downloaded something from the internet. Ask its user '
        'or your IT admin whether that was expected; if not, contain {src} and scan it.']),
    (('ldap_cleartext_bind', 'http_basic_auth'), [
        'An application on {src} sends a password in clear text (plain LDAP or HTTP Basic). Switch it to '
        'LDAPS (port 636), StartTLS or HTTPS, then change that account\'s password.']),
    (('ot_',), [
        'Call the person responsible for the controllers listed above before changing anything on the network.',
        'Check on the HMI / engineering station that the controller is in the expected state (running, '
        'correct program).',
        'If {src} is not a known engineering workstation, isolate it, but do not block the controller itself.']),
    (('new_device',), [
        'Identify {src} (vendor and hostname are in Devices). Unknown devices on the network are a common '
        'first step of an attack.']),
    (('tls_cert', 'tls_no_sni', 'tls_new_client'), [
        'Check which program on {src} made the connection; a certificate warning to an unknown server is '
        'often malware or a misconfigured app.']),
]
GENERIC = ['Look at the evidence on each alert below and decide: expected activity (mark it false positive) or '
           'not (contain {src}).']
CLOSING = 'When it is handled, mark the incident resolved with a short note of what you did.'


def checklist(kinds, src, responses):
    steps = []
    for keys, items in CHECKLISTS:
        if any(k in kind.lower() for kind in kinds for k in keys):
            steps += [s.format(src=src) for s in items]
    if not steps:
        steps = [s.format(src=src) for s in GENERIC]
    active = [r for r in responses if r.get('action') in ('block', 'quarantine', 'contain', 'rate_limit')]
    if active:
        last = active[-1]
        steps.insert(0, f'The appliance already applied "{last["action"]}" to {last.get("ip")}. '
                        'If this was legitimate, undo it in Operations → Response.')
    steps.append(CLOSING)
    return steps


# ---------------- responses and status ----------------

def load_actions(path=None):
    path = path or os.path.join(ROOT, 'logs', 'firewall_actions.jsonl')
    out = []
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                try:
                    item = json.loads(line)
                except ValueError:
                    continue
                ts = _ts(item.get('ts') or item.get('timestamp'))
                if ts is not None and item.get('ip'):
                    item['ts'] = ts
                    out.append(item)
    except OSError:
        pass
    return out


def status_file():
    return os.environ.get('SENTINEL_INCIDENTS') or os.path.join(ROOT, 'data', 'incidents.json')


def load_status():
    try:
        with open(status_file(), 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def set_status(incident_id, status, note='', by=None, now=None):
    if status not in STATUSES:
        raise ValueError(f'status must be one of {", ".join(STATUSES)}')
    with _lock:
        data = load_status()
        history = data.get(incident_id, {}).get('history', [])
        entry = {'status': status, 'note': str(note)[:1000], 'by': by, 'at': now or time.time()}
        data[incident_id] = {**entry, 'history': (history + [entry])[-50:]}
        path = status_file()
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        tmp = path + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=1)
        os.replace(tmp, path)
    return data[incident_id]


# ---------------- assembly ----------------

def _severity(risk):
    return 'critical' if risk >= 75 else 'high' if risk >= 50 else 'medium' if risk >= 25 else 'low'


def _title(kinds, src, targets):
    names = ', '.join(k.replace('_', ' ') for k in kinds[:2]) + (' and more' if len(kinds) > 2 else '')
    tail = f' against {targets[0]}' if len(targets) == 1 else f' against {len(targets)} devices' if targets else ''
    return f'{names[:1].upper() + names[1:]} from {src}{tail}'


def build(alerts, actions=(), status=None, gap=GAP):
    """Incidents from raw alerts, newest activity first, each with timeline, devices, responses and checklist."""
    status = status or {}
    out = []
    for group_alerts in group([normalize(a) for a in alerts], gap):
        first, last = group_alerts[0]['ts'], group_alerts[-1]['ts']
        sources = {}
        for a in group_alerts:
            sources[a['src']] = sources.get(a['src'], 0) + 1
        src = max(sources, key=sources.get)
        devices = set(sources) | {a['dst'] for a in group_alerts if a['dst']}
        targets = sorted({a['dst'] for a in group_alerts if a['dst'] and a['dst'] not in sources})
        kinds = []
        for a in group_alerts:
            if a['kind'] not in kinds:
                kinds.append(a['kind'])
        responses = [r for r in actions if r['ip'] in devices and first - 300 <= r['ts'] <= last + 3600]
        inc_id = hashlib.sha256(f'{group_alerts[0]["id"]}'.encode()).hexdigest()[:10]
        st = status.get(inc_id, {})
        state = st.get('status', 'open')
        if state == 'resolved' and last > st.get('at', 0):
            state = 'open'                                   # new activity after it was resolved
        risk = max(a['risk'] for a in group_alerts)
        timeline = [{'ts': a['ts'], 'type': 'alert', 'kind': a['kind'], 'src': a['src'], 'dst': a['dst'],
                     'risk': a['risk'], 'technique': a['technique'], 'evidence': a['evidence']} for a in group_alerts]
        timeline += [{'ts': r['ts'], 'type': 'response', 'action': r.get('action'), 'ip': r['ip'],
                      'reason': r.get('reason'), 'ttl': r.get('ttl'), 'dry_run': r.get('dry_run', False)}
                     for r in responses]
        timeline.sort(key=lambda e: e['ts'])
        out.append({
            'id': inc_id, 'title': _title(kinds, src, targets), 'status': state, 'severity': _severity(risk),
            'risk': risk, 'first_seen': first, 'last_seen': last, 'alert_count': len(group_alerts),
            'source': src, 'sources': sorted(sources), 'targets': targets, 'kinds': kinds,
            'techniques': sorted({a['technique'] for a in group_alerts if a['technique']}),
            'responses': len(responses), 'timeline': timeline[-500:],
            'checklist': checklist(kinds, src, responses),
            'note': st.get('note'), 'updated_by': st.get('by'), 'updated_at': st.get('at'),
            'history': st.get('history', []),
        })
    out.sort(key=lambda i: i['last_seen'], reverse=True)
    return out


def summary(incident):
    return {k: v for k, v in incident.items() if k not in ('timeline', 'checklist', 'history')}


def load_alerts(limit=5000):
    """Alerts from the database, or alerts.json when the database is unavailable."""
    try:
        from core.storage import get_storage
        s = get_storage(os.path.join(ROOT, 'data', 'sentinel.db'))
        s.connect()
        rows = s.get_alerts(limit=limit)
        if rows:
            return rows
    except Exception:
        pass
    try:
        with open(os.path.join(ROOT, 'alerts.json'), 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data[-limit:] if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def current(since=None, limit=5000):
    alerts = load_alerts(limit)
    incidents = build(alerts, load_actions(), load_status())
    if since is not None:
        incidents = [i for i in incidents if i['last_seen'] >= since]
    return incidents
