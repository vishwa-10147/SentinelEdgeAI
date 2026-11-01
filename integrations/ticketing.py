"""Ticketing and SOAR (Phase 10): incidents become tickets, and tickets update incidents.

Outbound, per configured target (Jira, ServiceNow, TheHive or a signed webhook):
  * an incident at or above the target's minimum severity opens ONE ticket
    (not one per alert);
  * new alerts on that incident are added as a comment / work note;
  * resolving the incident in SentinelEdgeAI resolves the ticket (Jira: an
    optional transition; ServiceNow: state Resolved; webhook: an event).
Inbound, POST /api/tickets/inbound/<target>: the ticket system reports that a
ticket was acknowledged, resolved or reopened, and the incident follows. The
call is authenticated per target by `inbound_token` (Authorization: Bearer) or
`inbound_secret` (X-Sentinel-Signature HMAC, as our own webhooks).

SOAR platforms that want to act (block, contain) use a scoped API token
(Operator) on the existing endpoints, so every action still goes through
the policy, protected hosts and approvals. Nothing inbound can act directly.

Configuration: the `ticketing` list in data/integrations.json (Admin, through
PUT /api/integrations). The mapping incident -> tickets is in
data/tickets.json (SENTINEL_TICKETS). `python -m integrations.ticketing sync`.
"""
import hashlib
import hmac
import json
import logging
import os
import threading
import time

import requests

from integrations.sinks import verify_webhook

logger = logging.getLogger('sentinel.ticketing')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SEVERITY_RANK = {'low': 0, 'medium': 1, 'high': 2, 'critical': 3}
SECRET_KEYS = ('api_token', 'password', 'secret', 'inbound_token', 'inbound_secret')
REQUIRED = {'jira': ('url', 'project', 'user', 'api_token'), 'servicenow': ('url', 'user', 'password'),
            'thehive': ('url', 'api_token'), 'webhook': ('url',)}
_lock = threading.Lock()


def tickets_file():
    return os.environ.get('SENTINEL_TICKETS') or os.path.join(ROOT, 'data', 'tickets.json')


def load_map():
    try:
        with open(tickets_file(), 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def save_map(data):
    path = tickets_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=1)
    os.replace(path + '.tmp', path)


# ---------------- text ----------------

def _when(ts):
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)) if ts else '-'


def describe(incident, console_url=None):
    lines = [incident['title'], '',
             f"Severity: {incident['severity']} (risk {round(incident['risk'])})",
             f"First seen: {_when(incident['first_seen'])}   Last seen: {_when(incident['last_seen'])}",
             f"Sources: {', '.join(incident['sources'])}"]
    if incident.get('targets'):
        lines.append(f"Targets: {', '.join(incident['targets'][:20])}")
    if incident.get('techniques'):
        lines.append(f"MITRE ATT&CK: {', '.join(incident['techniques'])}")
    lines += ['', 'What to do now:'] + [f'{n}. {s}' for n, s in enumerate(incident.get('checklist', []), 1)]
    alerts = [e for e in incident.get('timeline', []) if e['type'] == 'alert'][-10:]
    if alerts:
        lines += ['', 'Latest alerts:']
        for e in alerts:
            ev = ('; '.join(e.get('evidence') or []))[:300]
            lines.append(f"- {_when(e['ts'])} {e['kind']} {e['src']} -> {e.get('dst') or '-'} "
                         f"(risk {round(e['risk'])}){': ' + ev if ev else ''}")
    lines += ['', f"SentinelEdgeAI incident {incident['id']}"
              + (f" - {console_url.rstrip('/')}/#incidents/{incident['id']}" if console_url else '')]
    # network-derived text (hostnames, DNS names) is data: tickets are plain text, never markup
    return '\n'.join(lines)


def update_text(incident, previous_count):
    new = incident['alert_count'] - previous_count
    alerts = [e for e in incident.get('timeline', []) if e['type'] == 'alert'][-min(new, 10):]
    lines = [f'{new} new alert(s); incident now has {incident["alert_count"]}, severity {incident["severity"]}.']
    lines += [f"- {_when(e['ts'])} {e['kind']} {e['src']} -> {e.get('dst') or '-'}" for e in alerts]
    return '\n'.join(lines)


# ---------------- targets ----------------

class Target:
    kind = 'base'

    def __init__(self, config):
        self.config = config
        self.name = config.get('name') or self.kind
        self.min_severity = config.get('min_severity', 'high')
        self.timeout = float(config.get('timeout', 10))
        self.verify = config.get('ca_file') or True

    def wants(self, incident):
        return SEVERITY_RANK.get(incident['severity'], 0) >= SEVERITY_RANK.get(self.min_severity, 2)

    def _url(self, path):
        return self.config['url'].rstrip('/') + path

    def _request(self, method, path, **kw):
        r = requests.request(method, self._url(path), timeout=self.timeout, verify=self.verify, **kw)
        r.raise_for_status()
        return r.json() if r.content and 'json' in r.headers.get('Content-Type', '') else {}

    def create(self, incident, text):
        raise NotImplementedError

    def comment(self, ref, text):
        raise NotImplementedError

    def resolve(self, ref, text):
        self.comment(ref, text)


class JiraTarget(Target):
    """Jira Cloud / Data Center REST v2: issue, comment, optional transition on resolve."""
    kind = 'jira'

    def _auth(self):
        return (self.config['user'], self.config['api_token'])

    def create(self, incident, text):
        fields = {'project': {'key': self.config['project']}, 'summary': incident['title'][:250],
                  'description': text, 'issuetype': {'name': self.config.get('issue_type', 'Task')},
                  'labels': ['sentineledgeai', f"severity-{incident['severity']}"]}
        priority = (self.config.get('priorities') or {}).get(incident['severity'])
        if priority:
            fields['priority'] = {'name': priority}
        body = self._request('POST', '/rest/api/2/issue', json={'fields': fields}, auth=self._auth())
        key = body.get('key')
        return {'key': key, 'id': body.get('id'), 'url': self._url(f'/browse/{key}')}

    def comment(self, ref, text):
        self._request('POST', f"/rest/api/2/issue/{ref['key']}/comment", json={'body': text}, auth=self._auth())

    def resolve(self, ref, text):
        self.comment(ref, text)
        transition = self.config.get('resolve_transition')
        if transition:
            self._request('POST', f"/rest/api/2/issue/{ref['key']}/transitions",
                          json={'transition': {'id': str(transition)}}, auth=self._auth())


class ServiceNowTarget(Target):
    """ServiceNow Table API: an incident record, work notes, state Resolved (6)."""
    kind = 'servicenow'
    URGENCY = {'critical': '1', 'high': '1', 'medium': '2', 'low': '3'}

    def _auth(self):
        return (self.config['user'], self.config['password'])

    def create(self, incident, text):
        record = {'short_description': incident['title'][:160], 'description': text,
                  'urgency': self.URGENCY[incident['severity']],
                  'impact': '1' if incident['severity'] == 'critical' else '2',
                  'category': self.config.get('category', 'network'), 'correlation_id': incident['id'],
                  'correlation_display': 'SentinelEdgeAI'}
        if self.config.get('assignment_group'):
            record['assignment_group'] = self.config['assignment_group']
        body = self._request('POST', '/api/now/table/incident', json=record, auth=self._auth(),
                             headers={'Accept': 'application/json'}).get('result', {})
        return {'key': body.get('number'), 'id': body.get('sys_id'),
                'url': self._url(f"/nav_to.do?uri=incident.do?sys_id={body.get('sys_id')}")}

    def comment(self, ref, text):
        self._request('PATCH', f"/api/now/table/incident/{ref['id']}", json={'work_notes': text}, auth=self._auth(),
                      headers={'Accept': 'application/json'})

    def resolve(self, ref, text):
        self._request('PATCH', f"/api/now/table/incident/{ref['id']}", auth=self._auth(),
                      headers={'Accept': 'application/json'},
                      json={'state': '6', 'close_code': self.config.get('close_code', 'Resolved by caller'),
                            'close_notes': text, 'work_notes': text})


class TheHiveTarget(Target):
    """TheHive 5: an alert (sourceRef = incident id) with the devices as observables."""
    kind = 'thehive'
    SEVERITY = {'low': 1, 'medium': 2, 'high': 3, 'critical': 4}

    def _headers(self):
        h = {'Authorization': f"Bearer {self.config['api_token']}"}
        if self.config.get('organisation'):
            h['X-Organisation'] = self.config['organisation']
        return h

    def create(self, incident, text):
        observables = [{'dataType': 'ip', 'data': ip} for ip in (incident['sources'] + incident.get('targets', []))[:50]]
        body = self._request('POST', '/api/v1/alert', headers=self._headers(), json={
            'type': 'network', 'source': 'SentinelEdgeAI', 'sourceRef': incident['id'],
            'title': incident['title'][:250], 'description': text,
            'severity': self.SEVERITY[incident['severity']],
            'tags': ['sentineledgeai'] + incident.get('techniques', [])[:10], 'observables': observables})
        return {'key': body.get('_id'), 'id': body.get('_id'), 'url': self._url(f"/alerts/{body.get('_id')}")}

    def comment(self, ref, text):
        # TheHive alerts have no comments; the description carries the latest state
        self._request('PATCH', f"/api/v1/alert/{ref['id']}", headers=self._headers(), json={'description': text})

    def resolve(self, ref, text):
        self.comment(ref, text)


class WebhookTarget(Target):
    """Signed JSON events incident.opened / incident.updated / incident.resolved for any SOAR."""
    kind = 'webhook'

    def _post(self, event, incident_id, payload):
        body = json.dumps({'event': event, 'incident_id': incident_id, 'ts': time.time(), **payload},
                          sort_keys=True).encode()
        headers = {'Content-Type': 'application/json', 'User-Agent': 'SentinelEdgeAI'}
        secret = self.config.get('secret')
        if secret:
            ts = str(int(time.time()))
            mac = hmac.new(secret.encode(), ts.encode() + b'.' + body, hashlib.sha256).hexdigest()
            headers['X-Sentinel-Signature'] = f't={ts},v1={mac}'
        r = requests.post(self.config['url'], data=body, headers=headers, timeout=self.timeout, verify=self.verify)
        r.raise_for_status()

    def create(self, incident, text):
        summary = {k: v for k, v in incident.items() if k not in ('timeline', 'history')}
        self._post('incident.opened', incident['id'], {'incident': summary, 'text': text})
        return {'key': incident['id'], 'id': incident['id'], 'url': None}

    def comment(self, ref, text):
        self._post('incident.updated', ref['id'], {'text': text})

    def resolve(self, ref, text):
        self._post('incident.resolved', ref['id'], {'text': text})


TARGETS = {'jira': JiraTarget, 'servicenow': ServiceNowTarget, 'thehive': TheHiveTarget, 'webhook': WebhookTarget}


def build(config):
    kind = config.get('type')
    if kind not in TARGETS:
        raise ValueError(f"unknown ticketing type {kind!r}; use one of {', '.join(TARGETS)}")
    missing = [k for k in REQUIRED[kind] if not config.get(k)]
    if missing:
        raise ValueError(f"{kind} ticketing needs: {', '.join(missing)}")
    if not str(config['url']).startswith('https://') and not config.get('allow_http'):
        raise ValueError(f'{kind} URL must use https://')
    if config.get('min_severity', 'high') not in SEVERITY_RANK:
        raise ValueError('min_severity must be low, medium, high or critical')
    if not config.get('name'):
        raise ValueError('every ticketing target needs a unique name')
    return TARGETS[kind](config)


def validate(configs):
    names = [c.get('name') for c in configs]
    if len(names) != len(set(names)):
        raise ValueError('ticketing target names must be unique')
    return [build(c) for c in configs]


def configured():
    from integrations import dispatcher
    return dispatcher.load_config().get('ticketing', [])


# ---------------- sync ----------------

def sync(incidents=None, targets=None, console_url=None, now=None):
    """Bring every target up to date with the incidents. Returns counters; failures are retried next run."""
    if targets is None:
        targets = [build(c) for c in configured() if c.get('enabled', True)]
    stats = {'created': 0, 'updated': 0, 'resolved': 0, 'failed': 0}
    if not targets:
        return stats
    if incidents is None:
        from core import incidents as inc_mod
        incidents = inc_mod.current()
    console_url = console_url or os.environ.get('SENTINEL_CONSOLE_URL')
    now = now or time.time()
    with _lock:
        mapping = load_map()
        for inc in incidents:
            for t in targets:
                entry = mapping.setdefault(inc['id'], {}).get(t.name)
                try:
                    if entry is None:
                        if inc['status'] == 'resolved' or not t.wants(inc):
                            continue
                        ref = t.create(inc, describe(inc, console_url))
                        mapping[inc['id']][t.name] = {**ref, 'created': now, 'alerts': inc['alert_count'],
                                                      'resolved': False, 'type': t.kind}
                        stats['created'] += 1
                    elif inc['status'] == 'resolved' and not entry.get('resolved'):
                        note = inc.get('note') or 'no note'
                        t.resolve(entry, f"Resolved in SentinelEdgeAI by {inc.get('updated_by') or 'unknown'}: {note}")
                        entry.update(resolved=True, resolved_at=now)
                        stats['resolved'] += 1
                    elif inc['status'] != 'resolved' and inc['alert_count'] > entry.get('alerts', 0):
                        t.comment(entry, update_text(inc, entry.get('alerts', 0)))
                        entry.update(alerts=inc['alert_count'], resolved=False, updated=now)
                        stats['updated'] += 1
                except (requests.RequestException, KeyError, ValueError) as exc:
                    stats['failed'] += 1
                    logger.warning('ticketing %s failed for incident %s: %s', t.name, inc['id'], exc)
            if not mapping.get(inc['id']):
                mapping.pop(inc['id'], None)
        save_map(mapping)
    return stats


# ---------------- inbound ----------------

INBOUND_STATUS = {'resolved': 'resolved', 'resolve': 'resolved', 'closed': 'resolved', 'done': 'resolved',
                  'acknowledged': 'acknowledged', 'in progress': 'acknowledged', 'in_progress': 'acknowledged',
                  'open': 'open', 'reopened': 'open', 'new': 'open'}


def authenticate_inbound(config, body, headers):
    """True when the request carries the target's inbound token or a valid HMAC signature."""
    token = config.get('inbound_token')
    auth = headers.get('authorization') or ''
    if token and auth.startswith('Bearer ') and hmac.compare_digest(auth[7:].strip(), token):
        return True
    secret = config.get('inbound_secret')
    sig = headers.get('x-sentinel-signature')
    return bool(secret and sig and verify_webhook(secret, body, sig))


def inbound(target_name, payload, by=None):
    """Apply a status change reported by a ticket system. Returns (incident_id, status)."""
    from core import incidents as inc_mod
    status = INBOUND_STATUS.get(str(payload.get('status') or '').strip().lower())
    if not status:
        raise ValueError(f'status must be one of {", ".join(sorted(set(INBOUND_STATUS)))}')
    incident_id = payload.get('incident_id')
    key = payload.get('ticket') or payload.get('key')
    mapping = load_map()
    if not incident_id and key:
        for iid, targets in mapping.items():
            ref = targets.get(target_name)
            if ref and key in (ref.get('key'), ref.get('id')):
                incident_id = iid
                break
    if not incident_id or target_name not in mapping.get(incident_id, {}):
        raise LookupError('no incident is linked to that ticket on this target')
    note = str(payload.get('note') or f'{status} in {target_name}')[:1000]
    inc_mod.set_status(incident_id, status, note, by=by or f'ticket:{target_name}')
    with _lock:
        mapping = load_map()
        entry = mapping.get(incident_id, {}).get(target_name)
        if entry is not None:
            entry['resolved'] = status == 'resolved'     # do not push the resolution back to its source
            save_map(mapping)
    return incident_id, status


def start_background(interval=60):
    """Sync every `interval` seconds in a daemon thread (does nothing while no target is configured)."""
    stop = threading.Event()

    def loop():
        while not stop.wait(interval):
            try:
                if configured():
                    sync()
            except Exception:
                logger.exception('ticketing sync failed')

    threading.Thread(target=loop, daemon=True, name='ticketing-sync').start()
    return stop


def main(argv=None):
    import argparse
    p = argparse.ArgumentParser(prog='python -m integrations.ticketing')
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('sync', help='create, update and resolve tickets now')
    sub.add_parser('status', help='incidents and their tickets')
    args = p.parse_args(argv)
    if args.command == 'sync':
        print(json.dumps(sync(), indent=2))
    else:
        print(json.dumps(load_map(), indent=2))


if __name__ == '__main__':
    main()
