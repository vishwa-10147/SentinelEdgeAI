"""Notifications (Phase 10): approval requests the moment they happen, and daily/weekly digests.

Both go to destinations already configured under Integrations (e-mail, Slack,
Teams or a signed webhook), named in data/notifications.json
(SENTINEL_NOTIFICATIONS, Admin through GET/PUT /api/notifications):

    {"console_url": "https://sentinel.example.org",
     "approvals": {"enabled": true, "sinks": ["ops-slack", "oncall-mail"]},
     "digest": {"enabled": true, "frequency": "daily", "hour": 8, "weekday": 0, "sinks": ["oncall-mail"]}}

An approval message links to <console_url>/#approve/<id>: the phone-friendly
approval page of the console. The link carries no credentials: the Operator
signs in (with two-step sign-in or SSO) before approving or denying, and the
decision goes through the same endpoint, policy and audit as in the console.

Messages are sent from a background queue, so the engine never waits on SMTP
or Slack. Text from the network (hostnames, DNS names) is sent as plain text.
"""
import json
import logging
import os
import queue
import threading
import time
from datetime import datetime, timedelta

logger = logging.getLogger('sentinel.notify')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
NOTIFY_TYPES = ('email', 'slack', 'teams', 'webhook')
FREQUENCIES = ('daily', 'weekly')
DEFAULTS = {'console_url': '', 'approvals': {'enabled': False, 'sinks': []},
            'digest': {'enabled': False, 'frequency': 'daily', 'hour': 8, 'weekday': 0, 'sinks': []}}
_lock = threading.Lock()


def config_file():
    return os.environ.get('SENTINEL_NOTIFICATIONS') or os.path.join(ROOT, 'data', 'notifications.json')


def state_file():
    return os.path.join(os.path.dirname(os.path.abspath(config_file())), 'notifications_state.json')


def _read(path, default):
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, dict) else default
    except (OSError, ValueError):
        return default


def _write(path, data):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path + '.tmp', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    os.replace(path + '.tmp', path)


def load_config():
    data = _read(config_file(), {})
    return {'console_url': data.get('console_url', ''),
            'approvals': {**DEFAULTS['approvals'], **(data.get('approvals') or {})},
            'digest': {**DEFAULTS['digest'], **(data.get('digest') or {})}}


def _sink_configs():
    from integrations import dispatcher
    return {s.get('name') or s.get('type'): s for s in dispatcher.load_config().get('sinks', [])}


def validate(cfg):
    cfg = {'console_url': str(cfg.get('console_url') or '').rstrip('/'),
           'approvals': {**DEFAULTS['approvals'], **(cfg.get('approvals') or {})},
           'digest': {**DEFAULTS['digest'], **(cfg.get('digest') or {})}}
    if cfg['console_url'] and not cfg['console_url'].startswith('https://'):
        raise ValueError('console_url must start with https://')
    sinks = _sink_configs()
    for part in ('approvals', 'digest'):
        names = cfg[part]['sinks']
        if not isinstance(names, list):
            raise ValueError(f'{part}.sinks must be a list of integration names')
        for name in names:
            if name not in sinks:
                raise ValueError(f'{part}: no integration named {name!r} (add it under Integrations first)')
            if sinks[name].get('type') not in NOTIFY_TYPES:
                raise ValueError(f'{part}: {name!r} is a {sinks[name].get("type")} destination; '
                                 f'notifications go to {", ".join(NOTIFY_TYPES)}')
        if cfg[part]['enabled'] and not names:
            raise ValueError(f'{part} needs at least one destination')
    d = cfg['digest']
    if d['frequency'] not in FREQUENCIES:
        raise ValueError('digest.frequency must be daily or weekly')
    if not 0 <= int(d['hour']) <= 23 or not 0 <= int(d['weekday']) <= 6:
        raise ValueError('digest.hour is 0-23 and digest.weekday 0 (Monday) to 6 (Sunday)')
    d['hour'], d['weekday'] = int(d['hour']), int(d['weekday'])
    return cfg


def save_config(cfg, now=None):
    cfg = validate(cfg)
    _write(config_file(), cfg)
    if cfg['digest']['enabled']:
        with _lock:                                  # the first digest is the next scheduled one, not a catch-up
            state = _read(state_file(), {})
            if not state.get('last_digest'):
                state['last_digest'] = now or time.time()
                _write(state_file(), state)
    return cfg


# ---------------- sending ----------------

def send(sink_names, subject, text, link=None):
    """Send now to each named destination. Returns {name: 'ok' | error}."""
    from integrations import sinks
    configs = _sink_configs()
    out = {}
    for name in sink_names:
        try:
            sink = sinks.build(configs[name])
            sink.message(subject, text, link)
            out[name] = 'ok'
        except Exception as exc:                    # one broken destination must not stop the others
            logger.warning('notification to %s failed: %s', name, exc)
            out[name] = str(exc)[:200] or exc.__class__.__name__
    return out


_queue = queue.Queue(maxsize=1000)
_worker = None


def _run():
    while True:
        names, subject, text, link = _queue.get()
        try:
            send(names, subject, text, link)
        finally:
            _queue.task_done()


def enqueue(names, subject, text, link=None):
    """Send in the background; drops (and logs) when 1000 messages are already waiting."""
    global _worker
    with _lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_run, daemon=True, name='notifications')
            _worker.start()
    try:
        _queue.put_nowait((list(names), subject, text, link))
    except queue.Full:
        logger.warning('notification queue full; dropped: %s', subject)


def _link(cfg, fragment):
    return f"{cfg['console_url']}/#{fragment}" if cfg.get('console_url') else None


# ---------------- approvals ----------------

def approval_requested(pending_id, ip, action, risk, reason, ttl=None):
    """Called by the playbook when an action waits for an Operator. Never raises."""
    from integrations import webpush                # browsers/phones that turned push on (per user)
    webpush.approval_requested(pending_id, ip, action, risk, reason)
    try:
        cfg = load_config()
        if not cfg['approvals']['enabled'] or not cfg['approvals']['sinks']:
            return
        duration = f' for {int(ttl) // 60} min' if ttl else ''
        subject = f'Approval needed: {action} {ip}'
        text = (f'SentinelEdgeAI wants to {action} {ip}{duration} (risk {int(risk)}).\n'
                f'Reason: {reason}\n\n'
                'An Operator must approve or deny it. Until then nothing is applied to this device.')
        enqueue(cfg['approvals']['sinks'], subject, text, _link(cfg, f'approve/{int(pending_id)}'))
    except Exception:
        logger.exception('approval notification failed')


# ---------------- digest ----------------

def _when(ts):
    return time.strftime('%Y-%m-%d %H:%M', time.localtime(ts)) if ts else '-'


def build_digest(period_seconds, now=None, incidents=None, pending=None, suggestions=None):
    """(subject, text) for the last `period_seconds`."""
    now = now or time.time()
    since = now - period_seconds
    if incidents is None:
        from core import incidents as inc
        incidents = inc.current()
    if pending is None:
        try:
            from enforcement.playbook import get_playbook
            pending = get_playbook().pending()
        except Exception:
            pending = []
    if suggestions is None:
        try:
            from detection import guided_tuning
            suggestions = guided_tuning.current_suggestions(now)
        except Exception:
            suggestions = []
    open_ = [i for i in incidents if i['status'] != 'resolved']
    new = [i for i in incidents if i['first_seen'] >= since]
    resolved = [i for i in incidents if i['status'] == 'resolved' and (i.get('updated_at') or 0) >= since]
    by_sev = {s: sum(1 for i in open_ if i['severity'] == s) for s in ('critical', 'high', 'medium', 'low')}
    label = 'day' if period_seconds <= 86400 else 'week'
    subject = (f"{'Daily' if label == 'day' else 'Weekly'} digest: {len(open_)} open incident"
               f"{'s' if len(open_) != 1 else ''}, {len(pending)} awaiting approval")
    lines = [f'SentinelEdgeAI summary for the last {label} ({_when(since)} to {_when(now)}).', '',
             f'Open incidents: {len(open_)} (critical {by_sev["critical"]}, high {by_sev["high"]}, '
             f'medium {by_sev["medium"]}, low {by_sev["low"]})',
             f'New this {label}: {len(new)}    Resolved this {label}: {len(resolved)}']
    if open_:
        lines += ['', 'Needs attention:']
        rank = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        for i in sorted(open_, key=lambda i: (rank.get(i['severity'], 4), -i['last_seen']))[:8]:
            lines.append(f"- [{i['severity']}] {i['title']} - {i['alert_count']} alerts, last {_when(i['last_seen'])}"
                         f" ({i['status']})")
    if pending:
        lines += ['', f'Waiting for an Operator ({len(pending)}):']
        for p in pending[:8]:
            lines.append(f"- {p['action']} {p['ip']} (risk {p['risk']}), requested {_when(p['created'])}")
    if suggestions:
        lines += ['', f'Tuning suggestions ({len(suggestions)}):']
        lines += [f"- {s['text']}" for s in suggestions[:5]]
    if not open_ and not pending and not suggestions:
        lines += ['', 'Nothing needs your attention.']
    return subject, '\n'.join(lines)


def _last_due(cfg, now):
    """The most recent scheduled digest time at or before `now`."""
    d = cfg['digest']
    t = datetime.fromtimestamp(now).replace(hour=d['hour'], minute=0, second=0, microsecond=0)
    if d['frequency'] == 'daily':
        if t.timestamp() > now:
            t -= timedelta(days=1)
    else:
        t -= timedelta(days=(t.weekday() - d['weekday']) % 7)
        if t.timestamp() > now:
            t -= timedelta(days=7)
    return t.timestamp()


def send_digest(cfg=None, now=None, force=False):
    """Send the digest when it is due (or now with force). Returns the delivery result or None."""
    cfg = cfg or load_config()
    now = now or time.time()
    d = cfg['digest']
    if not d['sinks'] or not (d['enabled'] or force):
        return None
    due = _last_due(cfg, now)
    state = _read(state_file(), {})
    if not force and state.get('last_digest', 0) >= due:
        return None
    period = 86400 if d['frequency'] == 'daily' else 7 * 86400
    subject, text = build_digest(period, now)
    result = send(d['sinks'], subject, text, _link(cfg, 'incidents'))
    with _lock:
        state = _read(state_file(), {})
        state['last_digest'] = now
        state['last_result'] = result
        _write(state_file(), state)
    return result


def start_background(interval=300):
    """Check every `interval` seconds whether a digest is due."""
    stop = threading.Event()

    def loop():
        while not stop.wait(interval):
            try:
                send_digest()
            except Exception:
                logger.exception('digest failed')

    threading.Thread(target=loop, daemon=True, name='digest').start()
    return stop
