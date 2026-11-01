"""Guided tuning (Phase 10): turn analysts' false-positive labels into scoped, expiring rules.

Analyst labels already recalibrate each detector, but globally: forty false
alarms from the printer VLAN make a detector weaker for every device. Guided
tuning finds where the false alarms come from and proposes a rule for just
that place:

    "Beaconing raised 12 false alarms from 10.0.5.0/24 in the last 14 days
     and none were confirmed. Downgrade it there?"

Suggestions group false-positive labels per detector by source host, source
subnet (/24, IPv6 /64) or destination, and are made only when there are at
least `min_fp` false alarms there and no confirmed (true-positive) one.

Rules (data/guided_tuning.json, SENTINEL_GUIDED_TUNING):
  downgrade  the finding is kept and shown, with severity -25 and half the
             probability, so it no longer confirms an automatic response
  suppress   the finding is dropped (Operator only; never for the detectors
             in NEVER_SUPPRESS, whose misses are too costly)
Every rule expires (default 30 days, at most 180), records who made it and
why, and the engine counts the findings each one touched. Rules apply in one place
(DetectionPipeline._accept), so they cover every detector, Zeek and Suricata.
"""
import hashlib
import ipaddress
import json
import os
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ACTIONS = ('downgrade', 'suppress')
NEVER_SUPPRESS = {'dcsync', 'ot_device_stop', 'threat_intel', 'tls_known_bad', 'intel', 'ot_external'}
DEFAULT_DAYS, MAX_DAYS = 30, 180
WINDOW = 14 * 86400
MIN_FP = 5
DISMISS_DAYS = 30
RELOAD_SECONDS = 10
_lock = threading.Lock()


def rules_file():
    return os.environ.get('SENTINEL_GUIDED_TUNING') or os.path.join(ROOT, 'data', 'guided_tuning.json')


def _load():
    try:
        with open(rules_file(), 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    if not isinstance(data, dict):
        data = {}
    data.setdefault('rules', [])
    data.setdefault('dismissed', {})
    return data


def _save(data):
    path = rules_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path + '.tmp', 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=1)
    os.replace(path + '.tmp', path)


# ---------------- scopes ----------------

def _net(value):
    """An ip_network for an address or CIDR, or ValueError."""
    return ipaddress.ip_network(str(value), strict=False)


def validate_scope(scope):
    if not isinstance(scope, dict) or not scope:
        raise ValueError('a rule needs a scope: src and/or dst (address or CIDR), optionally dport')
    out = {}
    for key in ('src', 'dst'):
        if scope.get(key):
            net = _net(scope[key])
            if net.prefixlen < (16 if net.version == 4 else 48):
                raise ValueError(f'{key} scope {net} is too wide; use /16 or narrower')
            out[key] = str(net) if net.num_addresses > 1 else str(net.network_address)
    if scope.get('dport') not in (None, ''):
        port = int(scope['dport'])
        if not 0 < port < 65536:
            raise ValueError('dport must be 1-65535')
        out['dport'] = port
    if not out.get('src') and not out.get('dst'):
        raise ValueError('a rule needs a src or dst scope; a detector cannot be tuned for the whole network here')
    return out


def _in(ip, cidr):
    try:
        return ipaddress.ip_address(str(ip)) in _net(cidr)
    except ValueError:
        return False


def matches(rule, finding, now):
    if rule.get('expires', 0) <= now or rule['kind'] != finding.kind:
        return False
    scope = rule['scope']
    target = finding.details.get('target') if isinstance(finding.details, dict) else None
    if scope.get('src') and not _in(finding.src, scope['src']):
        return False
    if scope.get('dst') and not (target and _in(target, scope['dst'])):
        return False
    if scope.get('dport') is not None:
        port = finding.details.get('dport') or finding.details.get('port') if isinstance(finding.details, dict) else None
        if port is None or int(port) != scope['dport']:
            return False
    return True


def describe_scope(scope):
    parts = []
    if scope.get('src'):
        parts.append(f"from {scope['src']}")
    if scope.get('dst'):
        parts.append(f"to {scope['dst']}")
    if scope.get('dport') is not None:
        parts.append(f"on port {scope['dport']}")
    return ' '.join(parts)


# ---------------- rules ----------------

def add_rule(kind, scope, action='downgrade', days=DEFAULT_DAYS, by=None, note='', source='manual', now=None):
    now = now or time.time()
    if action not in ACTIONS:
        raise ValueError('action must be downgrade or suppress')
    if not kind:
        raise ValueError('a rule needs a detector kind')
    if action == 'suppress' and kind in NEVER_SUPPRESS:
        raise ValueError(f'{kind} findings can be downgraded but never suppressed')
    days = int(days or DEFAULT_DAYS)
    if not 1 <= days <= MAX_DAYS:
        raise ValueError(f'a rule lasts 1 to {MAX_DAYS} days')
    scope = validate_scope(scope)
    rule = {'id': hashlib.sha256(f'{kind}|{json.dumps(scope, sort_keys=True)}|{now}'.encode()).hexdigest()[:10],
            'kind': str(kind)[:64], 'scope': scope, 'action': action, 'created': now,
            'expires': now + days * 86400, 'by': by, 'note': str(note)[:500], 'source': source}
    with _lock:
        data = _load()
        data['rules'] = [r for r in data['rules'] if r['expires'] > now]       # drop expired rules
        data['rules'].append(rule)
        _save(data)
    return rule


def remove_rule(rule_id):
    with _lock:
        data = _load()
        kept = [r for r in data['rules'] if r['id'] != rule_id]
        if len(kept) == len(data['rules']):
            raise KeyError(rule_id)
        data['rules'] = kept
        _save(data)


def list_rules(now=None, include_expired=False):
    now = now or time.time()
    rules = _load()['rules']
    return rules if include_expired else [r for r in rules if r['expires'] > now]


class RuleSet:
    """The active rules, reloaded from disk every few seconds (the API writes, the engine reads)."""

    def __init__(self, clock=time.time):
        self.clock = clock
        self.rules, self._at, self._mtime = [], -1e18, None
        self.hits = {}

    def _refresh(self, now):
        if now - self._at < RELOAD_SECONDS:
            return
        self._at = now
        try:
            mtime = os.path.getmtime(rules_file())
        except OSError:
            self.rules, self._mtime = [], None
            return
        if mtime != self._mtime:
            self._mtime = mtime
            self.rules = [r for r in _load()['rules'] if r.get('expires', 0) > now]

    def apply(self, findings, now=None):
        """The findings after rules: suppressed ones removed, downgraded ones marked and weakened."""
        if not findings:
            return findings
        now = now or self.clock()
        self._refresh(now)
        if not self.rules:
            return findings
        out = []
        for f in findings:
            rule = next((r for r in self.rules if matches(r, f, now)), None)
            if rule is None:
                out.append(f)
                continue
            self.hits[rule['id']] = self.hits.get(rule['id'], 0) + 1
            if rule['action'] == 'suppress':
                continue
            f.severity = max(10, int(f.severity) - 25)
            f.probability = round(f.probability * 0.5, 3)
            details = dict(f.details) if isinstance(f.details, dict) else {}
            details['tuned'] = {'rule': rule['id'], 'action': 'downgrade', 'note': rule.get('note')}
            f.details = details
            out.append(f)
        return out



# ---------------- suggestions ----------------

def _subnet(ip):
    try:
        a = ipaddress.ip_address(str(ip))
    except ValueError:
        return None
    return str(ipaddress.ip_network(f'{a}/{24 if a.version == 4 else 64}', strict=False))


def _target(alert):
    if not isinstance(alert, dict):
        return None
    return alert.get('responder_ip') or alert.get('dst_ip') or alert.get('dst')


def _within(value, rule_value):
    try:
        inner, outer = _net(value), _net(rule_value)
        return inner.version == outer.version and inner.subnet_of(outer)
    except (ValueError, TypeError):
        return False


def _covered(rules, kind, scope, now):
    """True when an active rule for `kind` already covers everything `scope` covers."""
    for r in rules:
        if r['kind'] != kind or r['expires'] <= now:
            continue
        if all(k in scope and (scope[k] == v if k == 'dport' else _within(scope[k], v))
               for k, v in r['scope'].items()):
            return True
    return False


def suggest(labels, rules=(), dismissed=None, now=None, window=WINDOW, min_fp=MIN_FP):
    """Suggestions from feedback labels [{'ts', 'kind', 'src', 'label', 'alert'}], strongest first."""
    now = now or time.time()
    dismissed = dismissed or {}
    recent = [l for l in labels if l.get('ts', 0) >= now - window and l.get('kind') and l.get('src')]
    candidates = {}

    def add(kind, scope, label):
        key = (kind, json.dumps(scope, sort_keys=True))
        c = candidates.setdefault(key, {'kind': kind, 'scope': scope, 'fp': 0, 'tp': 0, 'sources': set(),
                                        'last': 0})
        c['fp' if label['label'] == 'fp' else 'tp'] += 1
        c['sources'].add(label['src'])
        c['last'] = max(c['last'], label.get('ts', 0))

    for l in recent:
        add(l['kind'], {'src': l['src']}, l)
        net = _subnet(l['src'])
        if net:
            add(l['kind'], {'src': net}, l)
        dst = _target(l.get('alert'))
        if dst:
            add(l['kind'], {'dst': dst}, l)

    out = []
    for c in candidates.values():
        if c['fp'] < min_fp or c['tp'] > 0:
            continue
        scope = c['scope']
        # a subnet only when several hosts share the problem; one host gets its own (narrower) suggestion
        if 'src' in scope and '/' in scope['src'] and len(c['sources']) < 2:
            continue
        if 'dst' in scope and len(c['sources']) < 2:
            continue
        sid = hashlib.sha256(f"{c['kind']}|{json.dumps(scope, sort_keys=True)}".encode()).hexdigest()[:10]
        if dismissed.get(sid, 0) > now or _covered(rules, c['kind'], scope, now):
            continue
        name = c['kind'].replace('_', ' ')
        where = describe_scope(scope)
        hosts = f' ({len(c["sources"])} devices)' if len(c['sources']) > 1 else ''
        out.append({
            'id': sid, 'kind': c['kind'], 'scope': scope, 'false_positives': c['fp'], 'sources': len(c['sources']),
            'last_seen': c['last'], 'action': 'downgrade', 'can_suppress': c['kind'] not in NEVER_SUPPRESS,
            'text': f'{name[:1].upper() + name[1:]} raised {c["fp"]} false alarms {where}{hosts} in the last '
                    f'{int(window / 86400)} days and none were confirmed. Downgrade it there?',
            'effect': 'Its alerts from there stay visible but no longer trigger an automatic response. '
                      f'The rule expires after {DEFAULT_DAYS} days unless you renew it.',
        })
    # prefer the narrowest scope that explains the problem, then the noisiest
    out.sort(key=lambda s: (-s['false_positives'], 'src' in s['scope'] and '/' in s['scope'].get('src', '')))
    # drop a subnet suggestion when one host in it already explains all its false alarms
    hosts = {(s['kind'], s['scope'].get('src')): s['false_positives'] for s in out
             if 'src' in s['scope'] and '/' not in s['scope']['src']}
    final = []
    for s in out:
        src = s['scope'].get('src', '')
        if '/' in src and any(k == s['kind'] and h and _in(h, src) and n >= s['false_positives']
                              for (k, h), n in hosts.items()):
            continue
        final.append(s)
    return final


def feedback_labels(since):
    from detection.feedback import get_store
    store = get_store()
    with store._lock:
        rows = store._db().execute('SELECT ts, kind, src, label, alert FROM feedback WHERE ts >= ?',
                                   (int(since),)).fetchall()
    out = []
    for r in rows:
        try:
            alert = json.loads(r['alert']) if r['alert'] else None
        except ValueError:
            alert = None
        out.append({'ts': r['ts'], 'kind': r['kind'], 'src': r['src'], 'label': r['label'], 'alert': alert})
    return out


def current_suggestions(now=None):
    now = now or time.time()
    data = _load()
    return suggest(feedback_labels(now - WINDOW), data['rules'], data['dismissed'], now)


def accept(suggestion_id, action='downgrade', days=DEFAULT_DAYS, by=None, note='', now=None):
    for s in current_suggestions(now):
        if s['id'] == suggestion_id:
            return add_rule(s['kind'], s['scope'], action, days, by,
                            note or s['text'], source='suggestion', now=now)
    raise KeyError(suggestion_id)


def dismiss(suggestion_id, now=None):
    now = now or time.time()
    with _lock:
        data = _load()
        data['dismissed'] = {k: v for k, v in data['dismissed'].items() if v > now}
        data['dismissed'][suggestion_id] = now + DISMISS_DAYS * 86400
        _save(data)
