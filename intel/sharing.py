"""Community threat sharing (Phase 11): opt-in, anonymised indicators between sites and between fleets.

Two levels, both off by default:

* **Within a fleet.** The fleet server already receives alert summaries from its sites. With sharing on
  (sharing.json in the fleet directory, `python -m fleet share enable`), an internet address that appears in serious
  alerts (score >= min_score, of the kinds below) at `min_sites` or more different sites within `days` is
  sent to every site in its desired state, and the site agent loads it as the intel source `fleet`.
* **Between fleets.** `python -m fleet share export --out community.json` writes the same indicators as a
  STIX 2.1 bundle signed with the fleet's Ed25519 sharing key; publish the file anywhere (a web server, a
  git repository). Another fleet subscribes with
  `python -m intel add-feed <name> <url> --format signed-stix --public-key publisher.pem`: the signature
  is checked against the pinned key before any indicator is used.

What leaves the fleet: only internet addresses (never private, link-local, CGNAT, documentation or the
`never_share` ranges, e.g. your own public addresses), the alert kinds, a day-granularity first-seen date
and a validity of `valid_days`. No site names or ids, no internal addresses, no counts, no times.

Shared indicators are second-hand and could be wrong or poisoned, so a match raises a finding of lower
severity and probability (`fleet`: 0.6, community feeds: 0.5) that never triggers an automatic response on
its own; it adds weight when the device's own behaviour is also suspicious.
"""
import ipaddress
import json
import os
import time
from collections import defaultdict

from common import signing

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SHARE_KINDS = frozenset({'beaconing', 'session_rhythm', 'threat_intel', 'tls_known_bad', 'http_known_bad',
                         'http_lolbin', 'exfiltration', 'dns_tunnel', 'dga', 'port_scan', 'host_sweep',
                         'brute_force', 'zeek_notice', 'suricata_alert'})
DEFAULTS = {'enabled': False, 'min_sites': 2, 'min_score': 70, 'days': 7, 'valid_days': 14, 'never_share': [],
            'publisher': 'SentinelEdgeAI fleet', 'max_indicators': 5000}
SOURCE_TRUST = {'fleet': (65, 0.6)}          # source -> (severity, probability) of a match
COMMUNITY_TRUST = (60, 0.5)
_NOT_INTERNET = [ipaddress.ip_network(n) for n in ('100.64.0.0/10', '192.0.0.0/24', '198.18.0.0/15')]


def config_file():
    if os.environ.get('SENTINEL_FLEET_SHARING'):
        return os.environ['SENTINEL_FLEET_SHARING']
    from fleet.keys import fleet_dir
    return os.path.join(fleet_dir(), 'sharing.json')


def load_config():
    try:
        with open(config_file(), encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    return {**DEFAULTS, **(data if isinstance(data, dict) else {})}


def save_config(cfg):
    cfg = {**DEFAULTS, **cfg}
    cfg['min_sites'] = max(1, int(cfg['min_sites']))
    cfg['min_score'] = max(0, min(100, int(cfg['min_score'])))
    cfg['days'] = max(1, min(90, int(cfg['days'])))
    cfg['valid_days'] = max(1, min(90, int(cfg['valid_days'])))
    nets = []
    for n in cfg['never_share'] or []:
        nets.append(str(ipaddress.ip_network(str(n), strict=False)))       # ValueError on a bad range
    cfg['never_share'] = nets
    path = config_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path + '.tmp', 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2)
    os.replace(path + '.tmp', path)
    return cfg


def shareable_ip(value, never_share=()):
    """True only for a plain internet address outside the excluded ranges."""
    try:
        a = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    if not a.is_global or a.is_multicast or any(a in n for n in _NOT_INTERNET):
        return False
    return not any(a.version == n.version and a in n for n in (ipaddress.ip_network(x) for x in never_share))


def collect(alerts, cfg=None, now=None):
    """[{'type': 'ip', 'value', 'kinds', 'first_seen_day'}] from fleet alert rows (site, ts, type, score, src_ip, dst_ip)."""
    cfg = cfg or load_config()
    now = now or time.time()
    since = now - cfg['days'] * 86400
    seen = defaultdict(lambda: {'sites': set(), 'kinds': set(), 'first': now})
    for a in alerts:
        if (a.get('type') or '') not in SHARE_KINDS or float(a.get('ts') or 0) < since:
            continue
        if a.get('score') is None or float(a['score']) < cfg['min_score']:
            continue
        for ip in (a.get('src_ip'), a.get('dst_ip')):
            if ip and shareable_ip(ip, cfg['never_share']):
                s = seen[ip]
                s['sites'].add(a.get('site'))
                s['kinds'].add(a['type'])
                s['first'] = min(s['first'], float(a['ts']))
    out = [{'type': 'ip', 'value': ip, 'kinds': sorted(s['kinds']),
            'first_seen_day': time.strftime('%Y-%m-%d', time.gmtime(s['first']))}
           for ip, s in seen.items() if len(s['sites']) >= cfg['min_sites']]
    out.sort(key=lambda i: (i['first_seen_day'], i['value']))
    return out[:cfg['max_indicators']]


def to_store(indicators, valid_days, now=None):
    """The indicators as intel.store rows."""
    expires = int((now or time.time()) + valid_days * 86400)
    return [{'type': i['type'], 'value': i['value'], 'label': ', '.join(i['kinds']), 'expires': expires}
            for i in indicators]


# ---------------- signed STIX bundle ----------------

def _stix_time(day):
    return f'{day}T00:00:00.000Z'


def bundle(indicators, cfg=None, now=None):
    import uuid
    cfg = cfg or load_config()
    now = now or time.time()
    day = time.strftime('%Y-%m-%d', time.gmtime(now))
    until = time.strftime('%Y-%m-%d', time.gmtime(now + cfg['valid_days'] * 86400))
    ns = uuid.UUID('6f1f4d55-3c0a-4a0e-9a63-5e9f0b7c2a11')
    ident = f'identity--{uuid.uuid5(ns, cfg["publisher"])}'
    objects = [{'type': 'identity', 'spec_version': '2.1', 'id': ident, 'name': cfg['publisher'][:120],
                'identity_class': 'organization', 'created': _stix_time(day), 'modified': _stix_time(day)}]
    for i in indicators:
        stype = 'ipv6-addr' if ':' in i['value'] else 'ipv4-addr'
        objects.append({'type': 'indicator', 'spec_version': '2.1', 'id': f'indicator--{uuid.uuid5(ns, i["value"])}',
                        'created_by_ref': ident, 'created': _stix_time(i['first_seen_day']), 'modified': _stix_time(day),
                        'name': ', '.join(i['kinds']), 'indicator_types': ['malicious-activity'],
                        'pattern': f"[{stype}:value = '{i['value']}']", 'pattern_type': 'stix',
                        'valid_from': _stix_time(i['first_seen_day']), 'valid_until': _stix_time(until),
                        'confidence': 50})
    return {'type': 'bundle', 'id': f'bundle--{uuid.uuid5(ns, cfg["publisher"] + day)}', 'objects': objects}


def sign_bundle(stix, private_pem, public_pem):
    return {'format': 'sentineledgeai-signed-stix', 'version': 1, **signing.sign(private_pem, stix, public_pem)}


def verify_bundle(doc, public_pem):
    """The STIX bundle inside a signed document, or ValueError."""
    if isinstance(doc, (str, bytes)):
        doc = json.loads(doc)
    if not isinstance(doc, dict) or doc.get('format') != 'sentineledgeai-signed-stix':
        raise ValueError('not a signed community bundle')
    if doc.get('kid') and doc['kid'] != signing.key_id(public_pem):
        raise ValueError('bundle signed with a different key than the one pinned for this feed')
    try:
        return signing.verify(public_pem, doc)
    except signing.SignatureError as exc:
        raise ValueError(f'community bundle signature: {exc}')


def trust_for(source):
    """(severity, probability) for an intel match from `source`, or None for first-hand feeds."""
    if source in SOURCE_TRUST:
        return SOURCE_TRUST[source]
    if str(source).startswith('community:'):
        return COMMUNITY_TRUST
    return None
