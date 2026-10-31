"""Per-device trust score, 0-100, with the reasons behind it (Phase 7, zero-trust).

  start                   50
  identity                +10 known MAC, +5 vendor, +5 hostname; -10 when no MAC was ever seen
  tenure                  +2 per day seen, up to +20
  alerts (last 7 days)    -25 x risk/100 per alert, halved every 24 h, up to -80;
                          kinds an analyst marked false positive for this device are ignored
  restrictions            quarantined or blocked: 0; contained: at most 30

Levels: trusted >= 70, watch >= 40, untrusted below. An untrusted device with
a learned peer profile can be contained to it (core.firewall 'contain');
without one, quarantine is the fallback.
"""
import ast
import json
import time

from detection import peers as peer_profiles

WINDOW = 7 * 86400
HALF_LIFE = 86400
TRUSTED, WATCH = 70, 40


def _details(raw):
    if isinstance(raw, dict):
        return raw
    for parse in (json.loads, ast.literal_eval):
        try:
            value = parse(raw)
            if isinstance(value, dict):
                return value
        except (ValueError, SyntaxError, TypeError):
            continue
    return {}


def normalise_alerts(rows):
    """Alert rows from storage -> [{'src', 'ts', 'risk', 'kind'}]."""
    out = []
    for r in rows:
        d = _details(r.get('details'))
        src = r.get('src_ip') or d.get('initiator_ip') or d.get('src_ip')
        if not src:
            continue
        out.append({'src': src, 'ts': float(r.get('timestamp') or 0), 'risk': float(r.get('score') or 0),
                    'kind': d.get('attack_type') or 'anomaly'})
    return out


def level(score):
    return 'trusted' if score >= TRUSTED else 'watch' if score >= WATCH else 'untrusted'


def score_device(ip, now=None, device=None, alerts=(), false_positive=frozenset(), restrictions=(),
                 first_seen=None, profile_learned=False):
    now = now or time.time()
    score, reasons = 50.0, []
    if device:
        score += 10
        reasons.append(f"+10 known MAC address {device.get('mac')}")
        if device.get('vendor'):
            score += 5
            reasons.append(f"+5 vendor {device['vendor']}")
        if device.get('hostname'):
            score += 5
            reasons.append(f"+5 hostname {device['hostname']}")
        first_seen = min(x for x in (first_seen, device.get('first_seen')) if x) if first_seen else device.get('first_seen')
    else:
        score -= 10
        reasons.append('-10 no MAC address seen for this IP')
    if first_seen:
        days = max(0.0, (now - first_seen) / 86400)
        bonus = min(20.0, 2 * days)
        score += bonus
        reasons.append(f'+{bonus:.0f} seen for {days:.1f} days')

    penalty, counted, ignored, strongest = 0.0, 0, 0, None
    for a in alerts:
        if a['src'] != ip or now - a['ts'] > WINDOW or a['ts'] > now + 60:
            continue
        if (ip, a['kind']) in false_positive:
            ignored += 1
            continue
        counted += 1
        penalty += 25 * a['risk'] / 100 * 0.5 ** (max(0.0, now - a['ts']) / HALF_LIFE)
        if strongest is None or a['risk'] > strongest['risk']:
            strongest = a
    if counted:
        penalty = min(80.0, penalty)
        score -= penalty
        reasons.append(f"-{penalty:.0f} {counted} alert{'s' if counted > 1 else ''} in the last 7 days "
                       f"(strongest: {strongest['kind']}, risk {strongest['risk']:.0f})")
    if ignored:
        reasons.append(f'{ignored} alert{"s" if ignored > 1 else ""} ignored (marked false positive)')

    kinds = {r['kind'] for r in restrictions if r.get('ip') == ip}
    if kinds & {'quarantine', 'block'}:
        score = 0
        reasons.append('currently ' + ('quarantined' if 'quarantine' in kinds else 'blocked'))
    elif 'contain' in kinds:
        score = min(score, 30)
        reasons.append('currently contained to its learned peers')

    score = int(round(max(0.0, min(100.0, score))))
    lvl = level(score)
    if lvl != 'untrusted' or kinds:
        recommendation = 'none' if lvl == 'trusted' else 'watch'
        if kinds:
            recommendation = 'keep restricted' if lvl == 'untrusted' else 'consider releasing'
    else:
        recommendation = 'contain' if profile_learned else 'quarantine (no learned peer profile yet)'
    return {'ip': ip, 'score': score, 'level': lvl, 'reasons': reasons, 'recommendation': recommendation,
            'profile_learned': profile_learned}


def _load_alerts(limit=5000):
    try:
        from core.storage import get_storage
        s = get_storage('data/sentinel.db')
        s.connect()
        return normalise_alerts(s.get_alerts(limit=limit))
    except Exception:
        return []


def scores(now=None):
    """Trust for every device we know of: identity registry, peer profiles and recent alert sources."""
    import core.firewall as firewall
    from detection.feedback import get_store
    from enforcement import identity
    now = now or time.time()
    devices = {d['ip']: d for d in identity.get_registry().list(limit=5000) if d.get('ip')}
    store = peer_profiles.PeerStore()
    try:
        first = store.first_seen()
        alerts = _load_alerts()
        try:
            fps = get_store().false_positive_kinds(since=now - WINDOW)
        except Exception:
            fps = set()
        restrictions = list(firewall.list_restrictions())
        restrictions += [{'ip': r['ip'], 'kind': 'block'} for r in firewall.list_rules() if r.get('blocked')]
        ips = set(devices) | set(first) | {a['src'] for a in alerts if now - a['ts'] <= WINDOW}
        out = []
        for ip in sorted(ips):
            profile = store.profile(ip) if ip in first else None
            out.append(score_device(ip, now, devices.get(ip), alerts, fps, restrictions, first.get(ip),
                                    peer_profiles.learned(profile, now)))
    finally:
        store.close()
    return sorted(out, key=lambda d: (d['score'], d['ip']))
