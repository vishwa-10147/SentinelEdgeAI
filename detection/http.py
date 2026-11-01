"""Plain-HTTP request metadata and JA4H client fingerprints (Phase 9, encrypted-traffic companion).

Only the request line and header *names* are read, plus three header values
that matter: Host, User-Agent and the first Accept-Language tag. The request
path, cookies' values and any credentials are never kept: cookie names and
name=value pairs only go into one-way JA4H hashes, and an Authorization header
is only noted as present (and its scheme).

JA4H follows the FoxIO layout:
    <method 2><version 2><cookie c|n><referer r|n><#headers 2><lang 4>
    _<sha256 of header names in order, without Cookie and Referer, 12 hex>
    _<sha256 of sorted cookie names, 12 hex>_<sha256 of sorted cookie name=value, 12 hex>

Findings (MITRE ATT&CK):
  http_known_bad   JA4H (full, or its first two parts) on the blocklist or in threat intel (T1071.001)
  http_lolbin      PowerShell or certutil fetching from an internet host: a download cradle (T1105)
  http_basic_auth  a password sent with HTTP Basic authentication over plain HTTP (credentials on the wire)
  http_new_client  a new HTTP client fingerprint on a device after its learning day (new software)
"""
import hashlib
import time

from common.bounded import BoundedDict
from detection.detectors import MAX_SOURCES, Cooldown, Finding, is_external

METHODS = (b'GET ', b'POST ', b'HEAD ', b'PUT ', b'DELETE ', b'OPTIONS ', b'PATCH ', b'CONNECT ')
# the first four bytes, for the capture fast path
METHOD_PREFIXES = frozenset(m[:4] for m in METHODS)
MAX_HEADERS = 64
NO_HASH = '000000000000'
# User-Agents of Windows tools that attackers use to download payloads ("living off the land")
LOLBIN_AGENTS = (('windowspowershell', 'PowerShell'), ('certutil url agent', 'certutil'))


def is_http_request(payload):
    return payload[:4] in METHOD_PREFIXES and any(payload.startswith(m) for m in METHODS)


def _h12(text):
    return hashlib.sha256(text.encode('utf-8', 'replace')).hexdigest()[:12]


def parse_http_request(payload):
    """{method, version, host, user_agent, auth_scheme, ja4h, ja4h_ab, headers} or None."""
    if not is_http_request(payload):
        return None
    head = payload[:8192].split(b'\r\n\r\n', 1)[0]
    lines = head.split(b'\r\n')
    parts = lines[0].split(b' ')
    if len(parts) != 3 or not parts[2].startswith(b'HTTP/'):
        return None
    method = parts[0].decode('ascii', 'replace')
    version = parts[2][5:].decode('ascii', 'replace')
    names, cookies, values = [], [], {}
    referer = False
    for line in lines[1:1 + MAX_HEADERS]:
        name, sep, value = line.partition(b':')
        if not sep or not name or name != name.strip():
            continue
        name = name.decode('latin-1')
        low = name.lower()
        value = value.strip().decode('latin-1')
        if low == 'cookie':
            cookies += [c.strip() for c in value.split(';') if c.strip()]
            continue
        if low == 'referer':
            referer = True
            continue
        names.append(name)
        if low in ('host', 'user-agent', 'accept-language', 'authorization'):
            values.setdefault(low, value)
    lang = values.get('accept-language', '').split(',')[0].split(';')[0].replace('-', '').lower()[:4]
    lang = (lang + '0000')[:4] if lang else '0000'
    ver = {'1.1': '11', '1.0': '10', '2': '20', '2.0': '20', '0.9': '09'}.get(version, '00')
    a = (f"{method[:2].lower()}{ver}{'c' if cookies else 'n'}{'r' if referer else 'n'}"
         f"{min(len(names), 99):02d}{lang}")
    b = _h12(','.join(names))
    if cookies:
        c = _h12(','.join(sorted(k.split('=', 1)[0] for k in cookies)))
        d = _h12(','.join(sorted(cookies)))
    else:
        c = d = NO_HASH
    auth = values.get('authorization', '')
    return {'method': method, 'version': version, 'host': values.get('host', '')[:255] or None,
            'user_agent': values.get('user-agent', '')[:200] or None,
            'auth_scheme': auth.split(' ', 1)[0].lower() if auth else None,
            'ja4h': f'{a}_{b}_{c}_{d}', 'ja4h_ab': f'{a}_{b}', 'headers': len(names)}


class HTTPDetector:
    def __init__(self, blocklist=None, learning=86400, clock=time.time):
        if blocklist is None:
            from detection.tls import load_blocklist
            blocklist = load_blocklist()
        self.blocklist = blocklist
        self.learning = learning
        self.clock = clock
        self.seen = BoundedDict(MAX_SOURCES, set)       # src -> JA4H a_b used
        self.first = BoundedDict(MAX_SOURCES)
        self.cooldown = Cooldown(1800)
        self.daily = Cooldown(86400)

    def observe(self, src, dst, req, ts=None, intel=None):
        """Findings for one parsed request from `src` to `dst`. `intel` is an optional fingerprint matcher."""
        ts = ts or self.clock()
        out = []
        if is_external(src):
            return out
        host = req.get('host') or dst
        for fp in ((req['ja4h'], req['ja4h_ab']) if req.get('ja4h') else ()):
            label = self.blocklist.get(fp.lower())
            listed = (label, 'blocklist') if label else None
            if listed is None and intel is not None:
                hit = intel(fp)
                listed = (hit[1] or 'listed fingerprint', hit[0]) if hit else None
            if listed and self.cooldown.ready(('http_known_bad', src, fp), ts):
                from intel.sharing import trust_for
                sev, prob = trust_for(listed[1]) or (85, 0.85)
                out.append(Finding('http_known_bad', src, sev, prob, 'T1071.001',
                                   f'HTTP client fingerprint {fp} from {src} to {host} is listed by {listed[1]} '
                                   f'({listed[0]})', {'fingerprint': fp, 'host': host, 'target': dst,
                                                      'protocol': 'http'}, ts=ts))
                break
        ua = (req.get('user_agent') or '').lower()
        if is_external(dst):
            for needle, tool in LOLBIN_AGENTS:
                if needle in ua and self.cooldown.ready(('http_lolbin', src, host), ts):
                    out.append(Finding('http_lolbin', src, 60, 0.45, 'T1105',
                                       f'{tool} on {src} fetched from internet host {host} over plain HTTP '
                                       '(a common way to download malware)',
                                       {'tool': tool, 'host': host, 'target': dst, 'protocol': 'http',
                                        'user_agent': req.get('user_agent')}, ts=ts))
        if req.get('auth_scheme') == 'basic' and self.daily.ready(('http_basic_auth', src, dst), ts):
            # an exposure rather than an attack: low probability, never a response on its own
            out.append(Finding('http_basic_auth', src, 35, 0.2, 'T1040',
                               f'{src} sent a password to {host} with HTTP Basic authentication over plain HTTP; '
                               'anyone on the path can read it', {'host': host, 'target': dst,
                                                                  'protocol': 'http'}, ts=ts))
        if not req.get('ja4h_ab'):
            return out
        self.first.setdefault(src, ts)
        fps = self.seen[src]
        if req['ja4h_ab'] not in fps:
            if fps and ts - self.first[src] > self.learning and \
                    self.cooldown.ready(('http_new_client', src, req['ja4h_ab']), ts):
                out.append(Finding('http_new_client', src, 25, 0.2, 'T1071.001',
                                   f'new HTTP client fingerprint {req["ja4h_ab"]} on {src} '
                                   f'(User-Agent {req.get("user_agent") or "none"})',
                                   {'ja4h': req['ja4h'], 'host': host, 'protocol': 'http'}, ts=ts))
            fps.add(req['ja4h_ab'])
        return out
