"""TLS metadata: JA3/JA4 client and JA4S server fingerprints, SNI, ALPN and certificates (no decryption).

Server certificates are only visible up to TLS 1.2; TLS 1.3 encrypts them, so
for those only JA4S is known.

parse_client_hello() works on the first bytes of a TCP payload. JA3 follows
the original Salesforce definition (MD5 of version,ciphers,extensions,
groups,point formats, GREASE removed); JA4 follows the FoxIO layout
(t<ver><sni><#ciphers><#ext><alpn>_<sha256 ciphers>_<sha256 ext+sigalgs>).
"""
import hashlib
import ipaddress
import os
import struct
import time

from common.bounded import BoundedDict
from detection.detectors import MAX_SOURCES, Cooldown, Finding, is_external

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TLS_VERSIONS = {0x0304: '13', 0x0303: '12', 0x0302: '11', 0x0301: '10', 0x0300: 's3'}


def _grease(v):
    return (v & 0x0F0F) == 0x0A0A and (v >> 8) == (v & 0xFF)


def _u16list(data):
    return [struct.unpack('>H', data[i:i + 2])[0] for i in range(0, len(data) - 1, 2)]


def parse_client_hello(payload):
    """Return a dict with ja3, ja4, sni, alpn, version, or None if not a ClientHello."""
    try:
        if len(payload) < 43 or payload[0] != 0x16 or payload[5] != 0x01:
            return None
        p = 9                                     # record header (5) + handshake header (4)
        legacy_version = struct.unpack('>H', payload[p:p + 2])[0]
        p += 2 + 32                               # version + random
        sid_len = payload[p]
        p += 1 + sid_len
        cs_len = struct.unpack('>H', payload[p:p + 2])[0]
        ciphers = [c for c in _u16list(payload[p + 2:p + 2 + cs_len]) if not _grease(c)]
        p += 2 + cs_len
        comp_len = payload[p]
        p += 1 + comp_len
        extensions, groups, point_formats, sigalgs, alpn, versions = [], [], [], [], [], []
        sni = None
        if p + 2 <= len(payload):
            ext_total = struct.unpack('>H', payload[p:p + 2])[0]
            p += 2
            end = min(len(payload), p + ext_total)
            while p + 4 <= end:
                etype, elen = struct.unpack('>HH', payload[p:p + 4])
                data = payload[p + 4:p + 4 + elen]
                p += 4 + elen
                if _grease(etype):
                    continue
                extensions.append(etype)
                if etype == 0 and len(data) > 5:                       # server_name
                    name_len = struct.unpack('>H', data[3:5])[0]
                    sni = data[5:5 + name_len].decode('ascii', 'replace')
                elif etype == 10 and len(data) >= 2:                   # supported_groups
                    groups = [g for g in _u16list(data[2:2 + struct.unpack('>H', data[:2])[0]]) if not _grease(g)]
                elif etype == 11 and data:                             # ec_point_formats
                    point_formats = list(data[1:1 + data[0]])
                elif etype == 13 and len(data) >= 2:                   # signature_algorithms
                    sigalgs = _u16list(data[2:2 + struct.unpack('>H', data[:2])[0]])
                elif etype == 16 and len(data) >= 3:                   # ALPN
                    q = 2
                    while q < len(data):
                        n = data[q]
                        alpn.append(data[q + 1:q + 1 + n].decode('ascii', 'replace'))
                        q += 1 + n
                elif etype == 43 and data:                             # supported_versions
                    versions = [v for v in _u16list(data[1:1 + data[0]]) if not _grease(v)]
    except (IndexError, struct.error):
        return None

    ja3_str = ','.join([str(legacy_version), '-'.join(map(str, ciphers)), '-'.join(map(str, extensions)),
                        '-'.join(map(str, groups)), '-'.join(map(str, point_formats))])
    ja3 = hashlib.md5(ja3_str.encode(), usedforsecurity=False).hexdigest()

    version = max(versions) if versions else legacy_version
    sni_flag = 'i' if (sni is None or _is_ip(sni)) else 'd'
    first_alpn = alpn[0] if alpn else ''
    alpn_code = (first_alpn[0] + first_alpn[-1]) if first_alpn else '00'
    ja4_a = f't{TLS_VERSIONS.get(version, "00")}{sni_flag}{min(len(ciphers), 99):02d}{min(len(extensions), 99):02d}{alpn_code}'
    cipher_hex = ','.join(f'{c:04x}' for c in sorted(ciphers))
    ext_hex = ','.join(f'{e:04x}' for e in sorted(e for e in extensions if e not in (0, 16)))
    sig_hex = ','.join(f'{s:04x}' for s in sigalgs)
    ja4_b = hashlib.sha256(cipher_hex.encode()).hexdigest()[:12] if ciphers else '000000000000'
    ja4_c = hashlib.sha256((ext_hex + ('_' + sig_hex if sig_hex else '')).encode()).hexdigest()[:12]
    return {'ja3': ja3, 'ja3_string': ja3_str, 'ja4': f'{ja4_a}_{ja4_b}_{ja4_c}', 'sni': sni,
            'alpn': alpn, 'version': TLS_VERSIONS.get(version, hex(version))}


def _is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def blocklist_file():
    return os.environ.get('SENTINEL_JA3_BLOCKLIST') or os.path.join(ROOT, 'data', 'ja3_blocklist.txt')


def load_blocklist(path=None):
    """{fingerprint: label}. One per line: '<ja3 md5 or ja4> <label>'; '#' comments."""
    out = {}
    try:
        with open(path or blocklist_file(), 'r', encoding='utf-8') as f:
            for line in f:
                line = line.split('#', 1)[0].strip()
                if line:
                    fp, _, label = line.partition(' ')
                    out[fp.lower()] = label.strip() or 'listed fingerprint'
    except OSError:
        pass
    return out


class TLSDetector:
    def __init__(self, blocklist=None, learning=86400, clock=time.time):
        self.blocklist = load_blocklist() if blocklist is None else blocklist
        self.seen = BoundedDict(MAX_SOURCES, set)   # src -> fingerprints used
        self.first = BoundedDict(MAX_SOURCES)
        self.learning = learning
        self.clock = clock
        self.cooldown = Cooldown(1800)
        self.sni = BoundedDict(MAX_SOURCES)         # (client, server) -> last SNI, to check certificates

    def observe(self, src, dst, hello, ts=None):
        ts = ts or self.clock()
        out = []
        if hello.get('sni'):
            self.sni[(src, dst)] = hello['sni']
        for fp in (hello['ja3'], hello['ja4']):
            label = self.blocklist.get(fp.lower())
            if label and self.cooldown.ready(('tls_blocklist', src, fp), ts):
                out.append(Finding('tls_known_bad', src, 90, 0.9, 'T1071.001',
                                   f'TLS fingerprint {fp} matches the blocklist ({label}), to {dst}',
                                   {'fingerprint': fp, 'label': label, 'sni': hello.get('sni'), 'target': dst}, ts=ts))
        if is_external(dst) and (hello.get('sni') is None or _is_ip(hello.get('sni') or '')) \
                and self.cooldown.ready(('tls_no_sni', src, dst), ts):
            out.append(Finding('tls_no_sni', src, 35, 0.3, 'T1573',
                               f'TLS to external {dst} without a server name (SNI)', {'target': dst}, ts=ts))
        self.first.setdefault(src, ts)
        fps = self.seen[src]
        if hello['ja4'] not in fps:
            if fps and ts - self.first[src] > self.learning and self.cooldown.ready(('tls_new_fp', src, hello['ja4']), ts):
                out.append(Finding('tls_new_client', src, 30, 0.25, 'T1071.001',
                                   f'new TLS client fingerprint {hello["ja4"]} on this device (SNI {hello.get("sni")})',
                                   {'ja4': hello['ja4'], 'ja3': hello['ja3'], 'sni': hello.get('sni')}, ts=ts))
            fps.add(hello['ja4'])
        return out

    def observe_server(self, server, client, hello, certs, ts=None):
        """A reassembled server handshake (see ServerHandshakes); `client` is the source of findings."""
        return _server_observe(self, server, client, hello, certs, ts)


# ---------- server side: JA4S and certificates (Phase 9) ----------

TLS_HANDSHAKE_MAX = 32768          # bytes of server handshake kept per connection while reassembling
TLS_HANDSHAKE_SEGMENTS = 8
SHORT_LIVED_SECONDS = 3 * 86400


def ja4s(server_hello):
    """FoxIO JA4S from a parsed ServerHello: t<ver><#ext><alpn>_<cipher>_<sha256 ext in order>."""
    alpn = server_hello['alpn']
    alpn_code = (alpn[0] + alpn[-1]) if alpn else '00'
    a = f't{TLS_VERSIONS.get(server_hello["version_code"], "00")}{min(len(server_hello["extensions"]), 99):02d}{alpn_code}'
    ext = ','.join(f'{e:04x}' for e in server_hello['extensions'])
    c = hashlib.sha256(ext.encode()).hexdigest()[:12] if ext else '000000000000'
    return f'{a}_{server_hello["cipher"]:04x}_{c}'


def _parse_server_hello(body):
    legacy = struct.unpack('>H', body[0:2])[0]
    p = 2 + 32
    p += 1 + body[p]                                   # session id
    cipher = struct.unpack('>H', body[p:p + 2])[0]
    p += 3                                             # cipher + compression
    extensions, version, alpn = [], legacy, ''
    if p + 2 <= len(body):
        end = min(len(body), p + 2 + struct.unpack('>H', body[p:p + 2])[0])
        p += 2
        while p + 4 <= end:
            etype, elen = struct.unpack('>HH', body[p:p + 4])
            data = body[p + 4:p + 4 + elen]
            p += 4 + elen
            extensions.append(etype)
            if etype == 43 and len(data) == 2:         # supported_versions: the chosen one
                version = struct.unpack('>H', data)[0]
            elif etype == 16 and len(data) >= 4:
                alpn = data[3:3 + data[2]].decode('ascii', 'replace')
    out = {'version_code': version, 'version': TLS_VERSIONS.get(version, hex(version)), 'cipher': cipher,
           'extensions': extensions, 'alpn': alpn}
    out['ja4s'] = ja4s(out)
    return out


def _parse_certificates(body):
    """DER certificates from a TLS 1.0-1.2 Certificate message (leaf first)."""
    total = int.from_bytes(body[0:3], 'big')
    p, end, out = 3, min(len(body), 3 + total), []
    while p + 3 <= end and len(out) < 4:
        n = int.from_bytes(body[p:p + 3], 'big')
        out.append(bytes(body[p + 3:p + 3 + n]))
        p += 3 + n
    return out


def parse_server_handshake(data):
    """(server_hello or None, [DER certificates], complete) from in-order server handshake bytes.

    complete is True once nothing more can be learned: TLS 1.3 (certificates are
    encrypted), a Certificate message, or ServerHelloDone.
    """
    hs, p = bytearray(), 0
    while p + 5 <= len(data) and data[p] == 0x16:
        n = struct.unpack('>H', data[p + 3:p + 5])[0]
        hs += data[p + 5:p + 5 + n]
        if p + 5 + n > len(data):
            break
        p += 5 + n
    hello, certs, q = None, [], 0
    try:
        while q + 4 <= len(hs):
            mtype, n = hs[q], int.from_bytes(hs[q + 1:q + 4], 'big')
            if q + 4 + n > len(hs):
                break
            body = bytes(hs[q + 4:q + 4 + n])
            if mtype == 2:
                hello = _parse_server_hello(body)
                if hello['version_code'] == 0x0304:
                    return hello, [], True
            elif mtype == 11:
                return hello, _parse_certificates(body), True
            elif mtype == 14:
                return hello, certs, True
            q += 4 + n
    except (IndexError, struct.error):
        return hello, [], True
    return hello, certs, False


def _name_matches(name, patterns):
    name = name.lower().rstrip('.')
    for pat in patterns:
        pat = pat.lower().rstrip('.')
        if pat == name:
            return True
        if pat.startswith('*.') and name.count('.') == pat.count('.') and name.endswith(pat[1:]):
            return True
    return False


def certificate_facts(der):
    """Plain facts about a leaf certificate: subject, issuer, names, validity, self-signed."""
    from cryptography import x509
    cert = x509.load_der_x509_certificate(der)
    names = []
    try:
        names = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName)
    except x509.ExtensionNotFound:
        pass
    cn = [a.value for a in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)]
    return {'subject': cert.subject.rfc4514_string(), 'issuer': cert.issuer.rfc4514_string(),
            'names': list(names) or [str(v) for v in cn],
            'not_before': cert.not_valid_before_utc.timestamp(), 'not_after': cert.not_valid_after_utc.timestamp(),
            'self_signed': cert.issuer == cert.subject,
            'sha256': hashlib.sha256(der).hexdigest()}


def certificate_anomalies(facts, sni, now):
    reasons = []
    if facts['self_signed']:
        reasons.append('self-signed')
    life = facts['not_after'] - facts['not_before']
    if life < SHORT_LIVED_SECONDS:
        reasons.append(f'valid for only {life / 3600:.0f} hours')
    if now > facts['not_after']:
        reasons.append('expired')
    elif now < facts['not_before']:
        reasons.append('not valid yet')
    if sni and not _is_ip(sni) and facts['names'] and not _name_matches(sni, facts['names']):
        reasons.append(f'issued for {", ".join(facts["names"][:3])}, not {sni}')
    return reasons


class ServerHandshakes:
    """Reassembles the first server segments of TLS connections, in order, best effort."""

    def __init__(self, max_conns=4096):
        self.pending = BoundedDict(max_conns)          # (server, sport, client, cport) -> [bytes, segments]

    def feed(self, key, payload):
        """Parsed (server_hello, certs) once complete, else None."""
        entry = self.pending.get(key)
        if entry is None:
            if len(payload) < 6 or payload[0] != 0x16 or payload[5] != 0x02:
                return None
            entry = self.pending[key] = [b'', 0]
        entry[0] = (entry[0] + payload)[:TLS_HANDSHAKE_MAX]
        entry[1] += 1
        hello, certs, complete = parse_server_handshake(entry[0])
        if complete or entry[1] >= TLS_HANDSHAKE_SEGMENTS or len(entry[0]) >= TLS_HANDSHAKE_MAX:
            del self.pending[key]
            return (hello, certs) if hello else None
        return None


def _server_observe(self, server, client, hello, certs, ts=None):
    """Findings for one server handshake: blocklisted JA4S and certificate anomalies (external servers)."""
    ts = ts or self.clock()
    out = []
    label = self.blocklist.get(hello['ja4s'].lower())
    if label and self.cooldown.ready(('tls_blocklist', server, hello['ja4s']), ts):
        out.append(Finding('tls_known_bad', client, 90, 0.9, 'T1071.001',
                           f'TLS server {server} answers with fingerprint {hello["ja4s"]} on the blocklist ({label})',
                           {'fingerprint': hello['ja4s'], 'label': label, 'target': server}, ts=ts))
    if not certs or not is_external(server):
        return out                                  # internal devices are commonly self-signed
    try:
        facts = certificate_facts(certs[0])
    except Exception:
        return out
    sni = self.sni.get((client, server))
    reasons = certificate_anomalies(facts, sni, ts)
    if reasons and self.cooldown.ready(('tls_cert', server, facts['sha256']), ts):
        out.append(Finding('tls_cert_anomaly', client, min(70, 35 + 10 * len(reasons)), 0.35, 'T1573',
                           f'certificate of {server}' + (f' ({sni})' if sni else '') + ': ' + '; '.join(reasons),
                           {'target': server, 'sni': sni, 'reasons': reasons, 'issuer': facts['issuer'],
                            'subject': facts['subject'], 'sha256': facts['sha256'], 'ja4s': hello['ja4s']}, ts=ts))
    return out

