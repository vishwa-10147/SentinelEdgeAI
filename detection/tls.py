"""TLS ClientHello metadata: JA3 and JA4 fingerprints, SNI and ALPN (no decryption).

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
from collections import defaultdict

from detection.detectors import Cooldown, Finding, is_external

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
        self.seen = defaultdict(set)          # src -> fingerprints used
        self.first = {}
        self.learning = learning
        self.clock = clock
        self.cooldown = Cooldown(1800)

    def observe(self, src, dst, hello, ts=None):
        ts = ts or self.clock()
        out = []
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
