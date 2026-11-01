"""Passive OS and device-type fingerprinting (Phase 9, asset context).

Nothing is sent to the device. Two kinds of evidence are combined:

* **TCP SYN fingerprint.** The first packet of every connection a device opens
  carries choices its operating system makes: the initial TTL, the window
  size and scale, the MSS and, above all, which TCP options it sends and in
  what order. Windows, Linux/Android, Apple and BSD stacks differ in a stable
  way. The signature format follows the idea of p0f v3
  (`version:initial-ttl:ip-options:mss:window,scale:option-layout:quirks`);
  the classification rules below are our own, not p0f's database.
* **Identity the device already announced** (enforcement.identity): DHCP
  vendor class (option 60), DHCP parameter list (option 55), the IEEE OUI
  vendor of its MAC and its DHCP hostname.

Only internal hosts are fingerprinted (a SYN from the internet says nothing
about the site's assets). The capture paths call `observe_ip()` with the IP
header of every TCP packet; it returns at once for anything that is not a
SYN, and for a source seen within the last minute, so floods cost a dict
lookup. Fingerprints are stored in the device database (one row per address,
capped) with a write budget, because the API reads them from another process.

    python -m enforcement osfp list
    python -m enforcement osfp show 192.168.1.20
"""
import ipaddress
import os
import sqlite3
import struct
import threading
import time

from common.bounded import BoundedDict

RECHECK_SECONDS = 60                  # one parse per source per minute
TOUCH_SECONDS = 600                   # refresh last_seen in the database at most this often
MAX_HOSTS = int(os.environ.get('SENTINEL_MAX_DEVICES', '20000'))
WRITES_PER_SECOND = 20                # database writes; beyond this, sightings are skipped (counted)

_OPT_NAMES = {0: 'eol', 1: 'nop', 2: 'mss', 3: 'ws', 4: 'sok', 5: 'sack', 8: 'ts'}

# ---------- parsing ----------


def initial_ttl(ttl):
    """The TTL the sender most likely started with (stacks use 32, 64, 128 or 255)."""
    for start in (32, 64, 128, 255):
        if ttl <= start:
            return start
    return 255


def _tcp_options(data):
    """(layout list, mss, window scale, quirks) from the raw TCP options."""
    layout, mss, ws, quirks = [], None, None, []
    i, n = 0, len(data)
    while i < n:
        kind = data[i]
        if kind == 0:
            layout.append('eol')
            if any(data[i + 1:]):
                quirks.append('pad')            # non-zero bytes after end-of-options
            break
        if kind == 1:
            layout.append('nop')
            i += 1
            continue
        if i + 1 >= n:
            quirks.append('bad')
            break
        length = data[i + 1]
        if length < 2 or i + length > n:
            quirks.append('bad')
            break
        name = _OPT_NAMES.get(kind, f'?{kind}')
        layout.append(name)
        body = data[i + 2:i + length]
        if kind == 2 and len(body) == 2:
            mss = struct.unpack('!H', body)[0]
        elif kind == 3 and len(body) == 1:
            ws = body[0]
            if ws > 14:
                quirks.append('exws')           # window scale above the RFC 7323 maximum
        elif kind == 8 and len(body) == 8:
            tsval, tsecr = struct.unpack('!II', body)
            if tsval == 0:
                quirks.append('ts1-')
            if tsecr:
                quirks.append('ts2+')           # echo reply set in a SYN
        i += length
    return layout, mss, ws, quirks


def parse_syn(ip):
    """Fingerprint fields from an IP packet holding a TCP SYN (without ACK), or None.

    `ip` starts at the IPv4 or IPv6 header (bytes or memoryview). IPv6 extension
    headers are not walked: such packets are skipped.
    """
    if len(ip) < 20:
        return None
    version = ip[0] >> 4
    quirks = []
    if version == 4:
        ihl = (ip[0] & 0x0F) * 4
        if ihl < 20 or ip[9] != 6 or len(ip) < ihl + 20:
            return None
        flags_frag = struct.unpack_from('!H', ip, 6)[0]
        if flags_frag & 0x1FFF:
            return None
        df = bool(flags_frag & 0x4000)
        if df:
            quirks.append('df')
            if struct.unpack_from('!H', ip, 4)[0] == 0:
                quirks.append('id0')            # DF set and IP ID zero (Linux does this)
        elif struct.unpack_from('!H', ip, 4)[0] == 0:
            quirks.append('id0-df')
        ttl = ip[8]
        olen = ihl - 20
        src = '.'.join(str(b) for b in bytes(ip[12:16]))
        tcp = ip[ihl:]
    elif version == 6:
        if len(ip) < 60 or ip[6] != 6:
            return None
        if (struct.unpack_from('!I', ip, 0)[0] & 0x000FFFFF):
            quirks.append('flow')               # non-zero flow label
        ttl = ip[7]
        olen = 0
        src = str(ipaddress.IPv6Address(bytes(ip[8:24])))
        tcp = ip[40:]
    else:
        return None
    if len(tcp) < 20:
        return None
    flags = tcp[13]
    if flags & 0x12 != 0x02:                    # SYN without ACK: the client side of a handshake
        return None
    if flags & 0xC0:
        quirks.append('ecn')
    data_off = (tcp[12] >> 4) * 4
    if data_off < 20 or len(tcp) < data_off:
        return None
    window = struct.unpack_from('!H', tcp, 14)[0]
    layout, mss, ws, oquirks = _tcp_options(bytes(tcp[20:data_off]))
    quirks += oquirks
    if struct.unpack_from('!I', tcp, 8)[0]:
        quirks.append('ack+')                   # acknowledgement number set without ACK
    if len(tcp) > data_off:
        quirks.append('data')                   # payload in the SYN (TCP Fast Open or odd stacks)
    ittl = initial_ttl(ttl)
    fp = {
        'src': src, 'version': version, 'ttl': ttl, 'initial_ttl': ittl, 'hops': ittl - ttl,
        'ip_options': olen, 'mss': mss, 'window': window, 'wscale': ws,
        'layout': ','.join(layout), 'quirks': ','.join(quirks),
    }
    fp['signature'] = (f"{version}:{ittl}:{olen}:{mss if mss is not None else '*'}:"
                       f"{window},{ws if ws is not None else '*'}:{fp['layout']}:{fp['quirks']}")
    return fp


# ---------- classification ----------


def classify(fp):
    """{'os', 'family', 'confidence' (high|medium|low), 'reason'} for a parsed SYN."""
    ittl, layout = fp['initial_ttl'], fp['layout']

    def out(os_name, family, confidence, reason):
        return {'os': os_name, 'family': family, 'confidence': confidence, 'reason': reason}

    if ittl == 128:
        if layout.startswith('mss,nop') and 'sok' in layout and 'ts' not in layout:
            return out('Windows', 'windows', 'high', 'initial TTL 128, Windows TCP option order')
        return out('Windows (probably)', 'windows', 'medium', 'initial TTL 128')
    if ittl == 64:
        if layout == 'mss,sok,ts,nop,ws':
            return out('Linux / Android', 'linux', 'high', 'initial TTL 64, Linux TCP option order')
        if layout.startswith('mss,nop,ws,nop,nop,ts,sok'):
            return out('macOS / iOS', 'apple', 'high', 'initial TTL 64, Apple TCP option order')
        if layout == 'mss,nop,ws,sok,ts':
            return out('FreeBSD', 'bsd', 'high', 'initial TTL 64, FreeBSD TCP option order')
        if layout in ('', 'mss'):
            return out('Embedded / IoT stack', 'embedded', 'medium',
                       'initial TTL 64 with few or no TCP options (lwIP-style minimal stack)')
        if layout.startswith('mss,sok,ts'):
            return out('Linux (probably)', 'linux', 'medium', 'initial TTL 64, Linux-like option order')
        return out('Unix-like', 'unix', 'low', 'initial TTL 64')
    if ittl == 255:
        if layout in ('', 'mss'):
            return out('Network device / RTOS', 'network', 'medium',
                       'initial TTL 255 with few or no TCP options')
        return out('Network device or Unix (TTL 255)', 'network', 'low', 'initial TTL 255')
    return out('Embedded (TTL 32)', 'embedded', 'low', 'initial TTL 32')


# vendor (IEEE OUI) keywords -> device type; first match wins
_VENDOR_TYPES = (
    (('raspberry pi',), 'Single-board computer'),
    (('brother', 'canon', 'seiko epson', 'epson', 'xerox', 'lexmark', 'kyocera', 'ricoh', 'konica'), 'Printer'),
    (('hikvision', 'dahua', 'axis communications', 'hanwha', 'reolink', 'amcrest', 'uniview'), 'IP camera'),
    (('siemens', 'rockwell', 'allen-bradley', 'schneider', 'wago', 'phoenix contact', 'beckhoff', 'omron',
      'mitsubishi electric', 'moxa', 'yokogawa', 'emerson', 'hirschmann', 'pilz', 'b&r'), 'Industrial device'),
    (('cisco', 'juniper', 'ubiquiti', 'mikrotik', 'routerboard', 'aruba', 'fortinet', 'palo alto',
      'zyxel', 'netgear', 'd-link', 'tp-link', 'ruckus', 'extreme networks', 'meraki'), 'Network device'),
    (('espressif', 'tuya', 'shelly', 'allterco', 'itead', 'signify', 'philips lighting', 'sonos', 'roku',
      'ring llc', 'nest labs', 'ecobee', 'amazon technologies'), 'IoT / smart device'),
    (('vmware', 'parallels', 'xensource'), 'Virtual machine'),
    (('apple',), 'Apple device'),
)
_HOSTNAME_HINTS = (
    (('iphone', 'ipad'), 'Phone / tablet', 'iOS'),
    (('macbook', 'imac', 'mac-mini', 'macmini'), 'Computer', 'macOS'),
    (('android', 'galaxy', 'pixel'), 'Phone / tablet', 'Android'),
    (('desktop-', 'laptop-'), 'Computer', 'Windows'),     # Windows default computer names
    (('raspberrypi',), 'Single-board computer', 'Linux'),
    (('npi', 'printer', 'brw', 'epson'), 'Printer', None),
    (('esp_', 'esp-', 'shelly', 'tasmota'), 'IoT / smart device', None),
)
_FAMILY_TYPES = {'windows': 'Computer', 'apple': 'Apple device', 'bsd': 'Server / appliance',
                 'embedded': 'Embedded / IoT device', 'network': 'Network device'}
_RANK = {'high': 3, 'medium': 2, 'low': 1}


def _vendor_class_os(vclass):
    v = (vclass or '').lower()
    if v.startswith('msft'):
        return 'Windows'
    if v.startswith('android-dhcp'):
        return 'Android'
    if v.startswith('dhcpcd'):
        return 'Linux'
    if v.startswith('udhcp'):
        return 'Embedded Linux (BusyBox)'
    return None


def _family(os_name):
    o = (os_name or '').lower()
    for key, fam in (('windows', 'windows'), ('android', 'linux'), ('busybox', 'embedded'), ('linux', 'linux'),
                     ('macos', 'apple'), ('ios', 'apple'), ('freebsd', 'bsd'), ('embedded', 'embedded'),
                     ('network', 'network'), ('unix', 'unix')):
        if key in o:
            return fam
    return None


def infer(device=None, fp=None):
    """Combine a device registry row and a SYN fingerprint into one profile.

    Returns {'os', 'device_type', 'confidence', 'evidence': [{'source', 'says', 'confidence'}]}.
    Evidence the device chose to announce (DHCP) is weighed above the TCP guess, except that a
    high-confidence TCP fingerprint is never overridden by a hostname.
    """
    device = device or {}
    evidence = []
    os_votes = []            # (rank, os)
    type_votes = []          # (rank, type)

    vc_os = _vendor_class_os(device.get('vendor_class'))
    if vc_os:
        evidence.append({'source': 'DHCP vendor class', 'says': vc_os, 'confidence': 'high',
                         'detail': device.get('vendor_class')})
        os_votes.append((3.5, vc_os))
    if fp:
        c = classify(fp)
        evidence.append({'source': 'TCP SYN fingerprint', 'says': c['os'], 'confidence': c['confidence'],
                         'detail': f"{fp['signature']} ({c['reason']}, {fp['hops']} hop(s) away)"})
        os_votes.append((_RANK[c['confidence']], c['os']))
        if c['family'] in _FAMILY_TYPES:
            type_votes.append((1, _FAMILY_TYPES[c['family']]))
    dhcp55 = [x.strip() for x in str(device.get('dhcp_fingerprint') or '').split(',') if x.strip()]
    if '249' in dhcp55:          # Microsoft classless static routes: requested only by Windows
        evidence.append({'source': 'DHCP parameter list', 'says': 'Windows', 'confidence': 'medium',
                         'detail': 'requests option 249'})
        os_votes.append((2.5, 'Windows'))
    vendor = (device.get('vendor') or '')
    if vendor:
        low = vendor.lower()
        if 'randomised' in low:
            evidence.append({'source': 'MAC address', 'says': 'Phone, tablet or laptop (randomised MAC)',
                             'confidence': 'low', 'detail': vendor})
            type_votes.append((1, 'Phone / tablet / laptop'))
        else:
            for keys, dtype in _VENDOR_TYPES:
                if any(k in low for k in keys):
                    evidence.append({'source': 'MAC vendor', 'says': dtype, 'confidence': 'medium', 'detail': vendor})
                    type_votes.append((2, dtype))
                    break
    host = (device.get('hostname') or '').lower()
    if host:
        for keys, dtype, hos in _HOSTNAME_HINTS:
            if any(host.startswith(k) or k in host for k in keys):
                evidence.append({'source': 'DHCP hostname', 'says': hos or dtype, 'confidence': 'low',
                                 'detail': device.get('hostname')})
                type_votes.append((1.5, dtype))
                if hos:
                    os_votes.append((1.5, hos))
                break

    os_name = max(os_votes, key=lambda v: v[0])[1] if os_votes else None
    # refine the TCP family with announced identity: a Linux stack that says "android-dhcp" is Android
    if os_name == 'Linux / Android' and any(o in ('Android', 'Linux') for _, o in os_votes if o != os_name):
        os_name = next(o for _, o in sorted(os_votes, reverse=True) if o in ('Android', 'Linux'))
    if os_name == 'macOS / iOS' and any(o in ('iOS', 'macOS') for _, o in os_votes):
        os_name = next(o for _, o in sorted(os_votes, reverse=True) if o in ('iOS', 'macOS'))
    device_type = max(type_votes, key=lambda v: v[0])[1] if type_votes else None
    if device_type in (None, 'Apple device') and os_name == 'iOS':
        device_type = 'Phone / tablet'
    if device_type is None and os_name == 'Android':
        device_type = 'Phone / tablet'
    if device_type is None and os_name and ('Linux' in os_name or os_name in ('Unix-like', 'FreeBSD')):
        device_type = 'Computer / server'

    family = _family(os_name)
    agreeing = sum(1 for _, o in os_votes if family and _family(o) == family)
    top = max((rank for rank, o in os_votes if _family(o) == family), default=0)
    if os_name is None:
        confidence = 'low' if type_votes else None
    elif agreeing >= 2 or top >= 3:
        confidence = 'high'
    else:
        confidence = 'medium' if top >= 2 else 'low'
    return {'os': os_name, 'device_type': device_type, 'confidence': confidence, 'evidence': evidence}


# ---------- store ----------


def _internal(ip):
    from detection.peers import _internal as peers_internal
    return peers_internal(ip) is True


class FingerprintStore:
    """Latest SYN fingerprint per internal address, in the device database."""

    def __init__(self, path=None):
        from enforcement.identity import default_path
        self.path = path or default_path()
        self._lock = threading.Lock()
        self._conn = None
        self._seen = BoundedDict(MAX_HOSTS)        # ip -> (monotonic time parsed, signature, wall time written)
        self._budget = [0.0, 0]                    # second, writes in that second
        self.skipped = 0                           # sightings not written because of the write budget

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("""CREATE TABLE IF NOT EXISTS tcp_fingerprints (
                ip TEXT PRIMARY KEY, signature TEXT NOT NULL, os TEXT, family TEXT, confidence TEXT,
                ttl INTEGER, hops INTEGER, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                changes INTEGER NOT NULL DEFAULT 0)""")
            conn.execute('CREATE INDEX IF NOT EXISTS tcp_fingerprints_seen ON tcp_fingerprints(last_seen)')
            conn.commit()
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _spend(self):
        now = int(time.monotonic())
        if self._budget[0] != now:
            self._budget = [now, 0]
        if self._budget[1] >= WRITES_PER_SECOND:
            self.skipped += 1
            return False
        self._budget[1] += 1
        return True

    def observe_ip(self, ip_bytes, now=None):
        """Feed the IP header of a TCP packet. Returns the fingerprint when one was recorded. Never raises."""
        try:
            if len(ip_bytes) < 20:
                return None
            v = ip_bytes[0] >> 4
            # cheap pre-checks before any parsing: TCP, and the SYN-without-ACK flag pair
            if v == 4:
                off = (ip_bytes[0] & 0x0F) * 4
                if ip_bytes[9] != 6 or len(ip_bytes) < off + 14:
                    return None
                key = bytes(ip_bytes[12:16])
            elif v == 6:
                off = 40
                if ip_bytes[6] != 6 or len(ip_bytes) < 54:
                    return None
                key = bytes(ip_bytes[8:24])
            else:
                return None
            if ip_bytes[off + 13] & 0x12 != 0x02:
                return None
            mono = time.monotonic() if now is None else now
            seen = self._seen.get(key)
            if seen is not None and mono - seen[0] < RECHECK_SECONDS:
                return None
            fp = parse_syn(ip_bytes)
            if fp is None or not _internal(fp['src']):
                self._seen[key] = (mono, None, 0)
                return None
            wall = int(time.time())
            if seen is not None and seen[1] == fp['signature'] and wall - seen[2] < TOUCH_SECONDS:
                self._seen[key] = (mono, seen[1], seen[2])
                self._seen.touch(key)
                return None
            if not self._spend():
                return None
            self._record(fp, wall)
            self._seen[key] = (mono, fp['signature'], wall)
            self._seen.touch(key)
            return fp
        except Exception:
            return None

    def _record(self, fp, wall):
        c = classify(fp)
        with self._lock:
            db = self._db()
            row = db.execute('SELECT signature FROM tcp_fingerprints WHERE ip = ?', (fp['src'],)).fetchone()
            if row is None:
                if db.execute('SELECT COUNT(*) FROM tcp_fingerprints').fetchone()[0] >= MAX_HOSTS:
                    db.execute('DELETE FROM tcp_fingerprints WHERE ip = '
                               '(SELECT ip FROM tcp_fingerprints ORDER BY last_seen LIMIT 1)')
                db.execute('INSERT INTO tcp_fingerprints(ip, signature, os, family, confidence, ttl, hops, '
                           'first_seen, last_seen) VALUES (?,?,?,?,?,?,?,?,?)',
                           (fp['src'], fp['signature'], c['os'], c['family'], c['confidence'], fp['ttl'],
                            fp['hops'], wall, wall))
            else:
                changed = 1 if row['signature'] != fp['signature'] else 0
                db.execute('UPDATE tcp_fingerprints SET signature = ?, os = ?, family = ?, confidence = ?, '
                           'ttl = ?, hops = ?, last_seen = ?, changes = changes + ? WHERE ip = ?',
                           (fp['signature'], c['os'], c['family'], c['confidence'], fp['ttl'], fp['hops'],
                            wall, changed, fp['src']))
            db.commit()

    def get(self, ip):
        with self._lock:
            row = self._db().execute('SELECT * FROM tcp_fingerprints WHERE ip = ?', (str(ip),)).fetchone()
        return dict(row) if row else None

    def list(self, limit=500):
        with self._lock:
            rows = self._db().execute('SELECT * FROM tcp_fingerprints ORDER BY last_seen DESC LIMIT ?',
                                      (int(limit),)).fetchall()
        return [dict(r) for r in rows]


def fp_from_row(row):
    """Rebuild the fields classify()/infer() need from a stored row."""
    if not row:
        return None
    parts = row['signature'].split(':')
    if len(parts) != 7:
        return None
    return {'signature': row['signature'], 'initial_ttl': int(parts[1]), 'layout': parts[5],
            'quirks': parts[6], 'ttl': row.get('ttl'), 'hops': row.get('hops') or 0}


_store = None


def get_store():
    global _store
    from enforcement.identity import default_path
    if _store is None or _store.path != default_path():
        _store = FingerprintStore()
    return _store


def observe_ip(ip_bytes):
    return get_store().observe_ip(ip_bytes)


def profile(ip, registry=None, store=None):
    """Everything known about the device at `ip`: identity row, SYN fingerprint and the combined guess."""
    from enforcement import identity
    reg = registry or identity.get_registry()
    st = store or get_store()
    device = reg.by_ip(ip)
    row = st.get(ip)
    result = infer(device, fp_from_row(row))
    result.update({'ip': ip, 'mac': (device or {}).get('mac'), 'vendor': (device or {}).get('vendor'),
                   'hostname': (device or {}).get('hostname'), 'tcp_signature': (row or {}).get('signature'),
                   'tcp_first_seen': (row or {}).get('first_seen'), 'tcp_last_seen': (row or {}).get('last_seen'),
                   'tcp_changes': (row or {}).get('changes', 0)})
    return result


def profiles(limit=500, registry=None, store=None):
    """A profile for every address with a fingerprint or a registry entry, newest first."""
    from enforcement import identity
    reg = registry or identity.get_registry()
    st = store or get_store()
    ips = []
    for d in reg.list(limit=limit):
        if d.get('ip') and d['ip'] not in ips:
            ips.append(d['ip'])
    for r in st.list(limit=limit):
        if r['ip'] not in ips:
            ips.append(r['ip'])
    return [profile(ip, reg, st) for ip in ips[:int(limit)]]
