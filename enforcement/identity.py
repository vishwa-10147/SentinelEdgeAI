"""MAC-based device identity, so a device keeps its history when its IP changes.

Sources: the kernel ARP/neighbour table, ARP packets and DHCP packets seen by
the sniffer. Each device records its vendor (IEEE OUI), DHCP hostname, DHCP
fingerprint (the option 55 parameter list, which identifies the OS family),
vendor class (option 60) and every IP it has used.
"""
import json
import os
import re
import sqlite3
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
OUI_FILES = ('/usr/share/ieee-data/oui.txt', '/usr/share/nmap/nmap-mac-prefixes')
MAC_RE = re.compile(r'^([0-9a-f]{2}:){5}[0-9a-f]{2}$')
MAX_IPS = 20

_oui = None
_oui_lock = threading.Lock()


def default_path():
    return os.environ.get('SENTINEL_DEVICES_DB') or os.path.join(ROOT, 'data', 'devices.db')


def normalise_mac(mac):
    mac = str(mac or '').strip().lower().replace('-', ':')
    if MAC_RE.match(mac) and mac not in ('00:00:00:00:00:00', 'ff:ff:ff:ff:ff:ff'):
        return mac
    return None


def _load_oui():
    table = {}
    for path in OUI_FILES:
        try:
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if '(base 16)' in line:
                        prefix, _, vendor = line.partition('(base 16)')
                        table.setdefault(prefix.strip().upper(), vendor.strip())
                    elif re.match(r'^[0-9A-Fa-f]{6}\s', line):
                        table.setdefault(line[:6].upper(), line[7:].strip())
        except OSError:
            continue
    return table


def vendor(mac):
    mac = normalise_mac(mac)
    if not mac:
        return None
    if int(mac[:2], 16) & 0x02:
        return 'Private (randomised MAC)'
    global _oui
    with _oui_lock:
        if _oui is None:
            _oui = _load_oui()
    return _oui.get(mac.replace(':', '')[:6].upper())


def arp_table(path='/proc/net/arp'):
    """[(ip, mac, interface)] of complete neighbour entries."""
    out = []
    try:
        with open(path, 'r', encoding='ascii') as f:
            next(f, None)
            for line in f:
                parts = line.split()
                if len(parts) >= 6 and parts[2] != '0x0':
                    mac = normalise_mac(parts[3])
                    if mac:
                        out.append((parts[0], mac, parts[5]))
    except OSError:
        pass
    return out


class DeviceRegistry:
    def __init__(self, path=None):
        self.path = path or default_path()
        self._lock = threading.Lock()
        self._conn = None

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.execute("""CREATE TABLE IF NOT EXISTS devices (
                mac TEXT PRIMARY KEY, first_seen INTEGER NOT NULL, last_seen INTEGER NOT NULL,
                ip TEXT, ips TEXT NOT NULL DEFAULT '[]', vendor TEXT, hostname TEXT,
                dhcp_fingerprint TEXT, vendor_class TEXT, interface TEXT)""")
            conn.execute('CREATE INDEX IF NOT EXISTS devices_ip ON devices(ip)')
            conn.commit()
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def observe(self, mac, ip=None, hostname=None, dhcp_fingerprint=None, vendor_class=None, interface=None):
        """Record a sighting; returns the device dict, or None for an invalid MAC."""
        mac = normalise_mac(mac)
        if not mac:
            return None
        now = int(time.time())
        with self._lock:
            db = self._db()
            row = db.execute('SELECT * FROM devices WHERE mac = ?', (mac,)).fetchone()
            if row is None:
                ips = [ip] if ip else []
                db.execute('INSERT INTO devices(mac, first_seen, last_seen, ip, ips, vendor, hostname, '
                           'dhcp_fingerprint, vendor_class, interface) VALUES (?,?,?,?,?,?,?,?,?,?)',
                           (mac, now, now, ip, json.dumps(ips), vendor(mac), hostname, dhcp_fingerprint,
                            vendor_class, interface))
            else:
                ips = json.loads(row['ips'])
                if ip and ip not in ips:
                    ips = (ips + [ip])[-MAX_IPS:]
                db.execute('UPDATE devices SET last_seen = ?, ip = COALESCE(?, ip), ips = ?, '
                           'hostname = COALESCE(?, hostname), dhcp_fingerprint = COALESCE(?, dhcp_fingerprint), '
                           'vendor_class = COALESCE(?, vendor_class), interface = COALESCE(?, interface) '
                           'WHERE mac = ?',
                           (now, ip, json.dumps(ips), hostname, dhcp_fingerprint, vendor_class, interface, mac))
            db.commit()
        return self.get(mac)

    def refresh_from_arp(self, path='/proc/net/arp'):
        count = 0
        for ip, mac, iface in arp_table(path):
            if self.observe(mac, ip=ip, interface=iface):
                count += 1
        return count

    @staticmethod
    def _public(row):
        if row is None:
            return None
        d = dict(row)
        d['ips'] = json.loads(d['ips'])
        return d

    def get(self, mac):
        with self._lock:
            row = self._db().execute('SELECT * FROM devices WHERE mac = ?', (normalise_mac(mac),)).fetchone()
        return self._public(row)

    def by_ip(self, ip):
        """The device currently using `ip` (most recently seen), or None."""
        with self._lock:
            row = self._db().execute('SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1',
                                     (str(ip),)).fetchone()
        return self._public(row)

    def list(self, limit=500):
        with self._lock:
            rows = self._db().execute('SELECT * FROM devices ORDER BY last_seen DESC LIMIT ?', (int(limit),)).fetchall()
        return [self._public(r) for r in rows]


_registry = None


def get_registry():
    global _registry
    if _registry is None or _registry.path != default_path():
        _registry = DeviceRegistry()
    return _registry


def observe_packet(packet, registry=None):
    """Learn identity from an ARP or DHCP packet (scapy). Never raises."""
    try:
        from scapy.layers.dhcp import BOOTP, DHCP
        from scapy.layers.l2 import ARP
        reg = registry or get_registry()
        if ARP in packet:
            arp = packet[ARP]
            if arp.psrc and arp.psrc != '0.0.0.0':
                return reg.observe(arp.hwsrc, ip=arp.psrc)
            return None
        if DHCP in packet and BOOTP in packet:
            bootp = packet[BOOTP]
            mac = ':'.join(f'{b:02x}' for b in bytes(bootp.chaddr)[:6])
            opts = {}
            for opt in packet[DHCP].options:
                if isinstance(opt, tuple) and len(opt) >= 2:
                    opts[opt[0]] = opt[1] if len(opt) == 2 else list(opt[1:])
            hostname = opts.get('hostname')
            if isinstance(hostname, bytes):
                hostname = hostname.decode('utf-8', 'replace')[:64]
            fingerprint = opts.get('param_req_list')
            if isinstance(fingerprint, (list, tuple, bytes)):
                fingerprint = ','.join(str(x) for x in fingerprint)
            vclass = opts.get('vendor_class_id')
            if isinstance(vclass, bytes):
                vclass = vclass.decode('utf-8', 'replace')[:64]
            ip = opts.get('requested_addr') or (bootp.ciaddr if bootp.ciaddr != '0.0.0.0' else None)
            return reg.observe(mac, ip=ip, hostname=hostname, dhcp_fingerprint=fingerprint, vendor_class=vclass)
    except Exception:
        return None
    return None
