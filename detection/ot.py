"""Industrial (OT) protocol awareness: Modbus/TCP, DNP3, BACnet/IP, OPC UA (Phase 7).

The parsers read request headers only: which function a master asked a
controller to perform. Nothing is decoded beyond that and nothing is ever
injected. OPC UA bodies are only readable on channels without encryption;
encrypted channels still show who talks to which server.

OTDetector learns, per controller, which hosts command it and which
functions each one uses. After the learning period it reports a new master,
a write/control function a master has never used, and always reports
restart/stop commands, OT traffic crossing the internet edge and Modbus
unit-id sweeps. Techniques are MITRE ATT&CK for ICS ids.

OTStore keeps what was learned in SQLite (data/ot.db, SENTINEL_OT_DB) so a
restart does not begin a new learning period, and so the API process can
serve the OT inventory the engine built.
"""
import os
import sqlite3
import struct
import threading
import time
from collections import defaultdict

from detection.detectors import Cooldown, Finding, _Window, is_external

# (transport, destination port) -> protocol
OT_PORTS = {('TCP', 502): 'modbus', ('TCP', 20000): 'dnp3', ('UDP', 20000): 'dnp3',
            ('UDP', 47808): 'bacnet', ('TCP', 4840): 'opcua'}

MODBUS_FUNCTIONS = {1: 'read coils', 2: 'read discrete inputs', 3: 'read holding registers',
                    4: 'read input registers', 5: 'write single coil', 6: 'write single register',
                    7: 'read exception status', 8: 'diagnostics', 11: 'get comm event counter',
                    15: 'write multiple coils', 16: 'write multiple registers', 17: 'report server id',
                    20: 'read file record', 21: 'write file record', 22: 'mask write register',
                    23: 'read/write multiple registers', 24: 'read FIFO queue', 43: 'encapsulated interface'}
MODBUS_WRITES = {5, 6, 15, 16, 21, 22, 23}

DNP3_FUNCTIONS = {0: 'confirm', 1: 'read', 2: 'write', 3: 'select', 4: 'operate', 5: 'direct operate',
                  6: 'direct operate (no ack)', 7: 'immediate freeze', 9: 'freeze and clear', 13: 'cold restart',
                  14: 'warm restart', 15: 'initialize data', 16: 'initialize application', 17: 'start application',
                  18: 'stop application', 20: 'enable unsolicited', 21: 'disable unsolicited',
                  23: 'delay measurement', 24: 'record current time', 25: 'open file', 27: 'delete file',
                  30: 'abort file', 31: 'activate configuration'}
DNP3_WRITES = {2, 3, 4, 5, 6, 9, 15, 16, 17, 21, 25, 27, 31}
DNP3_STOPS = {13: 'restart', 14: 'restart', 18: 'stop'}

BACNET_CONFIRMED = {5: 'subscribe COV', 6: 'atomic read file', 7: 'atomic write file', 8: 'add list element',
                    9: 'remove list element', 10: 'create object', 11: 'delete object', 12: 'read property',
                    14: 'read property multiple', 15: 'write property', 16: 'write property multiple',
                    17: 'device communication control', 20: 'reinitialize device', 26: 'read range'}
BACNET_UNCONFIRMED = {0: 'i-am', 1: 'i-have', 2: 'unconfirmed COV notification', 6: 'time synchronization',
                      7: 'who-has', 8: 'who-is', 9: 'utc time synchronization', 10: 'write group'}
BACNET_WRITES = {7, 8, 9, 10, 11, 15, 16, 17, 20}

OPCUA_REQUESTS = {631: 'read', 673: 'write', 712: 'call method', 527: 'browse', 461: 'create session',
                  467: 'activate session', 787: 'create subscription', 751: 'create monitored items',
                  488: 'add nodes', 500: 'delete nodes'}
OPCUA_WRITES = {673, 712, 488, 500}


def _msg(protocol, code, name, write=False, stop=None, unit=None):
    return {'protocol': protocol, 'code': code, 'function': name, 'write': write, 'stop': stop, 'unit': unit}


def parse_modbus(payload):
    """Modbus/TCP requests (several ADUs may share a segment)."""
    out, p = [], 0
    while p + 8 <= len(payload):
        _, proto_id, length = struct.unpack('>HHH', payload[p:p + 6])
        if proto_id != 0 or not 2 <= length <= 254:
            break
        unit, fc = payload[p + 6], payload[p + 7]
        if fc & 0x80:                                     # exception response, not a request
            break
        stop = None
        name = MODBUS_FUNCTIONS.get(fc, f'function {fc}')
        if fc == 8 and p + 10 <= len(payload):
            sub = struct.unpack('>H', payload[p + 8:p + 10])[0]
            stop = {1: 'restart', 4: 'listen-only'}.get(sub)
            name = {1: 'diagnostics: restart communications', 4: 'diagnostics: force listen-only mode'}.get(sub, name)
        elif fc == 43 and p + 9 <= len(payload) and payload[p + 8] == 14:
            name = 'read device identification'
        out.append(_msg('modbus', fc, name, fc in MODBUS_WRITES, stop, unit))
        p += 6 + length
    return out


def parse_dnp3(payload):
    """The application function of a DNP3 frame sent by a master (DIR bit set)."""
    if len(payload) < 13 or payload[0:2] != b'\x05\x64' or not payload[3] & 0x80:
        return []
    if not payload[10] & 0x40:                            # transport FIR: only the first fragment has the header
        return []
    fc = payload[12]
    if fc >= 0x81:                                        # responses
        return []
    return [_msg('dnp3', fc, DNP3_FUNCTIONS.get(fc, f'function {fc}'), fc in DNP3_WRITES, DNP3_STOPS.get(fc),
                 struct.unpack('<H', payload[4:6])[0])]


def parse_bacnet(payload):
    """BACnet/IP confirmed and unconfirmed service requests."""
    try:
        if len(payload) < 6 or payload[0] != 0x81:
            return []
        p = 4 + (6 if payload[1] == 0x04 else 0)          # Forwarded-NPDU carries the original address
        if payload[p] != 0x01:
            return []
        control = payload[p + 1]
        p += 2
        if control & 0x80:                                # network-layer message, no APDU
            return []
        if control & 0x20:
            p += 3 + payload[p + 2]
        if control & 0x08:
            p += 3 + payload[p + 2]
        if control & 0x20:
            p += 1                                        # hop count
        apdu_type = payload[p] >> 4
        if apdu_type == 0:
            service = payload[p + (5 if payload[p] & 0x08 else 3)]
            name = BACNET_CONFIRMED.get(service, f'confirmed service {service}')
            stop = {20: 'restart', 17: 'communication control'}.get(service)
            return [_msg('bacnet', service, name, service in BACNET_WRITES, stop)]
        if apdu_type == 1:
            service = payload[p + 1]
            return [_msg('bacnet', 100 + service, BACNET_UNCONFIRMED.get(service, f'unconfirmed service {service}'),
                         service == 10)]
    except IndexError:
        pass
    return []


def parse_opcua(payload):
    """OPC UA binary: the service of an unencrypted MSG, or just the connection for other messages."""
    if len(payload) < 8 or payload[:3] not in (b'HEL', b'OPN', b'MSG', b'CLO'):
        return []
    kind = payload[:3].decode()
    if kind != 'MSG' or len(payload) < 28:
        return [_msg('opcua', 0, {'HEL': 'hello', 'OPN': 'open channel', 'CLO': 'close channel'}.get(kind, 'message'))]
    enc = payload[24]
    if enc == 0x01:                                       # four-byte NodeId: namespace byte + uint16
        node = struct.unpack('<H', payload[26:28])[0] if payload[25] == 0 else None
    elif enc == 0x00:                                     # two-byte NodeId
        node = payload[25]
    else:
        node = None
    if node not in OPCUA_REQUESTS:
        return [_msg('opcua', 0, 'message')]              # encrypted or a service we do not name
    return [_msg('opcua', node, OPCUA_REQUESTS[node], node in OPCUA_WRITES)]


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TOUCH_SECONDS = 60                                        # last_seen is written at most once a minute per row


def default_path():
    return os.environ.get('SENTINEL_OT_DB') or os.path.join(ROOT, 'data', 'ot.db')


PARSERS = {'modbus': parse_modbus, 'dnp3': parse_dnp3, 'bacnet': parse_bacnet, 'opcua': parse_opcua}


def parse_ot(proto, dport, payload):
    """(protocol, [messages]) for a payload sent to an OT port, or (None, [])."""
    protocol = OT_PORTS.get((proto, dport))
    if not protocol or not payload:
        return None, []
    try:
        return protocol, PARSERS[protocol](payload)
    except (IndexError, struct.error):
        return protocol, []


class OTStore:
    """Controllers and (master, controller, function) links; function '' records the master itself."""

    def __init__(self, path=None):
        self.path = path or default_path()
        self._lock = threading.Lock()
        self._conn = None

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            conn.execute("""CREATE TABLE IF NOT EXISTS ot_servers (
                ip TEXT NOT NULL, protocol TEXT NOT NULL, first_seen REAL NOT NULL, PRIMARY KEY (ip, protocol))""")
            conn.execute("""CREATE TABLE IF NOT EXISTS ot_links (
                src TEXT NOT NULL, dst TEXT NOT NULL, protocol TEXT NOT NULL, function TEXT NOT NULL,
                first_seen REAL NOT NULL, last_seen REAL NOT NULL, PRIMARY KEY (src, dst, protocol, function))""")
            conn.commit()
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def load(self):
        """(servers {(ip, protocol): first_seen}, links [(src, dst, protocol, function, last_seen)])."""
        with self._lock:
            db = self._db()
            servers = {(ip, proto): first for ip, proto, first in db.execute('SELECT * FROM ot_servers')}
            links = db.execute('SELECT src, dst, protocol, function, last_seen FROM ot_links').fetchall()
        return servers, links

    def add_server(self, ip, protocol, ts):
        with self._lock:
            self._db().execute('INSERT OR IGNORE INTO ot_servers VALUES (?,?,?)', (ip, protocol, ts))
            self._conn.commit()

    def touch(self, src, dst, protocol, function, ts):
        with self._lock:
            self._db().execute('INSERT INTO ot_links VALUES (?,?,?,?,?,?) ON CONFLICT DO UPDATE SET last_seen = ?',
                               (src, dst, protocol, function, ts, ts, ts))
            self._conn.commit()

    def assets(self):
        """The inventory as OTDetector.assets() reports it, read from disk (used by the API)."""
        det = OTDetector(store=self)
        return det.assets()


class OTDetector:
    def __init__(self, learning=7 * 86400, scan_units=16, clock=time.time, store=None):
        self.learning = learning
        self.scan_units = scan_units
        self.clock = clock
        self.servers = {}                                 # (dst, protocol) -> first seen
        self.masters = defaultdict(set)                   # (dst, protocol) -> sources
        self.ops = defaultdict(set)                       # (src, dst, protocol) -> function names
        self.last = {}                                    # (src, dst, protocol) -> last seen
        self.units = _Window(60)
        self.cooldown = Cooldown(1800)
        self.store = store
        self._written = {}                                # (src, dst, protocol, function) -> last write
        if store is not None:
            self.servers, links = store.load()
            for src, dst, protocol, function, last in links:
                self.masters[(dst, protocol)].add(src)
                if function:
                    self.ops[(src, dst, protocol)].add(function)
                key = (src, dst, protocol)
                self.last[key] = max(self.last.get(key, 0), last)

    def _persist(self, method, *args):
        try:
            getattr(self.store, method)(*args)
        except sqlite3.Error:
            pass                                          # detection goes on from memory

    def _touch(self, src, dst, protocol, function, ts):
        if self.store is None:
            return
        k = (src, dst, protocol, function)
        if ts - self._written.get(k, -1e18) >= TOUCH_SECONDS:
            self._written[k] = ts
            self._persist('touch', src, dst, protocol, function, ts)

    def _learned(self, server, ts):
        return ts - self.servers[server] > self.learning

    def observe(self, src, dst, protocol, messages, ts=None):
        ts = ts or self.clock()
        out = []
        server = (dst, protocol)
        if server not in self.servers:
            self.servers[server] = ts
            if self.store is not None:
                self._persist('add_server', dst, protocol, ts)
        learned = self._learned(server, ts)
        label = protocol.upper() if protocol != 'opcua' else 'OPC UA'

        if (is_external(src) or is_external(dst)) and self.cooldown.ready(('ot_external', src, dst), ts):
            out.append(Finding('ot_external', src, 80, 0.8, 'T0883',
                               f'{label} between {src} and {dst} crosses the internet edge',
                               {'protocol': protocol, 'target': dst}, ts=ts))

        if src not in self.masters[server]:
            if learned and self.masters[server] and self.cooldown.ready(('ot_new_master', src, dst), ts):
                out.append(Finding('ot_new_master', src, 60, 0.5, 'T0886',
                                   f'{src} started talking {label} to {dst}, which only '
                                   f'{", ".join(sorted(self.masters[server])[:3])} used before',
                                   {'protocol': protocol, 'target': dst, 'known_masters': sorted(self.masters[server])},
                                   ts=ts))
            self.masters[server].add(src)

        key = (src, dst, protocol)
        self.last[key] = ts
        self._touch(src, dst, protocol, '', ts)
        for m in messages:
            name = m['function']
            if m['stop'] and self.cooldown.ready(('ot_stop', src, dst, name), ts):
                out.append(Finding('ot_device_stop', src, 85, 0.7, 'T0816' if m['stop'] == 'restart' else 'T0814',
                                   f'{src} sent {label} "{name}" to {dst}',
                                   {'protocol': protocol, 'target': dst, 'function': name}, ts=ts))
            if name not in self.ops[key]:
                if m['write'] and not m['stop'] and learned and self.ops[key] \
                        and self.cooldown.ready(('ot_new_write', src, dst, name), ts):
                    out.append(Finding('ot_new_write', src, 65, 0.55, 'T0855',
                                       f'{src} sent {label} "{name}" to {dst} for the first time',
                                       {'protocol': protocol, 'target': dst, 'function': name}, ts=ts))
                self.ops[key].add(name)
            self._touch(src, dst, protocol, name, ts)
            if protocol == 'modbus' and m['unit'] is not None:
                units = {u for _, u in self.units.add((src, dst), ts, m['unit'])}
                if len(units) >= self.scan_units and self.cooldown.ready(('ot_scan', src, dst), ts):
                    out.append(Finding('ot_scan', src, 60, 0.6, 'T0846',
                                       f'{src} probed {len(units)} Modbus unit ids on {dst} within a minute',
                                       {'protocol': protocol, 'target': dst, 'units': len(units)}, ts=ts))
        return out

    def assets(self):
        """OT inventory: each controller with its protocol, masters and the functions they use."""
        out = []
        for (dst, protocol), first in sorted(self.servers.items()):
            masters = []
            for src in sorted(self.masters[(dst, protocol)]):
                key = (src, dst, protocol)
                masters.append({'ip': src, 'functions': sorted(self.ops[key]), 'last_seen': self.last.get(key)})
            out.append({'ip': dst, 'protocol': protocol, 'first_seen': first, 'masters': masters})
        return out
