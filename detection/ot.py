"""Industrial (OT) protocol awareness (Phase 7, extended in Phase 9).

Modbus/TCP, DNP3, BACnet/IP, OPC UA, IEC 60870-5-104, S7comm, EtherNet/IP (CIP)
and MQTT (IoT).

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

from common.bounded import BoundedDict
from detection.detectors import Cooldown, Finding, _Window, is_external

# (transport, destination port) -> protocol
OT_PORTS = {('TCP', 502): 'modbus', ('TCP', 20000): 'dnp3', ('UDP', 20000): 'dnp3',
            ('UDP', 47808): 'bacnet', ('TCP', 4840): 'opcua',
            ('TCP', 2404): 'iec104', ('TCP', 102): 's7comm',
            ('TCP', 44818): 'ethernetip', ('TCP', 1883): 'mqtt'}
LABELS = {'modbus': 'Modbus', 'dnp3': 'DNP3', 'bacnet': 'BACnet', 'opcua': 'OPC UA', 'iec104': 'IEC 104',
          's7comm': 'S7comm', 'ethernetip': 'EtherNet/IP', 'mqtt': 'MQTT'}

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


IEC104_COMMANDS = {45: 'single command', 46: 'double command', 47: 'regulating step command',
                   48: 'setpoint command (normalised)', 49: 'setpoint command (scaled)',
                   50: 'setpoint command (float)', 51: 'bitstring command',
                   58: 'single command (time tag)', 59: 'double command (time tag)',
                   60: 'regulating step command (time tag)', 61: 'setpoint command (normalised, time tag)',
                   62: 'setpoint command (scaled, time tag)', 63: 'setpoint command (float, time tag)',
                   64: 'bitstring command (time tag)', 100: 'interrogation', 101: 'counter interrogation',
                   102: 'read', 103: 'clock synchronisation', 104: 'test command', 105: 'reset process',
                   106: 'delay acquisition', 107: 'test command (time tag)', 110: 'parameter (normalised)',
                   111: 'parameter (scaled)', 112: 'parameter (float)', 113: 'parameter activation'}
IEC104_WRITES = set(range(45, 52)) | set(range(58, 65)) | {103, 105, 110, 111, 112, 113}


def parse_iec104(payload):
    """IEC 60870-5-104: the type of each control-direction ASDU in I-format APDUs.

    APCI: 0x68, length, four control octets; the ASDU follows (type id, VSQ, cause
    of transmission, originator, common address). Monitor-direction types (1-44,
    sent by the outstation) are not requests and are skipped.
    """
    out, p = [], 0
    while p + 2 <= len(payload) and payload[p] == 0x68:
        length = payload[p + 1]
        if length < 4 or p + 2 + length > len(payload):
            break
        if not payload[p + 2] & 0x01 and length >= 10:          # I-format carries an ASDU
            type_id = payload[p + 6]
            common = struct.unpack('<H', payload[p + 10:p + 12])[0]
            if type_id in IEC104_COMMANDS:
                out.append(_msg('iec104', type_id, IEC104_COMMANDS[type_id], type_id in IEC104_WRITES,
                                'restart' if type_id == 105 else None, common))
        p += 2 + length
    return out


S7_FUNCTIONS = {0x04: 'read variable', 0x05: 'write variable', 0x1A: 'request download',
                0x1B: 'download block', 0x1C: 'download ended', 0x1D: 'start upload', 0x1E: 'upload',
                0x1F: 'end upload', 0x28: 'program invocation', 0x29: 'PLC stop',
                0xF0: 'setup communication'}
S7_WRITES = {0x05, 0x1A, 0x1B, 0x1C, 0x28}


def parse_s7comm(payload):
    """S7comm (Siemens S7-300/400/1200 classic): the function of a job request.

    TPKT (4 octets) + COTP data TPDU + S7 header (0x32, ROSCTR, ...). Only jobs
    (ROSCTR 1) are requests; userdata (7) is reported as one function. Connection
    setup TPDUs and S7comm-plus (0x72) carry no readable function.
    """
    if len(payload) < 7 or payload[0] != 0x03 or payload[1] != 0x00:
        return []
    cotp_len = payload[4]
    if payload[5] != 0xF0:                                       # only COTP data TPDUs carry S7
        return []
    p = 5 + cotp_len
    if p + 10 > len(payload) or payload[p] != 0x32:
        return []
    rosctr = payload[p + 1]
    if rosctr == 7:
        return [_msg('s7comm', 0x700, 'userdata (CPU functions)')]
    if rosctr != 1 or p + 11 > len(payload):
        return []
    func = payload[p + 10]                                       # first parameter octet
    return [_msg('s7comm', func, S7_FUNCTIONS.get(func, f'S7 function {func:#04x}'), func in S7_WRITES,
                 'stop' if func == 0x29 else None)]


CIP_SERVICES = {0x01: 'get attributes all', 0x02: 'set attributes all', 0x03: 'get attribute list',
                0x04: 'set attribute list', 0x05: 'reset', 0x06: 'start', 0x07: 'stop', 0x08: 'create',
                0x09: 'delete', 0x0A: 'multiple service packet', 0x0E: 'get attribute single',
                0x10: 'set attribute single', 0x4C: 'read tag', 0x4D: 'write tag',
                0x4E: 'read-modify-write tag', 0x52: 'read tag fragmented', 0x53: 'write tag fragmented'}
CIP_CONNECTION_MANAGER = {0x4E: 'forward close', 0x52: 'unconnected send', 0x54: 'forward open',
                          0x5B: 'large forward open'}
CIP_WRITES = {0x02, 0x04, 0x08, 0x09, 0x10, 0x4D, 0x4E, 0x53}
CIP_STOPS = {0x05: 'restart', 0x07: 'stop'}


def _cip(data, depth=0):
    """One CIP request: service, then the request path; unwraps an Unconnected Send once."""
    if len(data) < 2 or data[0] & 0x80:                           # bit 7 set: a reply
        return []
    service, words = data[0], data[1]
    path = data[2:2 + 2 * words]
    cls = path[1] if len(path) >= 2 and path[0] == 0x20 else None
    if cls == 0x06 and service in CIP_CONNECTION_MANAGER:
        if service == 0x52 and depth == 0:
            body = data[2 + 2 * words:]
            if len(body) >= 4:
                size = struct.unpack('<H', body[2:4])[0]
                inner = _cip(body[4:4 + size], 1)
                if inner:
                    return inner
        return [_msg('ethernetip', 0x600 + service, CIP_CONNECTION_MANAGER[service])]
    name = CIP_SERVICES.get(service, f'CIP service {service:#04x}')
    return [_msg('ethernetip', service, name, service in CIP_WRITES, CIP_STOPS.get(service))]


def parse_ethernetip(payload):
    """EtherNet/IP: the CIP service carried by SendRRData / SendUnitData.

    Encapsulation header (24 octets), then interface handle, timeout and a
    common packet format item list; the CIP request is the data item.
    """
    if len(payload) < 24:
        return []
    command, length = struct.unpack('<HH', payload[:4])
    if command == 0x0065:
        return [_msg('ethernetip', 0x10065, 'register session')]
    if command == 0x0063:
        return [_msg('ethernetip', 0x10063, 'list identity')]
    if command not in (0x006F, 0x0070) or len(payload) < 32:
        return []
    count = struct.unpack('<H', payload[30:32])[0]
    p = 32
    for _ in range(min(count, 4)):
        if p + 4 > len(payload):
            break
        item, size = struct.unpack('<HH', payload[p:p + 4])
        data = payload[p + 4:p + 4 + size]
        if item == 0x00B2:                                        # unconnected data
            return _cip(data)
        if item == 0x00B1 and len(data) > 2:                      # connected data: sequence count first
            return _cip(data[2:])
        p += 4 + size
    return []


MQTT_PACKETS = {1: 'connect', 3: 'publish', 8: 'subscribe', 10: 'unsubscribe', 12: 'ping', 14: 'disconnect',
                15: 'auth'}


def parse_mqtt(payload):
    """MQTT 3.1.1 / 5 control packets sent to the broker (several may share a segment).

    A client that publishes is the IoT equivalent of a master writing: publish is
    the write function. CONNECT must name the MQTT protocol to be accepted.
    """
    out, p = [], 0
    while p + 2 <= len(payload) and len(out) < 16:
        kind = payload[p] >> 4
        q, mult, remaining = p + 1, 1, 0
        for _ in range(4):                                        # variable-length remaining length
            if q >= len(payload):
                return out
            b = payload[q]
            remaining += (b & 0x7F) * mult
            mult *= 128
            q += 1
            if not b & 0x80:
                break
        else:
            return out
        if kind not in MQTT_PACKETS:
            break
        if kind == 1 and payload[q + 2:q + 6] not in (b'MQTT', b'MQIs'):
            break
        out.append(_msg('mqtt', kind, MQTT_PACKETS[kind], kind == 3))
        p = q + remaining
    return out


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TOUCH_SECONDS = 60                                        # last_seen is written at most once a minute per row
# a real site has tens or hundreds of controllers; beyond these caps, a flood of spoofed OT packets
# (e.g. UDP to the BACnet port) is ignored instead of filling memory and the database
MAX_SERVERS = 5000
MAX_LINKS = 50000


def default_path():
    return os.environ.get('SENTINEL_OT_DB') or os.path.join(ROOT, 'data', 'ot.db')


PARSERS = {'modbus': parse_modbus, 'dnp3': parse_dnp3, 'bacnet': parse_bacnet,
           'opcua': parse_opcua, 'iec104': parse_iec104, 's7comm': parse_s7comm,
           'ethernetip': parse_ethernetip, 'mqtt': parse_mqtt}


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
        self.ops = BoundedDict(MAX_LINKS, set)            # (src, dst, protocol) -> function names
        self.last = BoundedDict(MAX_LINKS)                # (src, dst, protocol) -> last seen
        self.ignored = 0                                  # packets to new controllers beyond MAX_SERVERS
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
            if len(self.servers) >= MAX_SERVERS:
                self.ignored += 1
                return out
            self.servers[server] = ts
            if self.store is not None:
                self._persist('add_server', dst, protocol, ts)
        learned = self._learned(server, ts)
        label = LABELS.get(protocol, protocol.upper())

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
