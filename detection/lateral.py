"""Lateral movement in Windows networks (Phase 9): SMB, DCE-RPC, Kerberos, RDP, WinRM.

Header metadata only, like the OT parsers: which SMB2 command, which share a
tree connect names, whether a session setup carries an NTLM authentication,
which DCE-RPC interface a bind or endpoint-mapper lookup asks for, and the
Kerberos message type. Nothing else is decoded and no payload is kept.
SMB 3 encrypted sessions hide everything after the session setup; the
detectors then see only the authentication and the flows.

Findings (MITRE ATT&CK enterprise ids):
  admin_share       first use of ADMIN$/C$-style shares from a source to a host (T1021.002)
  remote_service    remote service control (svcctl): PsExec-style execution (T1569.002)
  remote_task       remote scheduled task (atsvc / ITaskSchedulerService) (T1053.005)
  dcsync            directory replication (drsuapi) requested by a host that is not a known replicator (T1003.006)
  ntlm_fanout       NTLM authentications from one source to many hosts in minutes (pass-the-hash, T1550.002)
  kerberos_burst    many ticket requests from one source in a minute (Kerberoasting / spraying, T1558.003 / T1110.003)
  lateral_fanout    one source reaching many new hosts on admin services (SMB, RDP, WinRM, RPC, SSH) (T1021)

During the learning period (7 days, kept across restarts in data/lateral.db)
the detector only learns which sources use admin shares, service control,
scheduled tasks and replication; afterwards a known (source, interface) pair
is not reported again. Bursts and NTLM fan-out are reported at any time.
"""
import os
import sqlite3
import struct
import threading
import time
import uuid

from common.bounded import BoundedDict, BoundedSet
from detection.detectors import MAX_KEYS, Cooldown, Finding, _Window, is_external

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

SMB_PORTS = {139, 445}
RPC_PORTS = {135}
KERBEROS_PORT = 88
LATERAL_TCP_PORTS = frozenset(SMB_PORTS | RPC_PORTS | {KERBEROS_PORT})
LATERAL_UDP_PORTS = frozenset({KERBEROS_PORT})
# admin services for fan-out: SMB, RPC endpoint mapper, RDP, WinRM, SSH
ADMIN_PORTS = {135: 'RPC', 139: 'SMB', 445: 'SMB', 3389: 'RDP', 5985: 'WinRM', 5986: 'WinRM', 22: 'SSH'}
# SMB control messages are small; bulk reads and writes fill the segment. Only the small ones are
# inspected so a busy file server does not push every packet through the slow path.
SMB_INSPECT_MAX = 1200

SMB2_COMMANDS = {0: 'negotiate', 1: 'session setup', 2: 'logoff', 3: 'tree connect', 4: 'tree disconnect',
                 5: 'create', 6: 'close', 8: 'read', 9: 'write', 11: 'ioctl'}

RPC_INTERFACES = {
    uuid.UUID('367abb81-9844-35f1-ad32-98f038001003').bytes_le: 'svcctl',
    uuid.UUID('1ff70682-0a51-30e8-076d-740be8cee98b').bytes_le: 'atsvc',
    uuid.UUID('86d35949-83c9-4044-b424-db363231fd0c').bytes_le: 'taskscheduler',
    uuid.UUID('e3514235-4b06-11d1-ab04-00c04fc2dcd2').bytes_le: 'drsuapi',
    uuid.UUID('338cd001-2244-31f1-aaaa-900038001003').bytes_le: 'winreg',
}
NTLM_AUTH = b'NTLMSSP\x00\x03\x00\x00\x00'


def default_path():
    return os.environ.get('SENTINEL_LATERAL_DB') or os.path.join(ROOT, 'data', 'lateral.db')


def _rpc_interfaces(payload):
    """Interfaces named by a DCE-RPC bind/alter-context (ptype 11/14) or an endpoint-mapper request."""
    if b'\x05\x00' not in payload:
        return []
    return [name for raw, name in RPC_INTERFACES.items() if raw in payload]


def parse_smb(payload):
    """SMB2 requests in a NetBIOS session message: [{command, share?, ntlm, rpc: [...]}].

    Compounded requests are followed through NextCommand. Responses are skipped.
    """
    out = []
    if len(payload) < 4 + 64 or payload[0] != 0x00:
        return out
    base = 4
    rpc = _rpc_interfaces(payload)                         # binds travel in WRITE/IOCTL on a named pipe
    for _ in range(8):
        if payload[base:base + 4] != b'\xfeSMB' or base + 64 > len(payload):
            break
        command = struct.unpack_from('<H', payload, base + 12)[0]
        flags, nxt = struct.unpack_from('<II', payload, base + 16)
        if not flags & 0x1:                                # SERVER_TO_REDIR clear: a request
            msg = {'command': SMB2_COMMANDS.get(command, f'command {command}'), 'share': None,
                   'ntlm': False, 'rpc': []}
            if command == 3 and base + 72 <= len(payload):
                off, length = struct.unpack_from('<HH', payload, base + 68)
                raw = payload[base + off:base + off + length]
                try:
                    msg['share'] = raw.decode('utf-16-le').rsplit('\\', 1)[-1].upper() or None
                except UnicodeDecodeError:
                    pass
            elif command == 1:
                msg['ntlm'] = NTLM_AUTH in payload[base:base + nxt if nxt else len(payload)]
            elif command in (9, 11):
                msg['rpc'] = rpc
            out.append(msg)
        if not nxt:
            break
        base += nxt
    return out


def parse_rpc(payload):
    """DCE-RPC over TCP 135: the interfaces a bind or endpoint-mapper lookup asks for."""
    if len(payload) < 16 or payload[0] != 5 or payload[2] not in (0, 11, 14):   # request, bind, alter
        return []
    return _rpc_interfaces(payload)


def parse_kerberos(payload, tcp):
    """'as-req' / 'tgs-req' / None from a Kerberos message (TCP has a 4-byte length prefix)."""
    if tcp:
        if len(payload) < 5:
            return None
        payload = payload[4:]
    if not payload:
        return None
    return {0x6a: 'as-req', 0x6c: 'tgs-req'}.get(payload[0])


def is_admin_share(share):
    return bool(share) and share.endswith('$') and share not in ('IPC$', 'PRINT$')


class LateralStore:
    """What was learned: (kind, source) pairs, and when learning started."""

    def __init__(self, path=None):
        self.path = path or default_path()
        self._lock = threading.Lock()
        self._conn = None

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            conn.execute('CREATE TABLE IF NOT EXISTS lateral_meta (key TEXT PRIMARY KEY, value REAL NOT NULL)')
            conn.execute("""CREATE TABLE IF NOT EXISTS lateral_known (
                kind TEXT NOT NULL, src TEXT NOT NULL, first_seen REAL NOT NULL, PRIMARY KEY (kind, src))""")
            conn.commit()
            self._conn = conn
        return self._conn

    def started(self, now):
        with self._lock:
            db = self._db()
            db.execute("INSERT OR IGNORE INTO lateral_meta VALUES ('started', ?)", (now,))
            db.commit()
            return db.execute("SELECT value FROM lateral_meta WHERE key = 'started'").fetchone()[0]

    def known(self):
        with self._lock:
            return {(k, s) for k, s in self._db().execute('SELECT kind, src FROM lateral_known')}

    def add(self, kind, src, ts):
        with self._lock:
            self._db().execute('INSERT OR IGNORE INTO lateral_known VALUES (?,?,?)', (kind, src, ts))
            self._conn.commit()

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


# per-kind finding: (severity, probability, technique, evidence template)
_LEARNED = {
    'admin_share': (65, 0.6, 'T1021.002', '{src} opened the administrative share {share} on {dst}'),
    'svcctl': (80, 0.7, 'T1569.002', '{src} used remote service control (svcctl) on {dst}, as PsExec does'),
    'atsvc': (75, 0.65, 'T1053.005', '{src} created or queried a scheduled task on {dst} remotely (atsvc)'),
    'taskscheduler': (75, 0.65, 'T1053.005', '{src} used the remote Task Scheduler service on {dst}'),
    'drsuapi': (90, 0.8, 'T1003.006', '{src} asked {dst} for directory replication (drsuapi): '
                                      'DCSync unless {src} is a domain controller'),
}
_KIND = {'admin_share': 'admin_share', 'svcctl': 'remote_service', 'atsvc': 'remote_task',
         'taskscheduler': 'remote_task', 'drsuapi': 'dcsync'}


class LateralDetector:
    def __init__(self, learning=7 * 86400, ntlm_hosts=5, ntlm_window=300, kerberos_per_minute=30,
                 fanout_hosts=5, fanout_window=600, clock=time.time, store=None):
        self.learning = learning
        self.ntlm_hosts, self.kerberos_per_minute = ntlm_hosts, kerberos_per_minute
        self.fanout_hosts = fanout_hosts
        self.clock = clock
        self.store = store
        self.started = store.started(clock()) if store is not None else clock()
        self.known = BoundedSet(MAX_KEYS)                    # (what, src): learned users of shares / interfaces
        if store is not None:
            for k in store.known():
                self.known.add(k)
        self.admin_peers = BoundedDict(MAX_KEYS, set)         # src -> {(dst, service)} ever seen
        self.ntlm = _Window(ntlm_window)
        self.kerberos = _Window(60)
        self.fanout = _Window(fanout_window)
        self.cooldown = Cooldown(1800)

    def learning_now(self, ts):
        return ts - self.started < self.learning

    def _learned_use(self, what, src, dst, ts, **fmt):
        """Learn during the learning period; afterwards report a source new to `what`."""
        if is_external(src):
            return []
        key = (what, src)
        if key in self.known:
            return []
        if self.learning_now(ts):
            self.known.add(key)
            if self.store is not None:
                try:
                    self.store.add(what, src, ts)
                except sqlite3.Error:
                    pass
            return []
        if not self.cooldown.ready((what, src, dst), ts):
            return []
        severity, prob, technique, text = _LEARNED[what]
        return [Finding(_KIND[what], src, severity, prob, technique, text.format(src=src, dst=dst, **fmt),
                        {'target': dst, 'protocol': 'smb' if what == 'admin_share' else 'dcerpc', **fmt}, ts=ts)]

    def observe_smb(self, src, dst, messages, ts=None):
        ts = ts or self.clock()
        out = []
        for m in messages:
            if is_admin_share(m['share']):
                # learned per share kind, not per host: a backup server using C$ everywhere is one pair
                out += self._learned_use('admin_share', src, dst, ts, share=m['share'])
            for iface in m['rpc']:
                if iface in _LEARNED:
                    out += self._learned_use(iface, src, dst, ts)
            if m['ntlm']:
                hosts = {h for _, h in self.ntlm.add(src, ts, dst)}
                if len(hosts) >= self.ntlm_hosts and self.cooldown.ready(('ntlm_fanout', src), ts):
                    out.append(Finding('ntlm_fanout', src, 70, 0.6, 'T1550.002',
                                       f'{src} authenticated with NTLM to {len(hosts)} hosts within '
                                       f'{int(self.ntlm.seconds / 60)} minutes (pass-the-hash pattern)',
                                       {'hosts': sorted(hosts)[:10], 'protocol': 'smb'}, ts=ts))
        return out

    def observe_rpc(self, src, dst, interfaces, ts=None):
        ts = ts or self.clock()
        out = []
        for iface in interfaces:
            if iface in _LEARNED:
                out += self._learned_use(iface, src, dst, ts)
        return out

    def observe_kerberos(self, src, dst, kind, ts=None):
        ts = ts or self.clock()
        if kind is None:
            return []
        q = self.kerberos.add((src, kind), ts, dst)
        if len(q) < self.kerberos_per_minute or not self.cooldown.ready(('kerberos_burst', src, kind), ts):
            return []
        if kind == 'tgs-req':
            text, technique = (f'{src} requested {len(q)} service tickets within a minute '
                               '(Kerberoasting pattern)', 'T1558.003')
        else:
            text, technique = (f'{src} sent {len(q)} Kerberos logins (AS-REQ) within a minute '
                               '(password spraying or AS-REP roasting)', 'T1110.003')
        return [Finding('kerberos_burst', src, 70, 0.6, technique, text,
                        {'target': dst, 'protocol': 'kerberos', 'message': kind, 'count': len(q)}, ts=ts)]

    def observe(self, f):
        """Flow detector interface: admin-service fan-out to new internal hosts."""
        service = ADMIN_PORTS.get(f.get('dport'))
        src, dst, ts = f['src'], f['dst'], f['ts']
        if not service or is_external(src) or is_external(dst):
            return []
        peers = self.admin_peers[src]
        pair = (dst, service)
        if pair in peers:
            return []
        peers.add(pair)
        if self.learning_now(ts):
            return []
        q = self.fanout.add(src, ts, pair)
        hosts = {d for _, (d, _) in q}
        if len(hosts) < self.fanout_hosts or not self.cooldown.ready(('lateral_fanout', src), ts):
            return []
        services = sorted({s for _, (_, s) in q})
        return [Finding('lateral_fanout', src, 70, 0.65, 'T1021',
                        f'{src} reached {len(hosts)} hosts it had never used {", ".join(services)} on '
                        f'within {int(self.fanout.seconds / 60)} minutes',
                        {'hosts': sorted(hosts)[:10], 'services': services}, ts=ts)]


def parse_lateral(proto, dport, payload):
    """('smb'|'rpc'|'kerberos', parsed) for a payload to a Windows service port, or (None, None)."""
    if not payload:
        return None, None
    try:
        if proto == 'TCP' and dport in SMB_PORTS:
            return 'smb', parse_smb(payload)
        if proto == 'TCP' and dport in RPC_PORTS:
            return 'rpc', parse_rpc(payload)
        if dport == KERBEROS_PORT and proto in ('TCP', 'UDP'):
            return 'kerberos', parse_kerberos(payload, proto == 'TCP')
    except (IndexError, struct.error):
        pass
    return None, None
