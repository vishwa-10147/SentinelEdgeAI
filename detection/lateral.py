"""Lateral movement in Windows networks (Phase 9): SMB, DCE-RPC, Kerberos, LDAP, RDP, WinRM.

Header metadata only, like the OT parsers: which SMB2 command, which share a
tree connect names, whether a session setup carries an NTLM authentication,
which DCE-RPC interface a bind or endpoint-mapper lookup asks for, the
Kerberos message type, and for LDAP the operation, the bind method, a search's
base, scope, the attribute names in its filter and the attributes it asks for.
Nothing else is decoded and no payload is kept; an LDAP password is never read
beyond noting that a simple bind carried one.
SMB 3 encrypted sessions hide everything after the session setup; the
detectors then see only the authentication and the flows. Windows clients
sign and seal LDAP after a Kerberos/NTLM bind by default, so the search
detectors see plain LDAP (port 389 without sealing, CLDAP, global catalog
3268): many tools and scripts, some directory clients and Zeek's LDAP logs.

Findings (MITRE ATT&CK enterprise ids):
  admin_share       first use of ADMIN$/C$-style shares from a source to a host (T1021.002)
  remote_service    remote service control (svcctl): PsExec-style execution (T1569.002)
  remote_task       remote scheduled task (atsvc / ITaskSchedulerService) (T1053.005)
  dcsync            directory replication (drsuapi) requested by a host that is not a known replicator (T1003.006)
  ntlm_fanout       NTLM authentications from one source to many hosts in minutes (pass-the-hash, T1550.002)
  kerberos_burst    many ticket requests from one source in a minute (Kerberoasting / spraying, T1558.003 / T1110.003)
  lateral_fanout    one source reaching many new hosts on admin services (SMB, RDP, WinRM, RPC, SSH) (T1021)
  ldap_recon        a directory search new for its source: accounts with SPNs (T1558.003), without
                    pre-authentication (T1558.004), delegation (T1087.002), domain trusts (T1482),
                    LAPS passwords (T1552), privileged groups (T1069.002)
  ldap_enumeration  one source running three or more of those kinds of searches in ten minutes
                    (BloodHound / PowerView-style collection, T1087.002), reported at any time
  ldap_cleartext_bind  a simple bind with a password over unencrypted LDAP (credentials on the wire)

During the learning period (7 days, kept across restarts in data/lateral.db)
the detector only learns which sources use admin shares, service control,
scheduled tasks and replication; afterwards a known (source, interface) pair
is not reported again. Bursts and NTLM fan-out are reported at any time.
"""
import os
import re
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
LDAP_PORTS = {389, 3268}                                     # LDAP and the global catalog (636/3269 are TLS)
LATERAL_TCP_PORTS = frozenset(SMB_PORTS | RPC_PORTS | LDAP_PORTS | {KERBEROS_PORT})
LATERAL_UDP_PORTS = frozenset({KERBEROS_PORT, 389})         # CLDAP
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


# ---------- LDAP (BER) ----------

LDAP_OPS = {0x60: 'bind', 0x42: 'unbind', 0x63: 'search', 0x66: 'modify', 0x68: 'add', 0x4a: 'delete',
            0x6c: 'modify dn', 0x6e: 'compare', 0x77: 'extended'}
_LDAP_SCOPES = {0: 'base', 1: 'one', 2: 'subtree'}
LDAP_MAX_MESSAGES = 16
_FILTER_MAX_DEPTH = 16
_FILTER_MAX_TERMS = 64
_UAC_RULES = ('1.2.840.113556.1.4.803', '1.2.840.113556.1.4.804')   # bitwise AND / OR matching rules
_LAPS_ATTRS = ('ms-mcs-admpwd', 'mslaps-password', 'mslaps-encryptedpassword', 'mslaps-encrypteddsrmpassword')
_PRIVILEGED = ('domain admins', 'enterprise admins', 'schema admins', 'administrators', 'account operators',
               'backup operators', 'dnsadmins')


def _ber(buf, i, end):
    """(tag, value start, value end) of the BER element at i; ValueError when malformed."""
    if i + 2 > end:
        raise ValueError('short')
    tag = buf[i]
    n = buf[i + 1]
    i += 2
    if n & 0x80:
        k = n & 0x7F
        if k == 0 or k > 4 or i + k > end:
            raise ValueError('length')
        n = int.from_bytes(buf[i:i + k], 'big')
        i += k
    if i + n > end:
        raise ValueError('overrun')
    return tag, i, i + n


def _ber_items(buf, start, end):
    """(tag, value start, value end) of each element in [start, end)."""
    for tag, a, b, _ in _ber_elements(buf, start, end):
        yield tag, a, b


def _ber_elements(buf, start, end):
    """Like _ber_items, plus the offset where each element (its tag) starts."""
    i = start
    while i < end:
        tag, a, b = _ber(buf, i, end)
        yield tag, a, b, i
        i = b


def _text(raw, limit=256):
    return raw[:limit].decode('utf-8', 'replace')


def _ldap_filter(buf, start, end, terms, depth=0):
    """Collect (attribute, value or None, matching rule or None) from an LDAP filter."""
    if depth > _FILTER_MAX_DEPTH or len(terms) >= _FILTER_MAX_TERMS:
        return
    tag, a, b = _ber(buf, start, end)
    if tag in (0xa0, 0xa1):                                   # and, or
        for _, _, nxt, at in _ber_elements(buf, a, b):
            _ldap_filter(buf, at, nxt, terms, depth + 1)
    elif tag == 0xa2:                                         # not
        _ldap_filter(buf, a, b, terms, depth + 1)
    elif tag in (0xa3, 0xa5, 0xa6, 0xa8):                     # equality, >=, <=, approx: attribute and value
        items = list(_ber_items(buf, a, b))
        if len(items) >= 2:
            terms.append((_text(buf[items[0][1]:items[0][2]]).lower(), _text(buf[items[1][1]:items[1][2]]), None))
    elif tag == 0xa4:                                         # substrings: attribute and the pieces
        items = list(_ber_items(buf, a, b))
        if items:
            pieces = [_text(buf[x:y]) for _, x, y in _ber_items(buf, items[1][1], items[1][2])] \
                if len(items) > 1 else []
            terms.append((_text(buf[items[0][1]:items[0][2]]).lower(), '*'.join(pieces), None))
    elif tag == 0x87:                                         # present: (attr=*)
        terms.append((_text(buf[a:b]).lower(), '*', None))
    elif tag == 0xa9:                                         # extensible match
        rule = attr = value = None
        for t, x, y in _ber_items(buf, a, b):
            if t == 0x81:
                rule = _text(buf[x:y])
            elif t == 0x82:
                attr = _text(buf[x:y]).lower()
            elif t == 0x83:
                value = _text(buf[x:y])
        if attr:
            terms.append((attr, value, rule))


def ldap_markers(terms, attributes):
    """The reconnaissance kinds a search's filter and requested attributes point to."""
    found = set()
    attrs = {a.lower() for a in attributes}
    for attr, value, rule in terms:
        v = (value or '').lower()
        if attr == 'serviceprincipalname':
            found.add('spn')
        elif attr == 'useraccountcontrol' and rule in _UAC_RULES and v.isdigit():
            bits = int(v)
            if bits & 0x400000:                               # DONT_REQ_PREAUTH
                found.add('asrep')
            if bits & 0x80000 or bits & 0x1000000:            # TRUSTED_FOR_DELEGATION / ..._TO_AUTH_FOR_DELEGATION
                found.add('delegation')
        elif attr in ('msds-allowedtodelegateto', 'msds-allowedtoactonbehalfofotheridentity'):
            found.add('delegation')
        elif attr in ('objectclass', 'objectcategory') and v in ('trusteddomain', 'cn=trusted-domain'):
            found.add('trusts')
        elif attr == 'objectcategory' and v.startswith('cn=trusted-domain'):
            found.add('trusts')
        elif attr in _LAPS_ATTRS:
            found.add('laps')
        elif attr == 'admincount' and v == '1':
            found.add('admins')
        elif attr in ('memberof', 'member', 'cn', 'samaccountname') and any(p in v for p in _PRIVILEGED):
            found.add('admins')
    if attrs & set(_LAPS_ATTRS):
        found.add('laps')
    if 'serviceprincipalname' in attrs and any(a == 'useraccountcontrol' or a == 'objectcategory'
                                               for a, _, _ in terms):
        found.add('spn')
    return sorted(found)


_FILTER_TEXT = re.compile(r'\(([A-Za-z0-9;.\-]+)(?::(?:dn:)?([0-9.]+))?:?(~=|>=|<=|=)([^()]*)\)')


def parse_filter_text(text):
    """Terms from a filter in RFC 4515 text form, e.g. Zeek's ldap_search.log `filter`."""
    terms = []
    for attr, rule, _, value in _FILTER_TEXT.findall(str(text or '')[:4096]):
        terms.append((attr.lower(), value, rule or None))
        if len(terms) >= _FILTER_MAX_TERMS:
            break
    return terms


def parse_ldap(payload):
    """LDAP requests in a TCP segment or CLDAP datagram: [{op, ...}] (responses are skipped).

    bind:   {'op': 'bind', 'method': 'simple'|'sasl', 'mechanism', 'anonymous', 'password': bool}
    search: {'op': 'search', 'base', 'scope', 'filter_attributes', 'attributes', 'markers'}
    """
    out = []
    i, end = 0, len(payload)
    while i < end and len(out) < LDAP_MAX_MESSAGES:
        try:
            i = _ldap_message(payload, i, end, out)
        except (ValueError, IndexError):
            break                       # truncated or not LDAP (e.g. a sealed SASL buffer): keep what was read
    return out


def _ldap_message(payload, i, end, out):
    """Parse the LDAPMessage at i into `out`; returns where the next one starts (end to stop)."""
    tag, a, b = _ber(payload, i, end)
    if tag != 0x30:
        return end
    items = _ber_items(payload, a, b)
    mtag, _, _ = next(items, (None, 0, 0))                # messageID
    if mtag != 0x02:
        return end
    op_tag, x, y = next(items, (None, 0, 0))
    op = LDAP_OPS.get(op_tag)
    if op == 'bind':
        fields = list(_ber_items(payload, x, y))
        if len(fields) >= 3:
            name = payload[fields[1][1]:fields[1][2]]
            auth_tag, ax, ay = fields[2]
            msg = {'op': 'bind', 'method': 'simple' if auth_tag == 0x80 else 'sasl' if auth_tag == 0xa3
                   else f'auth {auth_tag:#x}', 'mechanism': None, 'anonymous': not name and ay == ax,
                   'password': auth_tag == 0x80 and ay > ax}
            if auth_tag == 0xa3:
                mech = next(_ber_items(payload, ax, ay), None)
                if mech:
                    msg['mechanism'] = _text(payload[mech[1]:mech[2]], 32)
            out.append(msg)
    elif op == 'search':
        fields = list(_ber_elements(payload, x, y))
        if len(fields) >= 8:
            terms = []
            try:
                _ldap_filter(payload, fields[6][3], fields[6][2], terms)
            except (ValueError, IndexError):
                pass                                      # keep what was read before the damage
            attrs = [_text(payload[p:q], 64) for _, p, q in _ber_items(payload, fields[7][1], fields[7][2])][:64]
            scope = int.from_bytes(payload[fields[1][1]:fields[1][2]], 'big') if fields[1][2] > fields[1][1] else 0
            out.append({'op': 'search', 'base': _text(payload[fields[0][1]:fields[0][2]]),
                        'scope': _LDAP_SCOPES.get(scope, str(scope)),
                        'filter_attributes': sorted({t[0] for t in terms})[:32], 'attributes': attrs,
                        'markers': ldap_markers(terms, attrs)})
    elif op:
        out.append({'op': op})
    return b


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
    'ldap_spn': (70, 0.6, 'T1558.003', '{src} searched the directory on {dst} for accounts with service '
                                       'principal names (Kerberoasting reconnaissance)'),
    'ldap_asrep': (75, 0.65, 'T1558.004', '{src} searched the directory on {dst} for accounts that do not need '
                                         'Kerberos pre-authentication (AS-REP roasting)'),
    'ldap_delegation': (60, 0.55, 'T1087.002', '{src} searched the directory on {dst} for accounts and computers '
                                               'trusted for delegation'),
    'ldap_trusts': (60, 0.55, 'T1482', '{src} listed the domain trusts in the directory on {dst}'),
    'ldap_laps': (75, 0.65, 'T1552', '{src} asked the directory on {dst} for LAPS local administrator passwords'),
    'ldap_admins': (55, 0.5, 'T1069.002', '{src} searched the directory on {dst} for privileged accounts '
                                          'and groups'),
}
_KIND = {'admin_share': 'admin_share', 'svcctl': 'remote_service', 'atsvc': 'remote_task',
         'taskscheduler': 'remote_task', 'drsuapi': 'dcsync', 'ldap_spn': 'ldap_recon', 'ldap_asrep': 'ldap_recon',
         'ldap_delegation': 'ldap_recon', 'ldap_trusts': 'ldap_recon', 'ldap_laps': 'ldap_recon',
         'ldap_admins': 'ldap_recon'}
LDAP_RECON_KINDS = 3            # distinct kinds of reconnaissance search from one source ...
LDAP_RECON_WINDOW = 600         # ... within this many seconds: ldap_enumeration


def _protocol(what):
    return 'smb' if what == 'admin_share' else 'ldap' if what.startswith('ldap_') else 'dcerpc'


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
        self.ldap_recon = _Window(LDAP_RECON_WINDOW)
        self.cleartext = Cooldown(86400)                     # one cleartext-bind report per pair per day

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
                        {'target': dst, 'protocol': _protocol(what), **fmt}, ts=ts)]

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

    def observe_ldap(self, src, dst, messages, ts=None):
        ts = ts or self.clock()
        if is_external(src):
            return []
        out = []
        for m in messages:
            if m['op'] == 'bind' and m.get('method') == 'simple' and m.get('password'):
                if self.cleartext.ready((src, dst), ts):
                    # an exposure rather than an attack: low probability, so it never triggers a response alone
                    out.append(Finding('ldap_cleartext_bind', src, 35, 0.2, 'T1040',
                                       f'{src} sent a password to {dst} in a plain LDAP simple bind; anyone on '
                                       'the path can read it. Use LDAPS (636) or StartTLS.',
                                       {'target': dst, 'protocol': 'ldap'}, ts=ts))
            elif m['op'] == 'search':
                kinds = set()
                for marker in m.get('markers', ()):
                    out += self._learned_use(f'ldap_{marker}', src, dst, ts, base=m.get('base', '')[:120])
                    kinds = {k for _, k in self.ldap_recon.add(src, ts, marker)}
                if len(kinds) >= LDAP_RECON_KINDS and self.cooldown.ready(('ldap_enumeration', src), ts):
                    out.append(Finding('ldap_enumeration', src, 75, 0.7, 'T1087.002',
                                       f'{src} ran {len(kinds)} kinds of Active Directory reconnaissance search '
                                       f'({", ".join(sorted(kinds))}) on {dst} within '
                                       f'{int(LDAP_RECON_WINDOW / 60)} minutes, as BloodHound or PowerView do',
                                       {'target': dst, 'protocol': 'ldap', 'searches': sorted(kinds)}, ts=ts))
        return out

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
    """('smb'|'rpc'|'kerberos'|'ldap', parsed) for a payload to a Windows service port, or (None, None)."""
    if not payload:
        return None, None
    try:
        if proto == 'TCP' and dport in SMB_PORTS:
            return 'smb', parse_smb(payload)
        if proto == 'TCP' and dport in RPC_PORTS:
            return 'rpc', parse_rpc(payload)
        if dport == KERBEROS_PORT and proto in ('TCP', 'UDP'):
            return 'kerberos', parse_kerberos(payload, proto == 'TCP')
        if (proto == 'TCP' and dport in LDAP_PORTS) or (proto == 'UDP' and dport == 389):
            return 'ldap', parse_ldap(payload)
    except (IndexError, ValueError, struct.error):
        pass
    return None, None
