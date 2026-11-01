"""Lateral movement: SMB2 / DCE-RPC / Kerberos header parsing and the detectors (Phase 9)."""
import struct
import uuid

from capture import afpacket
from detection.lateral import (LateralDetector, LateralStore, parse_kerberos, parse_lateral, parse_rpc,
                               parse_smb)
from detection.pipeline import DetectionPipeline

T0 = 1_700_000_000.0
WEEK = 7 * 86400
WS, SRV, DC = '10.0.0.20', '10.0.0.5', '10.0.0.2'
SVCCTL = uuid.UUID('367abb81-9844-35f1-ad32-98f038001003').bytes_le
DRSUAPI = uuid.UUID('e3514235-4b06-11d1-ab04-00c04fc2dcd2').bytes_le


def smb2(command, body=b'', response=False, next_command=0):
    hdr = b'\xfeSMB' + struct.pack('<HHIHHII', 64, 0, 0, command, 1, 1 if response else 0, next_command)
    hdr += b'\x00' * (64 - len(hdr))
    return hdr + body


def netbios(*msgs):
    data = b''.join(msgs)
    return b'\x00' + len(data).to_bytes(3, 'big') + data


def tree_connect(path):
    raw = path.encode('utf-16-le')
    return smb2(3, struct.pack('<HHHH', 9, 0, 64 + 8, len(raw)) + raw)


def rpc_bind(iface):
    return bytes([5, 0, 11, 3]) + b'\x10\x00\x00\x00' + b'\x00' * 20 + iface + b'\x00' * 20


def detector(**kw):
    return LateralDetector(clock=lambda: T0, **kw)


# ---------- parsing ----------

def test_smb_tree_connect_ntlm_and_pipe_binds():
    [m] = parse_smb(netbios(tree_connect(r'\\fs01\ADMIN$')))
    assert m['command'] == 'tree connect' and m['share'] == 'ADMIN$'
    [m] = parse_smb(netbios(smb2(1, b'\x19\x00' + b'\x00' * 22 + b'NTLMSSP\x00\x03\x00\x00\x00' + b'\x00' * 40)))
    assert m['command'] == 'session setup' and m['ntlm'] is True
    [m] = parse_smb(netbios(smb2(9, b'\x31\x00' + b'\x00' * 46 + rpc_bind(SVCCTL))))
    assert m['rpc'] == ['svcctl']
    assert parse_smb(netbios(tree_connect(r'\\fs01\IPC$'), )) [0]['share'] == 'IPC$'
    assert parse_smb(netbios(smb2(3, response=True))) == []                      # responses skipped
    assert parse_smb(b'GET / HTTP/1.1\r\n' * 10) == []


def test_smb_compounded_requests():
    first = smb2(5, b'\x00' * 8)
    msgs = parse_smb(netbios(smb2(5, b'\x00' * 8, next_command=len(first)), tree_connect(r'\\h\C$')))
    assert [m['command'] for m in msgs] == ['create', 'tree connect'] and msgs[1]['share'] == 'C$'


def test_rpc_and_kerberos():
    assert parse_rpc(rpc_bind(DRSUAPI)) == ['drsuapi']
    assert parse_rpc(b'\x04' + b'\x00' * 40) == []
    assert parse_kerberos(b'\x00\x00\x01\x00\x6c\x82', tcp=True) == 'tgs-req'
    assert parse_kerberos(b'\x6a\x81\x10', tcp=False) == 'as-req'
    assert parse_kerberos(b'\x6b\x00', tcp=False) is None                        # AS-REP
    assert parse_lateral('TCP', 445, b'\x00') == ('smb', [])
    assert parse_lateral('TCP', 80, b'abc') == (None, None)


def test_capture_inspects_control_messages_not_bulk_smb():
    from scapy.all import IP, TCP, UDP, Ether, Raw
    E = dict(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
    small = bytes(Ether(**E) / IP(src=WS, dst=SRV) / TCP(dport=445) / Raw(netbios(tree_connect(r'\\a\C$'))))
    bulk = bytes(Ether(**E) / IP(src=WS, dst=SRV) / TCP(dport=445) / Raw(b'\x00' * 1400))
    kerb = bytes(Ether(**E) / IP(src=WS, dst=DC) / UDP(sport=50000, dport=88) / Raw(b'\x6c\x00'))
    assert afpacket.parse(small)[6] is True and afpacket.parse(bulk)[6] is False
    assert afpacket.parse(kerb)[6] is True


# ---------- detectors ----------

def test_admin_share_learned_then_reported():
    d = detector()
    tc = parse_smb(netbios(tree_connect(r'\\pc1\C$')))
    assert d.observe_smb('10.0.0.9', SRV, tc, ts=T0 + 10) == []                 # backup server, learned
    assert d.observe_smb('10.0.0.9', '10.0.0.77', tc, ts=T0 + WEEK + 1) == []
    [f] = d.observe_smb(WS, SRV, tc, ts=T0 + WEEK + 1)
    assert f.kind == 'admin_share' and f.technique == 'T1021.002' and 'C$' in f.evidence
    assert d.observe_smb(WS, SRV, parse_smb(netbios(tree_connect(r'\\pc1\IPC$'))), ts=T0 + WEEK + 2) == []


def test_service_creation_and_dcsync():
    d = detector()
    bind = parse_smb(netbios(smb2(11, b'\x39\x00' + b'\x00' * 54 + rpc_bind(SVCCTL))))
    [f] = d.observe_smb(WS, SRV, bind, ts=T0 + WEEK + 5)
    assert f.kind == 'remote_service' and f.technique == 'T1569.002'
    assert d.observe_rpc('10.0.0.3', DC, ['drsuapi'], ts=T0 + 5) == []          # second DC learned
    assert d.observe_rpc('10.0.0.3', DC, ['drsuapi'], ts=T0 + WEEK + 5) == []
    [f] = d.observe_rpc(WS, DC, ['drsuapi'], ts=T0 + WEEK + 6)
    assert f.kind == 'dcsync' and f.severity >= 90


def test_ntlm_fanout_pass_the_hash():
    d = detector(ntlm_hosts=3)
    auth = [{'command': 'session setup', 'share': None, 'ntlm': True, 'rpc': []}]
    assert d.observe_smb(WS, '10.0.0.31', auth, ts=T0) == []
    assert d.observe_smb(WS, '10.0.0.32', auth, ts=T0 + 10) == []
    [f] = d.observe_smb(WS, '10.0.0.33', auth, ts=T0 + 20)
    assert f.kind == 'ntlm_fanout' and f.technique == 'T1550.002'


def test_kerberos_burst():
    d = detector(kerberos_per_minute=5)
    out = [d.observe_kerberos(WS, DC, 'tgs-req', ts=T0 + i) for i in range(5)]
    assert [len(o) for o in out] == [0, 0, 0, 0, 1] and out[-1][0].technique == 'T1558.003'
    assert d.observe_kerberos(WS, DC, 'as-req', ts=T0) == []


def test_admin_service_fanout_after_learning():
    d = detector(fanout_hosts=3)
    flow = lambda dst, port, ts: {'src': WS, 'dst': dst, 'dport': port, 'ts': ts}
    assert d.observe(flow(SRV, 3389, T0 + 1)) == []                             # learned
    t = T0 + WEEK + 10
    assert d.observe(flow(SRV, 3389, t)) == []                                  # known pair
    assert d.observe(flow('10.0.0.41', 445, t)) == []
    assert d.observe(flow('10.0.0.42', 5985, t + 1)) == []
    [f] = d.observe(flow('10.0.0.43', 3389, t + 2))
    assert f.kind == 'lateral_fanout' and set(f.details['services']) == {'SMB', 'WinRM', 'RDP'}
    assert d.observe({'src': WS, 'dst': '8.8.8.8', 'dport': 22, 'ts': t}) == []


def test_learning_survives_a_restart(tmp_path):
    store = LateralStore(str(tmp_path / 'lateral.db'))
    d = LateralDetector(store=store, clock=lambda: T0)
    d.observe_rpc('10.0.0.3', DC, ['drsuapi'], ts=T0 + 1)
    again = LateralDetector(store=LateralStore(str(tmp_path / 'lateral.db')), clock=lambda: T0 + WEEK + 100)
    assert again.started == T0 and not again.learning_now(T0 + WEEK + 100)
    assert again.observe_rpc('10.0.0.3', DC, ['drsuapi'], ts=T0 + WEEK + 100) == []
    assert again.observe_rpc(WS, DC, ['drsuapi'], ts=T0 + WEEK + 100)[0].kind == 'dcsync'


def test_pipeline_fuses_lateral_findings():
    pipe = DetectionPipeline(models=False, clock=lambda: T0, lateral=LateralDetector(clock=lambda: T0 - WEEK - 1))
    payload = netbios(smb2(9, b'\x31\x00' + b'\x00' * 46 + rpc_bind(SVCCTL)))
    service, _, findings = pipe.observe_lateral(WS, SRV, 'TCP', 445, payload, ts=T0)
    assert service == 'smb' and [f.kind for f in findings] == ['remote_service']
    assert pipe.fusion.fuse(WS, 0, 0, 'TCP', None, now=T0 + 1)['attack_type'] == 'remote_service'
    assert pipe.observe_lateral(WS, SRV, 'TCP', 443, payload) == (None, None, [])
