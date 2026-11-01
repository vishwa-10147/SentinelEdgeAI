"""Passive OS and device-type fingerprinting (Phase 9, asset context)."""
from scapy.all import IP, TCP, Ether, IPv6, Raw

from capture import afpacket
from enforcement import identity, os_fingerprint as osfp

# option lists as the real stacks send them in a SYN
WINDOWS = dict(ttl=128, window=64240, options=[('MSS', 1460), ('NOP', None), ('WScale', 8), ('NOP', None),
                                               ('NOP', None), ('SAckOK', b'')])
LINUX = dict(ttl=64, window=64240, options=[('MSS', 1460), ('SAckOK', b''), ('Timestamp', (12345, 0)),
                                            ('NOP', None), ('WScale', 7)])
APPLE = dict(ttl=64, window=65535, options=[('MSS', 1460), ('NOP', None), ('WScale', 6), ('NOP', None),
                                            ('NOP', None), ('Timestamp', (99, 0)), ('SAckOK', b''),
                                            ('EOL', None)])
FREEBSD = dict(ttl=64, window=65535, options=[('MSS', 1460), ('NOP', None), ('WScale', 6), ('SAckOK', b''),
                                              ('Timestamp', (5, 0))])
IOT = dict(ttl=255, window=5840, options=[('MSS', 536)])


def syn(src, stack, hops=0, flags='S', v6=False):
    ip = IPv6(src=src, dst='fd00::1', hlim=stack['ttl'] - hops) if v6 else \
        IP(src=src, dst='192.168.1.1', ttl=stack['ttl'] - hops, flags='DF', id=0)
    return bytes(ip / TCP(sport=50000, dport=443, flags=flags, window=stack['window'], options=stack['options']))


def test_classifies_common_stacks():
    for stack, family, conf in ((WINDOWS, 'windows', 'high'), (LINUX, 'linux', 'high'), (APPLE, 'apple', 'high'),
                                (FREEBSD, 'bsd', 'high'), (IOT, 'network', 'medium')):
        fp = osfp.parse_syn(syn('192.168.1.20', stack, hops=2))
        c = osfp.classify(fp)
        assert (c['family'], c['confidence']) == (family, conf), (stack, c, fp['signature'])
        assert fp['hops'] == 2


def test_signature_fields():
    fp = osfp.parse_syn(syn('192.168.1.20', LINUX))
    assert fp['signature'] == '4:64:0:1460:64240,7:mss,sok,ts,nop,ws:df,id0'
    assert fp['src'] == '192.168.1.20' and fp['mss'] == 1460 and fp['wscale'] == 7
    v6 = osfp.parse_syn(syn('fd00::20', APPLE, v6=True))
    assert v6['src'] == 'fd00::20' and v6['signature'].startswith('6:64:0:1460:65535,6:mss,nop,ws,nop,nop,ts,sok,eol')


def test_only_client_syns_are_parsed():
    assert osfp.parse_syn(syn('192.168.1.20', LINUX, flags='SA')) is None     # server reply
    assert osfp.parse_syn(syn('192.168.1.20', LINUX, flags='A')) is None
    assert osfp.parse_syn(b'\x45' + b'\x00' * 10) is None                    # truncated
    udp = bytes(IP(src='192.168.1.20', dst='192.168.1.1', proto=17) / Raw(b'\x00' * 30))
    assert osfp.parse_syn(udp) is None


def test_malformed_options_do_not_raise():
    pkt = bytearray(syn('192.168.1.20', LINUX))
    pkt[20 + 20 + 1] = 40                       # MSS option claims 40 bytes, past the header
    fp = osfp.parse_syn(bytes(pkt))
    assert 'bad' in fp['quirks']


def test_store_records_internal_hosts_once_per_minute():
    store = osfp.FingerprintStore()
    assert store.observe_ip(syn('192.168.1.20', WINDOWS), now=0)['signature']
    assert store.observe_ip(syn('192.168.1.20', WINDOWS), now=30) is None      # re-checked after a minute
    assert store.observe_ip(syn('8.8.8.8', LINUX), now=0) is None              # internet host
    assert store.observe_ip(syn('fd00::20', APPLE, v6=True), now=0) is not None
    rows = {r['ip']: r for r in store.list()}
    assert set(rows) == {'192.168.1.20', 'fd00::20'}
    assert rows['192.168.1.20']['os'] == 'Windows' and rows['192.168.1.20']['ttl'] == 128
    # a different stack on the same address (a new device took the IP) is recorded and counted
    assert store.observe_ip(syn('192.168.1.20', LINUX), now=100) is not None
    assert store.get('192.168.1.20')['changes'] == 1 and store.get('192.168.1.20')['os'] == 'Linux / Android'
    store.close()


def test_write_budget_bounds_a_flood(monkeypatch):
    monkeypatch.setattr(osfp, 'WRITES_PER_SECOND', 5)
    store = osfp.FingerprintStore()
    recorded = sum(1 for i in range(50) if store.observe_ip(syn(f'10.0.{i // 250}.{i % 250 + 1}', LINUX), now=0))
    assert recorded <= 5 and store.skipped >= 45
    assert len(store.list()) == recorded
    store.close()


def test_afpacket_fast_path_feeds_the_observer(monkeypatch):
    seen = []
    monkeypatch.setattr(afpacket, 'syn_observer', lambda ip: seen.append(bytes(ip)))
    frame = bytes(Ether() / IP(syn('192.168.1.20', WINDOWS)))
    parsed = afpacket.parse(frame)
    assert parsed[4] == 'TCP' and parsed[6] is False                      # SYNs stay on the fast path
    assert len(seen) == 1 and osfp.parse_syn(seen[0])['src'] == '192.168.1.20'
    afpacket.parse(bytes(Ether() / IP(src='192.168.1.20', dst='192.168.1.1') / TCP(flags='A')))
    assert len(seen) == 1


def test_infer_combines_dhcp_vendor_and_tcp():
    linux = osfp.parse_syn(syn('192.168.1.30', LINUX))
    android = osfp.infer({'vendor_class': 'android-dhcp-14', 'vendor': 'Private (randomised MAC)'}, linux)
    assert android['os'] == 'Android' and android['device_type'] == 'Phone / tablet / laptop'
    assert android['confidence'] == 'high'
    win = osfp.infer({'vendor_class': 'MSFT 5.0', 'dhcp_fingerprint': '1,3,6,15,31,33,43,44,46,47,119,121,249,252',
                      'hostname': 'DESKTOP-4KQ9'}, osfp.parse_syn(syn('192.168.1.31', WINDOWS)))
    assert win['os'] == 'Windows' and win['confidence'] == 'high' and win['device_type'] == 'Computer'
    assert {e['source'] for e in win['evidence']} == {'DHCP vendor class', 'TCP SYN fingerprint',
                                                     'DHCP parameter list', 'DHCP hostname'}
    printer = osfp.infer({'vendor': 'Brother Industries, Ltd.', 'hostname': 'BRW0080'},
                         osfp.parse_syn(syn('192.168.1.32', IOT)))
    assert printer['device_type'] == 'Printer'
    iphone = osfp.infer({'vendor': 'Apple, Inc.', 'hostname': 'Alexs-iPhone'}, osfp.parse_syn(syn('192.168.1.33', APPLE)))
    assert iphone['os'] == 'iOS' and iphone['device_type'] == 'Phone / tablet'
    # a hostname alone never overrides a high-confidence TCP fingerprint
    odd = osfp.infer({'hostname': 'DESKTOP-PI'}, linux)
    assert odd['os'] == 'Linux / Android'
    assert osfp.infer({}, None) == {'os': None, 'device_type': None, 'confidence': None, 'evidence': []}


def test_profile_joins_registry_and_store():
    reg = identity.DeviceRegistry()
    reg.observe('3c:22:fb:00:00:01', ip='192.168.1.40', hostname='macbook-pro', vendor_class=None)
    store = osfp.FingerprintStore()
    store.observe_ip(syn('192.168.1.40', APPLE), now=0)
    p = osfp.profile('192.168.1.40', reg, store)
    assert p['os'] == 'macOS' and p['mac'] == '3c:22:fb:00:00:01' and p['tcp_signature']
    assert [x['ip'] for x in osfp.profiles(registry=reg, store=store)] == ['192.168.1.40']
    reg.close()
    store.close()


def test_profile_endpoint():
    from fastapi.testclient import TestClient
    from dashboard import dashboard_api as api
    osfp.get_store().observe_ip(syn('192.168.1.50', WINDOWS), now=0)
    api.app.dependency_overrides[api.require_viewer] = lambda: {'username': 't', 'role': 'viewer'}
    try:
        client = TestClient(api.app)
        body = client.get('/api/assets/192.168.1.50/profile').json()
        assert client.get('/api/assets/not-an-ip/profile').status_code == 400
        listed = client.get('/api/assets/profiles').json()
    finally:
        api.app.dependency_overrides.clear()
        osfp.get_store().close()
    assert body['os'] == 'Windows' and body['device_type'] == 'Computer'
    assert [p['ip'] for p in listed['profiles']] == ['192.168.1.50']
