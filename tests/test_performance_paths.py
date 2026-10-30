from datetime import datetime, timedelta, timezone

import numpy as np
import pytest
from scapy.all import IP, TCP, UDP, Dot1Q, Ether, IPv6, Raw
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.l2 import ARP
from sklearn.ensemble import IsolationForest

from capture import afpacket
from detection.fast_iforest import FastIsolationForest
from flow.flow_table import FlowTable

E = dict(src='00:11:22:33:44:55', dst='66:77:88:99:aa:bb')


def test_parse_tcp_udp_and_slow_path_selection():
    tcp = bytes(Ether(**E) / IP(src='192.168.1.2', dst='8.8.8.8') / TCP(sport=40000, dport=443) / Raw(b'\x17data'))
    assert afpacket.parse(tcp) == ('192.168.1.2', '8.8.8.8', 40000, 443, 'TCP', len(tcp), False)
    hello = bytes(Ether(**E) / IP(src='192.168.1.2', dst='8.8.8.8') / TCP(sport=40001, dport=443) / Raw(b'\x16\x03\x01'))
    assert afpacket.parse(hello)[6] is True                     # TLS handshake -> scapy for JA3/JA4
    dns = bytes(Ether(**E) / IP(src='192.168.1.2', dst='192.168.1.1') / UDP(sport=5000, dport=53) / DNS(qd=DNSQR(qname='a.b')))
    assert afpacket.parse(dns)[4:] == ('UDP', len(dns), True)
    assert afpacket.parse(bytes(Ether(**E) / ARP(psrc='192.168.1.2')))[4] == 'ARP'


def test_parse_vlan_ipv6_fragments_and_junk():
    vlan = bytes(Ether(**E) / Dot1Q(vlan=10) / IP(src='10.0.0.1', dst='10.0.0.2') / UDP(sport=1, dport=2))
    assert afpacket.parse(vlan)[:5] == ('10.0.0.1', '10.0.0.2', 1, 2, 'UDP')
    v6 = bytes(Ether(**E) / IPv6(src='2001:db8::1', dst='2001:db8::2') / TCP(sport=3, dport=4))
    assert afpacket.parse(v6)[:5] == ('2001:db8::1', '2001:db8::2', 3, 4, 'TCP')
    frag = bytes(Ether(**E) / IP(src='10.0.0.1', dst='10.0.0.2', frag=100) / Raw(b'x' * 20))
    assert afpacket.parse(frag)[2:5] == (0, 0, 'OTHER')
    assert afpacket.parse(b'\x00' * 10) is None
    assert afpacket.parse(bytes(Ether(**E, type=0x88CC) / Raw(b'lldp'))) is None


def test_parse_agrees_with_scapy_on_mixed_traffic():
    from scripts.benchmark_capture import frames
    for raw in frames(300, seed=3):
        p = Ether(raw)
        got = afpacket.parse(raw)
        layer = TCP if TCP in p else UDP
        assert got[:4] == (p[IP].src, p[IP].dst, p[layer].sport, p[layer].dport)


def test_compiled_isolation_forest_matches_sklearn():
    rng = np.random.default_rng(0)
    X = np.vstack([rng.normal(0, 1, (500, 6)), rng.normal(8, 1, (10, 6))])
    model = IsolationForest(n_estimators=50, contamination=0.02, random_state=0).fit(X)
    fast = FastIsolationForest(model, check_samples=300)
    test = np.vstack([rng.normal(0, 2, (300, 6)), rng.lognormal(2, 2, (100, 6))])
    assert np.allclose(model.score_samples(test), [fast.score_samples(r) for r in test])
    assert list(model.predict(test)) == [fast.predict_one(r) for r in test]


def test_compiled_forest_refuses_a_mismatch(monkeypatch):
    rng = np.random.default_rng(1)
    model = IsolationForest(n_estimators=10, random_state=0).fit(rng.normal(0, 1, (200, 3)))
    monkeypatch.setattr(model, 'offset_', model.offset_)            # untouched model passes
    FastIsolationForest(model, check_samples=50)
    monkeypatch.setattr(FastIsolationForest, 'score_samples', lambda self, x: 0.0)
    with pytest.raises(ValueError, match='disagrees'):
        FastIsolationForest(model, check_samples=50)


def test_flows_idle_for_more_than_a_day_expire():
    ft = FlowTable(idle_timeout=30)
    ft.process_packet('10.0.0.1', 1, '10.0.0.2', 2, 'TCP', 100)
    key = next(iter(ft.flows))
    # timedelta(days=1, seconds=5).seconds == 5: the old check never expired this flow
    ft.flows[key]['last_seen'] = datetime.now(timezone.utc) - timedelta(days=1, seconds=5)
    assert len(ft.check_timeouts()) == 1


def test_api_reference_is_up_to_date():
    import subprocess
    import sys
    r = subprocess.run([sys.executable, 'scripts/gen_api_reference.py', '--check'], capture_output=True, text=True)
    assert r.returncode == 0, r.stderr
