"""Flood safety: a flood of spoofed addresses must not exhaust the appliance's memory."""
import random
from datetime import datetime, timedelta, timezone

import pytest

from common.bounded import BoundedDict, BoundedSet
from flow.flow_table import FlowTable


def spoofed(rng):
    return f'10.{rng.randrange(256)}.{rng.randrange(256)}.{rng.randrange(256)}', rng.randrange(1024, 65535)


# ---------- containers ----------

def test_bounded_dict_drops_the_oldest_and_counts():
    d = BoundedDict(3, list)
    for k in 'abcde':
        d[k].append(k)
    assert list(d) == ['c', 'd', 'e'] and d.evicted == 2
    d.touch('c')
    d['f'] = ['f']
    assert list(d) == ['e', 'c', 'f']
    with pytest.raises(KeyError):
        BoundedDict(2)['missing']
    s = BoundedSet(2)
    for x in range(5):
        s.add(x)
    assert 4 in s and 0 not in s and len(s) == 2 and s.evicted == 3


# ---------- the flow table ----------

def test_flow_table_is_capped_and_keeps_the_active_flows():
    ft = FlowTable(max_flows=1000)
    rng = random.Random(1)
    for i in range(5000):
        ft.process_packet('192.168.1.5', 50000, '192.168.1.10', 443, 'TCP', 1500)   # a real, busy session
        src, sport = spoofed(rng)
        ft.process_packet(src, sport, '192.168.1.10', 80, 'TCP', 60)
    st = ft.stats()
    assert st['active'] == 1000 and st['evicted_total'] == 4001
    key = ft._generate_key('192.168.1.5', 50000, '192.168.1.10', 443, 'TCP')
    assert ft.flows[key]['forward_packets'] == 5000                                 # never evicted


def test_evicted_flows_are_scored_within_a_budget(monkeypatch):
    import flow.flow_table as module
    monkeypatch.setattr(module, 'EVICT_SCORE_BUDGET', 10)
    ft = FlowTable(max_flows=100)
    rng = random.Random(2)
    for _ in range(150):
        ft.process_packet(*spoofed(rng), '192.168.1.10', 80, 'TCP', 60)
    out = ft.check_timeouts()
    assert [r.flow_state for r in out] == ['EVICTED'] * 10
    assert ft.stats()['shed_total'] == 40 and ft.check_timeouts() == []


def test_idle_flows_still_expire_oldest_first():
    ft = FlowTable(idle_timeout=30, max_flows=100)
    ft.process_packet('192.168.1.5', 1000, '192.168.1.10', 53, 'UDP', 80)
    ft.process_packet('192.168.1.6', 1001, '192.168.1.10', 53, 'UDP', 80)
    old = datetime.now(timezone.utc) - timedelta(seconds=60)
    first = next(iter(ft.flows))
    ft.flows[first]['last_seen'] = old
    out = ft.check_timeouts()
    assert [r.initiator_ip for r in out] == ['192.168.1.5'] and len(ft.flows) == 1
    assert [r.flow_state for r in ft.expire_all()] == ['FORCED_EXPIRE'] and not ft.flows


# ---------- detectors under a flood ----------

def test_detector_state_stays_bounded_under_spoofed_sources(monkeypatch):
    from detection import detectors, dns_analysis, fusion, tls
    monkeypatch.setattr(detectors, 'MAX_SOURCES', 500)
    monkeypatch.setattr(detectors, 'MAX_KEYS', 1000)
    for module in (dns_analysis, fusion, tls):
        for name in ('MAX_SOURCES', 'MAX_KEYS'):
            if hasattr(module, name):
                monkeypatch.setattr(module, name, getattr(detectors, name))
    from detection.pipeline import DetectionPipeline
    pipe = DetectionPipeline(models=False, clock=lambda: 1_800_000_000.0)
    rng = random.Random(3)
    for i in range(6000):
        src = f'192.168.{rng.randrange(256)}.{rng.randrange(256)}'
        pipe.observe_flow({'ts': 1_800_000_000.0 + i * 0.01, 'src': src, 'dst': '192.168.1.10', 'dport': rng.randrange(1, 1024),
                           'proto': 'TCP', 'duration': 0.0, 'forward_bytes': 60, 'backward_bytes': 0})
        pipe.observe_dns(src, f'{rng.random()}.example.com', ts=1_800_000_000.0 + i)
    for det in pipe.flow_detectors:
        for attr in ('data', 'last', 'seen', 'first'):
            obj = getattr(det, attr, None) or getattr(getattr(det, 'w', None), attr, None) \
                or getattr(getattr(det, 'cooldown', None), attr, None)
            if isinstance(obj, BoundedDict):
                assert len(obj) <= 1000, (type(det).__name__, attr, len(obj))
        known = getattr(det, 'known', None)
        if isinstance(known, BoundedSet):
            assert len(known) <= 500
    assert len(pipe.fusion.recent) <= 500 and len(pipe.dns.lookups) <= 500


def test_baseline_keeps_numbers_not_feature_dicts():
    from detection.adaptive_baseline import AdaptiveBaseline
    b = AdaptiveBaseline(window_size=50)
    f = {'duration': 1.0, 'total_bytes': 100, 'total_packets': 2, 'byte_ratio': 0.5, 'other': 'x' * 1000}
    for _ in range(20):
        b.update(f, '192.168.1.5', 'TCP')
    assert b.get('192.168.1.5', 'TCP')['bytes_mean'] == 100
    assert b.data['192.168.1.5_TCP'][0] == (1.0, 100, 2, 0.5)
    assert b.count('10.9.9.9', 'TCP') == 0 and '10.9.9.9_TCP' not in b.data        # reading creates nothing


def test_spoofed_ot_traffic_cannot_fill_the_controller_table(monkeypatch):
    from detection import ot
    monkeypatch.setattr(ot, 'MAX_SERVERS', 50)
    det = ot.OTDetector()
    msgs = ot.parse_bacnet(b'\x81\x0b\x00\x0c\x01\x20\xff\xff\x00\xff\x10\x08')
    for i in range(500):
        det.observe(f'192.168.5.{i % 250}', f'192.168.{i // 250}.{i % 250}', 'bacnet', msgs, ts=1_800_000_000.0)
    assert len(det.servers) == 50 and det.ignored == 450


def test_device_registry_and_peer_profiles_are_capped(monkeypatch, tmp_path):
    from detection import peers
    from enforcement import identity
    monkeypatch.setattr(identity, 'MAX_DEVICES', 20)
    reg = identity.DeviceRegistry(str(tmp_path / 'devices.db'))
    for i in range(60):
        reg.observe(f'02:00:00:00:00:{i:02x}', ip=f'192.168.1.{i}')
    assert len(reg.list(limit=1000)) == 20
    monkeypatch.setattr(peers, 'MAX_HOSTS', 30)
    store = peers.PeerStore(str(tmp_path / 'peers.db'))
    for i in range(100):
        store.observe({'src': f'192.168.2.{i}', 'dst': '192.168.1.10', 'proto': 'TCP', 'dport': 445, 'ts': 1.0 + i})
    assert len(store.first_seen()) == 30
    store.observe({'src': '192.168.2.1', 'dst': '192.168.1.11', 'proto': 'TCP', 'dport': 22, 'ts': 1000.0})
    assert ('192.168.1.11', 'tcp', 22) in store.profile('192.168.2.1')['internal']   # known devices still learn


def test_overload_raises_one_alert_and_clears():
    from capture.overload import OverloadMonitor
    alerts = []
    ft = FlowTable(max_flows=10)
    mon = OverloadMonitor(ft, alerts.append)
    rng = random.Random(4)
    clock = 1000.0
    mon.check(clock)
    for _ in range(3):
        for _ in range(50):
            ft.process_packet(*spoofed(rng), '192.168.1.10', 80, 'TCP', 60)
        clock += 11
        mon.check(clock)
    assert mon.stats()['overloaded'] is True
    assert [a['attack_type'] for a in alerts] == ['capture_overload']             # one alert, not one per check
    assert alerts[0]['details']['evicted_total'] == 40                             # raised at the first overloaded check
    clock += 11
    mon.check(clock)                                                               # the flood stopped
    assert mon.stats()['overloaded'] is False
    mon.ingest_shed += 5                                                           # scoring falls behind
    clock += 11
    mon.check(clock)
    assert mon.overloaded and len(alerts) == 1                                     # still within the alert interval
