"""OT micro-segmentation: plans, modes, the frozen snapshot and rollback (Phase 7).

The kernel side is covered by tests/firewall_netns/run_segmentation_netns.sh.
"""
import time

import pytest

import core.firewall as firewall
from detection.ot import OTStore
from enforcement import segmentation as seg

PLC, PLC2, HMI, HMI2, LAPTOP = '192.168.10.5', '192.168.10.6', '192.168.10.20', '192.168.10.21', '192.168.10.77'
OLD = time.time() - 8 * 86400


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setattr(firewall, 'ROOT', str(tmp_path))
    monkeypatch.setattr(firewall, 'FIREWALL_DRY_RUN', True)
    monkeypatch.setenv('SENTINEL_BRIDGE', '1')
    monkeypatch.setattr('enforcement.protected.why_protected', lambda ip, hosts=None: None)
    yield


def learn(src, dst, protocol='modbus', first=OLD, function='read holding registers'):
    store = OTStore()
    store.add_server(dst, protocol, first)
    store.touch(src, dst, protocol, '', first)
    store.touch(src, dst, protocol, function, first)
    store.close()


def test_plan_guards_learned_controllers_only():
    learn(HMI, PLC)
    learn(HMI2, PLC2, 'dnp3', first=time.time() - 3600)              # still learning
    plan = seg.build_plan(always=[])
    assert plan['controllers'] == [{'ip': PLC, 'protocol': 'modbus', 'allowed': [HMI]}]
    assert [c['ip'] for c in plan['learning']] == [PLC2]


def test_management_hosts_are_always_allowed_and_protected_hosts_never_guarded(monkeypatch):
    learn(HMI, PLC)
    learn(HMI, PLC2)
    monkeypatch.setattr('enforcement.protected.why_protected', lambda ip, hosts=None: 'gateway' if ip == PLC2 else None)
    plan = seg.build_plan(always=['192.168.10.2'])
    assert plan['controllers'] == [{'ip': PLC, 'protocol': 'modbus', 'allowed': ['192.168.10.2', HMI]}]
    assert plan['skipped'] == [{'ip': PLC2, 'protocol': 'modbus', 'reason': 'gateway'}]


def test_nft_script_lists_every_port_of_the_protocol():
    script = seg.nft_script({'controllers': [{'ip': PLC, 'protocol': 'dnp3', 'allowed': [HMI]}]}, bridge=True)
    assert f'{PLC} . tcp . 20000, {PLC} . udp . 20000' in script
    assert f'{HMI} . {PLC} . tcp . 20000, {HMI} . {PLC} . udp . 20000' in script
    assert script.count('counter drop') == 2                          # inet and bridge
    assert script.count('ct state established,related return') == 1  # bridged traffic has no conntrack


def test_enforce_needs_inline_placement_and_a_learned_controller(monkeypatch):
    with pytest.raises(ValueError, match='no OT controller'):
        seg.set_mode('enforce')
    learn(HMI, PLC)
    monkeypatch.setenv('SENTINEL_BRIDGE', '0')
    with pytest.raises(ValueError, match='inline'):
        seg.set_mode('enforce')
    with pytest.raises(ValueError, match='mode must be'):
        seg.set_mode('block-everything')


def test_enforced_plan_is_a_frozen_snapshot():
    learn(HMI, PLC)
    assert seg.set_mode('enforce', by='adam')['mode'] == 'enforce'
    learn(LAPTOP, PLC)                                                 # the detector learns a new master afterwards
    assert seg.status()['plan']['controllers'][0]['allowed'] == [HMI]  # ... which is not allowed by itself
    seg.allow(LAPTOP, PLC, 'modbus', by='adam')
    assert seg.status()['plan']['controllers'][0]['allowed'] == [HMI, LAPTOP]
    assert seg.load()['extra'] == [[LAPTOP, PLC, 'modbus']]


def test_refresh_takes_a_new_snapshot():
    learn(HMI, PLC)
    seg.set_mode('enforce')
    learn(HMI2, PLC2)
    assert len(seg.refresh()['plan']['controllers']) == 2
    seg.set_mode('monitor')
    with pytest.raises(ValueError, match='while enforcing'):
        seg.refresh()


def test_allow_validates_its_input():
    with pytest.raises(ValueError, match='IPv4'):
        seg.allow('not-an-ip', PLC, 'modbus')
    with pytest.raises(ValueError, match='protocol'):
        seg.allow(HMI, PLC, 'profinet')


def test_rollback_turns_enforcement_off():
    learn(HMI, PLC)
    seg.set_mode('enforce')
    firewall.rollback_blocks('watchdog: enforcer down')
    state = seg.status()
    assert state['mode'] == 'off' and state['suspended']['reason'] == 'watchdog: enforcer down'


def test_reapply_only_when_enforcing(monkeypatch):
    calls = []
    monkeypatch.setattr(seg, '_install', lambda plan: calls.append(plan) or (True, 'ok'))
    assert seg.reapply() == (True, 'nothing to apply')
    learn(HMI, PLC)
    seg.set_mode('enforce')
    seg.reapply()
    assert len(calls) == 2 and calls[1]['controllers'][0]['ip'] == PLC


def test_mode_changes_are_audited():
    from core import audit
    learn(HMI, PLC)
    seg.set_mode('enforce', by='adam')
    seg.set_mode('off', by='adam')
    entries = [e for e in audit.get_log().entries(action='ot_segmentation')]
    assert sorted(e['details']['mode'] for e in entries) == ['enforce', 'off']
