"""Response tuning: a bandit that picks gentler responses only inside the playbook's bounds (Phase 7)."""
import random

import pytest

from enforcement import tuning
from enforcement.playbook import DEFAULT_PLAYBOOK, Playbook

T0 = 1_800_000_000.0
HOUR = 3600


class FakeFirewall:
    def __init__(self, refuse=()):
        self.calls, self.refuse = [], set(refuse)

    def add_block(self, ip, ttl=None, reason=''):
        self.calls.append(('block', ip, ttl))

    def add_restriction(self, kind, ip, ttl=None, reason='', mac=None):
        if kind in self.refuse:
            raise ValueError(f'{ip} has no learned peer profile yet')
        self.calls.append((kind, ip, ttl))


class Clock:
    def __init__(self):
        self.t = T0

    def __call__(self):
        return self.t


def playbook(tmp_path, clock, fw=None, approval=None):
    config = {**DEFAULT_PLAYBOOK, 'approval': approval or {'required_from_risk': None}}
    pb = Playbook(config, path=str(tmp_path / 'pb.db'), firewall_module=fw or FakeFirewall(), clock=clock)
    pb.tuner.rng = random.Random(7)
    return pb


def cfg(**kw):
    return {**tuning.DEFAULTS, **kw}


def evidence(pb, kind, action, resolved, failed, ceiling='block'):
    for i in range(resolved + failed):
        pb.tuner.record(f'10.9.{i // 250}.{i % 250}', kind, action, ceiling, ts=T0 - 10 * HOUR)
    with pb._lock:
        db = pb._db()
        rows = db.execute('SELECT id FROM tuning_events WHERE kind = ? AND action = ? AND outcome IS NULL',
                          (kind, action)).fetchall()
        for n, (eid,) in enumerate(rows):
            db.execute('UPDATE tuning_events SET outcome = ? WHERE id = ?', (1 if n < resolved else 0, eid))
        db.commit()


def test_recommend_mode_never_changes_the_decision(tmp_path):
    clock = Clock()
    pb = playbook(tmp_path, clock)
    tuning.save_config({'mode': 'recommend'})
    evidence(pb, 'port_scan', 'rate_limit', 60, 0)
    out = pb.evaluate('192.168.1.50', 80, reason='port_scan')
    assert out['action'] == 'block' and out['status'] == 'applied'
    assert out['tuning']['action'] == 'rate_limit' and out['tuning']['mode'] == 'recommend'
    assert pb.fw.calls == [('block', '192.168.1.50', 3600)]


def test_apply_mode_takes_the_gentler_action_with_its_ttl(tmp_path):
    clock = Clock()
    pb = playbook(tmp_path, clock)
    tuning.save_config({'mode': 'apply'})
    evidence(pb, 'port_scan', 'rate_limit', 60, 0)
    out = pb.evaluate('192.168.1.50', 80, reason='port_scan')
    assert out['action'] == 'rate_limit' and pb.fw.calls == [('ratelimit', '192.168.1.50', 600)]


def test_never_stronger_than_the_playbook_nor_gentler_than_the_floor(tmp_path):
    pb = playbook(tmp_path, Clock())
    evidence(pb, 'dga', 'alert', 500, 0)
    for _ in range(50):
        action, _ = pb.tuner.choose('192.168.1.7', 'dga', 'rate_limit', cfg(), now=T0)
        assert action == 'rate_limit'                     # alert has evidence, but the floor is rate_limit
    action, _ = pb.tuner.choose('192.168.1.7', 'dga', 'rate_limit', cfg(min_action='alert'), explore=False, now=T0)
    assert action == 'alert'
    assert all(pb.tuner.choose('192.168.1.8', 'x', 'block', cfg(), now=T0)[0] in ('rate_limit', 'block')
               for _ in range(100))


def test_without_evidence_gentler_actions_are_rarely_tried(tmp_path):
    pb = playbook(tmp_path, Clock())
    picks = [pb.tuner.choose(f'192.168.2.{i}', 'brute_force', 'block', cfg(), now=T0)[0] for i in range(200)]
    assert picks.count('block') >= 195


def test_a_failed_response_is_never_repeated_for_the_same_incident(tmp_path):
    clock = Clock()
    pb = playbook(tmp_path, clock)
    tuning.save_config({'mode': 'apply'})
    evidence(pb, 'port_scan', 'rate_limit', 60, 0)
    assert pb.evaluate('192.168.1.60', 80, reason='port_scan')['action'] == 'rate_limit'
    clock.t += 120                                        # the same source again: rate limiting did not work
    assert pb.evaluate('192.168.1.60', 80, reason='port_scan')['action'] == 'block'
    stats = pb.tuner.stats()['port_scan']['rate_limit']
    assert stats == [60, 1]


def test_outcomes_settle_after_the_window(tmp_path):
    clock = Clock()
    pb = playbook(tmp_path, clock)
    tuning.save_config({'mode': 'recommend'})
    pb.evaluate('192.168.1.70', 80, reason='beaconing')   # resolved: never seen again
    pb.evaluate('192.168.1.71', 80, reason='beaconing')
    clock.t += 1800
    pb.evaluate('192.168.1.71', 40, reason='beaconing')   # below the playbook threshold, but a detection
    clock.t += 2 * HOUR
    pb.tuner.settle(HOUR)
    assert pb.tuner.stats()['beaconing']['block'] == [1, 1]


def test_false_positive_labels_count_as_alerts_that_were_enough(tmp_path):
    pb = playbook(tmp_path, Clock())
    pb.tuner._false_positives = lambda: {(f'10.0.0.{i}', 'new_device') for i in range(80)}
    assert pb.tuner.stats()['new_device']['alert'] == [80, 0]
    assert pb.tuner.summary(cfg(min_action='alert'))[0]['recommended_instead_of_block'] == 'alert'


def test_contain_only_with_a_profile_and_falls_back_when_refused(tmp_path, monkeypatch):
    clock = Clock()
    fw = FakeFirewall(refuse={'contain'})
    pb = playbook(tmp_path, clock, fw=fw)
    tuning.save_config({'mode': 'apply', 'min_action': 'contain'})
    evidence(pb, 'exfiltration', 'contain', 60, 0)
    assert pb.tuner.choose('192.168.1.80', 'exfiltration', 'block', cfg(min_action='contain'), now=T0)[0] == 'block'
    monkeypatch.setattr('detection.peers.learned', lambda profile, now=None: True)
    out = pb.evaluate('192.168.1.80', 80, reason='exfiltration')
    assert out['action'] == 'block' and fw.calls == [('block', '192.168.1.80', 3600)]


def test_the_approval_gate_still_applies(tmp_path):
    clock = Clock()
    pb = playbook(tmp_path, clock, approval={'required_from_risk': 75, 'until': None})
    tuning.save_config({'mode': 'apply'})
    evidence(pb, 'port_scan', 'rate_limit', 60, 0)
    out = pb.evaluate('192.168.1.90', 80, reason='port_scan')
    assert out['status'] == 'awaiting_approval' and out['action'] == 'rate_limit' and pb.fw.calls == []
    pb.decide(out['pending_id'], True, 'otto')
    assert pb.fw.calls == [('ratelimit', '192.168.1.90', 600)]


def test_off_mode_does_nothing(tmp_path):
    pb = playbook(tmp_path, Clock())
    tuning.save_config({'mode': 'off'})
    out = pb.evaluate('192.168.1.95', 80, reason='port_scan')
    assert 'tuning' not in out and pb.tuner.stats() == {}


def test_config_is_validated():
    for bad in ({'mode': 'yolo'}, {'min_action': 'quarantine'}, {'target': 0.2}, {'window_seconds': 5}):
        with pytest.raises(ValueError):
            tuning.save_config(bad)
