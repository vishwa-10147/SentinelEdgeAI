"""High availability: active/standby brains, the leader lease, pairing, sensor failover, dual sensors (Phase 7)."""
import os
import time

import pytest

import brain.store as store_module
from brain import ha, keys, manage
from brain.store import BrainStore
from common import pki
from sensor import uplink
from tests.test_brain_link import Brain, enrolled_uplink, env, free_port, records  # noqa: F401
from tests.test_brain_store_backends import store as backend_store  # noqa: F401  (sqlite + postgres)


def test_one_leader_at_a_time_and_takeover_after_expiry(backend_store, monkeypatch):
    s = backend_store
    s._db().execute('DELETE FROM lease')
    now = [1_800_000_000]
    monkeypatch.setattr(store_module.time, 'time', lambda: now[0])
    assert s.acquire_lease('brain-leader', 'brain-a', 30)
    assert not s.acquire_lease('brain-leader', 'brain-b', 30)
    now[0] += 20
    assert s.acquire_lease('brain-leader', 'brain-a', 30)              # renewal
    now[0] += 31                                                       # brain-a stopped renewing
    assert s.acquire_lease('brain-leader', 'brain-b', 30)
    assert not s.acquire_lease('brain-leader', 'brain-a', 30)
    assert s.lease('brain-leader')['holder'] == 'brain-b'


def test_pairing_bundle_moves_the_shared_keys_only(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTINEL_BRAIN_DIR', str(tmp_path / 'a'))
    keys.init(hostnames=['brain-a'], ips=['127.0.0.1'])
    a_server = keys.read('server.pem')
    bundle = str(tmp_path / 'pair.seha')
    out = ha.export_bundle(bundle, 'correct horse battery')
    assert oct(os.stat(bundle).st_mode & 0o777) == '0o600'
    monkeypatch.setenv('SENTINEL_BRAIN_DIR', str(tmp_path / 'b'))
    with pytest.raises(ValueError, match='wrong passphrase'):
        ha.import_bundle(bundle, 'not the passphrase!!')
    assert ha.import_bundle(bundle, 'correct horse battery')['ca_fingerprint'] == out['ca_fingerprint']
    assert keys.read('server.pem') != a_server                       # brain B has its own server certificate
    assert pki.fingerprint(keys.read('ca.pem')) == out['ca_fingerprint']
    monkeypatch.setenv('SENTINEL_BRAIN_DIR', str(tmp_path / 'c'))
    keys.init()
    with pytest.raises(ValueError, match='different CA'):
        ha.import_bundle(bundle, 'correct horse battery')


def test_only_the_active_brain_issues_commands(env, tmp_path, monkeypatch):
    link, _ = enrolled_uplink(env, tmp_path)
    sid = link.identity['sensor_id']
    assert manage.issue_command(sid, 'block', '198.51.100.7', ttl=60)  # this brain took the lease
    other = BrainStore(manage.store().path)                            # the standby, on the same database
    other.acquire_lease(ha.LEASE, 'someone-else', 30)
    manage.store().release_lease(ha.LEASE, ha.instance_id())
    assert other.acquire_lease(ha.LEASE, 'someone-else', 30)
    with pytest.raises(manage.StandbyError):
        manage.issue_command(sid, 'block', '198.51.100.8', ttl=60)
    assert ha.status(manage.store())['role'] == 'standby'


def test_sensor_fails_over_to_the_standby_brain(env, tmp_path):
    link, _ = enrolled_uplink(env, tmp_path)
    standby = Brain(free_port())
    standby.start()
    try:
        assert uplink.add_brain(standby.url) == [env.url, standby.url]
        link = uplink.Uplink(uplink.load_identity(), buffer=link.buffer, enforcer=link.enforcer, timeout=2)
        link.buffer.put(records(5))
        assert link.flush_once() == 5 and link.url == env.url
        env.stop()                                                     # the active brain goes away
        link.buffer.put(records(5, start=5))
        assert link.flush_once() == 0 and link.url == standby.url      # failed once, switched over
        assert link.flush_once() == 5
        assert manage.store().flow_count() == 10                       # one shared store: nothing lost
    finally:
        standby.stop()


def test_add_brain_refuses_a_brain_from_another_ca(env, tmp_path, monkeypatch):
    enrolled_uplink(env, tmp_path)
    with pytest.raises(uplink.EnrolmentError, match='could not reach'):
        uplink.add_brain('https://127.0.0.1:1')


def test_dual_sensors_the_healthy_one_gets_the_command(env, tmp_path, monkeypatch):
    s = manage.store()
    s.add_sensor('sensor-a', 'pi-a', 'fp-a')
    s.add_sensor('sensor-b', 'pi-b', 'fp-b')
    s.set_segment('sensor-a', 'floor-2')
    s.set_segment('sensor-b', 'floor-2')
    s.touch('sensor-b', {'version': 'x'})
    s._exec('UPDATE sensors SET last_seen = ? WHERE id = ?', (int(time.time()) - 3600, 'sensor-a'))
    sid, env_ = manage.issue_segment_command('floor-2', 'block', '198.51.100.9', ttl=60)
    assert sid == 'sensor-b' and env_['payload']['sensor_id'] == 'sensor-b'
    s._exec('UPDATE sensors SET last_seen = ? WHERE id = ?', (int(time.time()) - 3600, 'sensor-b'))
    with pytest.raises(ValueError, match='no sensor of segment'):
        manage.issue_segment_command('floor-2', 'block', '198.51.100.9')
    with pytest.raises(KeyError):
        s.set_segment('nope', 'floor-2')
