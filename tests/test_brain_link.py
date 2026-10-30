"""Sensor <-> brain over real mutual TLS (a uvicorn brain in a thread).

Covers the Phase 2 exit scenarios in simulation: a brain outage loses no
flow data, forged and replayed commands are rejected, several sensors at once.
"""
import copy
import socket
import threading
import time

import pytest
import requests
import uvicorn

import brain.manage as manage
from brain import keys
from brain import server as brain_server
from sensor import uplink
from sensor.buffer import DiskBuffer
from sensor.enforcer import Enforcer
from tests.test_link_units import FakeFirewall


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class Brain:
    def __init__(self, port):
        self.port = port
        self.server = None
        self.thread = None

    def start(self):
        config = uvicorn.Config(brain_server.app, host='127.0.0.1', port=self.port, log_level='error',
                                http=brain_server.PeerCertProtocol, **brain_server.ssl_options())
        self.server = uvicorn.Server(config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.thread.start()
        deadline = time.time() + 10
        while not self.server.started and time.time() < deadline:
            time.sleep(0.05)
        assert self.server.started

    def stop(self):
        self.server.should_exit = True
        self.thread.join(10)

    @property
    def url(self):
        return f'https://127.0.0.1:{self.port}'


@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTINEL_BRAIN_DIR', str(tmp_path / 'brain'))
    monkeypatch.setenv('SENTINEL_BRAIN_DB', str(tmp_path / 'brain.db'))
    monkeypatch.setenv('SENTINEL_SENSOR_DIR', str(tmp_path / 'sensor'))
    monkeypatch.setenv('SENTINEL_SENSOR_BUFFER', str(tmp_path / 'buffer.db'))
    keys.init(hostnames=['localhost'], ips=['127.0.0.1'])
    b = Brain(free_port())
    b.start()
    yield b
    if b.server and not b.server.should_exit:
        b.stop()
    manage.store().close()


def enrolled_uplink(brain, tmp_path, name='pi-test', sensor_dir=None, monkeypatch=None):
    code = manage.store().create_code()
    sensor_id = uplink.enroll(brain.url, code, keys.ca_fingerprint(), name)
    fw = FakeFirewall(whitelist={'192.0.2.1'})
    identity = uplink.load_identity()
    enf = Enforcer(sensor_id, open(uplink._path('brain.pub')).read(), uplink._path('enforcer_state.json'),
                   firewall_module=fw)
    link = uplink.Uplink(identity, buffer=DiskBuffer(), enforcer=enf, timeout=3)
    return link, fw


def records(n, start=0):
    return [{'src': '192.168.1.10', 'dst': '8.8.8.8', 'proto': 'UDP', 'ts': time.time(), 'dport': 53, 'n': i}
            for i in range(start, start + n)]


def test_enrolment_pins_the_ca_and_codes_are_single_use(env):
    code = manage.store().create_code()
    with pytest.raises(uplink.EnrolmentError, match='fingerprint'):
        uplink.enroll(env.url, code, '00' * 32)
    with pytest.raises(uplink.EnrolmentError, match='invalid'):
        uplink.enroll(env.url, 'AAAA-BBBB-CCCC', keys.ca_fingerprint())
    sensor_id = uplink.enroll(env.url, code, keys.ca_fingerprint(), 'pi-1')
    assert sensor_id.startswith('sensor-')
    assert manage.store().get_sensor(sensor_id)['name'] == 'pi-1'
    with pytest.raises(uplink.EnrolmentError, match='invalid, used or expired'):
        uplink.enroll(env.url, code, keys.ca_fingerprint(), 'pi-2')


def test_mtls_is_required_and_revocation_works(env, tmp_path):
    link, _ = enrolled_uplink(env, tmp_path)
    ca = uplink._path('ca.pem')
    # no client certificate
    r = requests.post(f'{env.url}/v1/flows', json={'records': []}, verify=ca, timeout=5)
    assert r.status_code == 401
    # with the certificate
    assert link.session.post(f'{env.url}/v1/flows', json={'records': []}, timeout=5).status_code == 200
    manage.store().revoke_sensor(link.identity['sensor_id'])
    assert link.session.post(f'{env.url}/v1/flows', json={'records': []}, timeout=5).status_code == 403


def test_flows_arrive_once_even_if_an_ack_is_lost(env, tmp_path):
    link, _ = enrolled_uplink(env, tmp_path)
    link.buffer.put(records(1200))
    while link.flush_once():
        pass
    sid = link.identity['sensor_id']
    assert manage.store().flow_count(sid) == 1200 and len(link.buffer) == 0
    # a batch re-sent after a lost acknowledgement is stored once
    link.buffer.put(records(10, 5000))
    batch = link.buffer.peek()
    link._post('/v1/flows', {'records': [[rid, rec] for rid, rec in batch]})   # brain stores, sensor "loses" the ack
    link.flush_once()                                                        # sensor re-sends
    assert manage.store().flow_count(sid) == 1210 and len(link.buffer) == 0


def test_brain_outage_loses_no_flows(env, tmp_path):
    link, _ = enrolled_uplink(env, tmp_path)
    sid = link.identity['sensor_id']
    link.buffer.put(records(100))
    link.flush_once()
    assert link.connected
    env.stop()                                   # "unplug the Jetson"
    for i in range(5):                           # the engine keeps producing flows
        link.buffer.put(records(300, 1000 + i * 300))
        assert link.flush_once() == 0
    assert link.connected is False and len(link.buffer) == 1500
    env.start()                                  # back online
    while link.flush_once():
        pass
    assert link.connected and len(link.buffer) == 0
    assert manage.store().flow_count(sid) == 1600
    got = sorted(f['n'] for f in manage.store().recent_flows(limit=5000, sensor_id=sid))
    assert got == list(range(100)) + list(range(1000, 2500))


def test_signed_commands_end_to_end(env, tmp_path):
    link, fw = enrolled_uplink(env, tmp_path)
    sid = link.identity['sensor_id']
    manage.issue_command(sid, 'block', '198.51.100.7', ttl=600, reason='portscan')
    manage.issue_command(sid, 'block', '192.0.2.1', reason='would hit the gateway')
    results = link.poll_commands()
    assert [r['status'] for r in results] == ['applied', 'refused']
    assert fw.calls == [('block', '198.51.100.7', 'brain:portscan')]
    cmds = {c['seq']: c for c in manage.store().list_commands(sid)}
    assert cmds[1]['status'] == 'applied' and cmds[2]['status'] == 'refused'
    assert link.poll_commands() == []            # nothing pending any more

    # a replayed or forged command delivered straight to the enforcer is refused
    env1 = manage.store()._all('SELECT envelope FROM commands WHERE sensor_id = ? AND seq = 1', (sid,))[0]
    import json
    replay = json.loads(env1['envelope'])
    assert link.enforcer.apply(replay)['status'] == 'rejected'
    forged = copy.deepcopy(replay)
    forged['payload']['seq'] = 99
    assert 'forged' in link.enforcer.apply(forged)['detail']
    assert len(fw.calls) == 1


def test_three_sensors_at_once(env, tmp_path, monkeypatch):
    links = []
    for i in range(3):
        monkeypatch.setenv('SENTINEL_SENSOR_DIR', str(tmp_path / f'sensor{i}'))
        monkeypatch.setenv('SENTINEL_SENSOR_BUFFER', str(tmp_path / f'buffer{i}.db'))
        link, _ = enrolled_uplink(env, tmp_path, name=f'pi-{i}')
        link.buffer.put(records(3000))
        links.append(link)
    start = time.time()

    def drain(link):
        while link.flush_once():
            pass

    threads = [threading.Thread(target=drain, args=(l,)) for l in links]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    elapsed = time.time() - start
    for link in links:
        assert manage.store().flow_count(link.identity['sensor_id']) == 3000
    assert manage.store().flow_count() == 9000
    print(f'3 sensors x 3000 flows in {elapsed:.1f}s ({9000 / elapsed:.0f} flows/s on this Pi)')
