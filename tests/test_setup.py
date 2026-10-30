import json
import os
from collections import namedtuple

import pytest
from fastapi.testclient import TestClient

import core.audit as audit
import core.auth as auth
import core.setup as setup
import dashboard.auth_routes as auth_routes
import dashboard.dashboard_api as api

PASSWORD = 'correct horse battery'
Stat = namedtuple('Stat', 'isup speed')
Addr = namedtuple('Addr', 'family address')


@pytest.fixture(autouse=True)
def env(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTINEL_AUTH_DB', str(tmp_path / 'auth.db'))
    monkeypatch.delenv('DASHBOARD_API_KEY', raising=False)
    monkeypatch.delenv('CAPTURE_IFACE', raising=False)
    monkeypatch.setenv('SENTINEL_MFA_ROLES', '')
    monkeypatch.setattr(auth_routes, 'login_throttle', auth.LoginThrottle())
    monkeypatch.setattr(setup.psutil, 'net_if_stats', lambda: {
        'lo': Stat(True, 0), 'eth0': Stat(True, 1000), 'eth1': Stat(False, 0),
        'docker0': Stat(False, 0), 'br-1a22b5c356a5': Stat(True, 10000), 'veth580a208': Stat(True, 10000),
    })
    monkeypatch.setattr(setup.psutil, 'net_if_addrs', lambda: {
        'eth0': [Addr(2, '192.168.50.4'), Addr(10, 'fe80::1')], 'lo': [Addr(2, '127.0.0.1')],
    })
    # keep the firewall policy file out of the repository
    policy = {}
    monkeypatch.setattr(api.firewall, 'update_policy', lambda update: policy.update(update) or dict(policy))
    yield policy
    auth.get_store().close()


def test_defaults_until_completed():
    s = setup.load()
    assert s['completed'] is False and s['network_role'] == 'standalone' and s['capture_interface'] == 'auto'
    assert setup.capture_interface() is None


def test_virtual_interfaces_are_hidden():
    names = [i['name'] for i in setup.list_interfaces()]
    assert names == ['eth0', 'eth1']
    eth0 = setup.list_interfaces()[0]
    assert eth0 == {'name': 'eth0', 'up': True, 'speed_mbps': 1000, 'addresses': ['192.168.50.4']}


@pytest.mark.parametrize('values, message', [
    ({'network_role': 'router'}, 'network_role'),
    ({'placement': 'tap'}, 'placement'),
    ({'capture_interface': 'docker0'}, 'unknown capture interface'),
    ({'response_mode': 'nuke'}, 'response_mode'),
])
def test_validation(values, message):
    with pytest.raises(ValueError, match=message):
        setup.validate(values)


def test_save_and_capture_interface(monkeypatch):
    saved = setup.save({'capture_interface': 'eth0', 'placement': 'inline'}, by='root')
    assert saved['completed'] and saved['completed_by'] == 'root'
    assert setup.load()['placement'] == 'inline'
    assert setup.capture_interface() == 'eth0'
    assert oct(os.stat(setup.setup_file()).st_mode & 0o777) == '0o640'
    monkeypatch.setenv('CAPTURE_IFACE', 'eth1')
    assert setup.capture_interface() == 'eth1'


def test_corrupt_file_falls_back_to_defaults():
    with open(setup.setup_file(), 'w') as f:
        f.write('{not json')
    assert setup.load()['completed'] is False


def client():
    return TestClient(api.app, client=('203.0.113.40', 50000))


def login(c, username='root'):
    r = c.post('/api/auth/login', json={'username': username, 'password': PASSWORD})
    assert r.status_code == 200, r.text
    return r.json(), {'Authorization': f"Bearer {r.json()['access_token']}"}


def test_admin_is_sent_to_setup_until_done(env):
    store = auth.get_store()
    store.create_user('root', PASSWORD, 'admin')
    store.create_user('viewer1', PASSWORD, 'viewer')
    c = client()
    body, h = login(c)
    assert body['user']['setup_required'] is True
    assert c.get('/api/auth/me', headers=h).json()['setup_required'] is True
    # non-admins are never asked
    vbody, vh = login(c, 'viewer1')
    assert vbody['user']['setup_required'] is False
    assert c.get('/api/setup', headers=vh).status_code == 403

    info = c.get('/api/setup', headers=h).json()
    assert [i['name'] for i in info['interfaces']] == ['eth0', 'eth1']
    assert [r['value'] for r in info['options']['roles'] if r['available']] == ['standalone', 'sensor', 'brain']
    assert info['enforcement'] in ('dry_run', 'enforcing')

    r = c.post('/api/setup', headers=h, json={'network_role': 'standalone', 'placement': 'passive',
                                              'capture_interface': 'eth0', 'response_mode': 'alert'})
    assert r.status_code == 200, r.text
    assert env == {'response_mode': 'alert'}  # applied to the firewall policy
    assert c.get('/api/auth/me', headers=h).json()['setup_required'] is False
    entry = audit.get_log().entries(action='setup')[0]
    assert entry['actor'] == 'root' and entry['details']['first_run'] is True
    assert entry['details']['capture_interface'] == 'eth0'


def test_invalid_setup_is_rejected_and_audited(env):
    auth.get_store().create_user('root', PASSWORD, 'admin')
    c = client()
    _, h = login(c)
    r = c.post('/api/setup', headers=h, json={'network_role': 'router'})
    assert r.status_code == 400 and 'network_role' in r.json()['detail']
    assert env == {}
    assert setup.is_complete() is False
    assert audit.get_log().entries(action='setup')[0]['outcome'] == 'rejected'


def test_brain_role_creates_the_service_marker():
    setup.save({'network_role': 'brain'}, by='root')
    assert os.path.exists(setup.brain_marker())
    setup.save({'network_role': 'standalone'}, by='root')
    assert not os.path.exists(setup.brain_marker())
