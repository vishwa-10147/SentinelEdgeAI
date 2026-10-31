"""Fleet manager: staged rollouts, templates and a site <-> fleet server round trip over real mutual TLS (Phase 7)."""
import json
import os
import socket
import threading
import time

import pytest
import requests
import uvicorn

import core.firewall as firewall
from fleet import agent, keys, manage, rollout
from fleet import server as fleet_server
from fleet.store import FleetStore

NOW = 1_800_000_000.0


# ---------- rollout logic ----------

def group(target='2.4.0', started=NOW, stages=None, paused=None):
    return {'name': 'default', 'target_version': target, 'started': started, 'paused': paused,
            'stages': stages or rollout.DEFAULT_STAGES}


def test_stages_are_validated():
    assert rollout.validate_stages(None) == rollout.DEFAULT_STAGES
    with pytest.raises(ValueError, match='last stage'):
        rollout.validate_stages([{'percent': 50, 'hours': 0}])
    with pytest.raises(ValueError, match='increasing'):
        rollout.validate_stages([{'percent': 50, 'hours': 10}, {'percent': 20, 'hours': 20}, {'percent': 100, 'hours': 30}])


def test_canaries_first_then_everyone():
    sites = [f'site-{i:04x}' for i in range(400)]
    g = group()
    first = [s for s in sites if rollout.desired_version(g, s, '2.3.1', NOW)]
    day1 = [s for s in sites if rollout.desired_version(g, s, '2.3.1', NOW + 25 * 3600)]
    day2 = [s for s in sites if rollout.desired_version(g, s, '2.3.1', NOW + 49 * 3600)]
    assert 0 < len(first) < len(day1) < len(day2) == 400
    assert set(first) <= set(day1)                              # canaries are always the same sites
    assert 20 <= len(first) <= 70 and 150 <= len(day1) <= 250


def test_paused_rollouts_hold_but_never_move_sites_back():
    g = group(paused='update to 2.4.0 failed on pi-7')
    assert rollout.desired_version(g, 'site-1', '2.3.1', NOW + 100 * 3600) is None
    assert rollout.desired_version(g, 'site-1', '2.4.0', NOW) == '2.4.0'
    assert rollout.desired_version(group(target=None), 'site-1', '2.3.1', NOW) is None


def test_failed_update_is_recognised():
    assert rollout.failed_update({'update': {'version': '2.4.0', 'ok': False}}, '2.4.0')
    assert not rollout.failed_update({'update': {'version': '2.4.0', 'ok': True}}, '2.4.0')
    assert not rollout.failed_update({'update': {'version': '2.3.9', 'ok': False}}, '2.4.0')


def test_templates_are_validated_before_they_are_stored():
    v = manage.put_template('ot-sites', preset='ot')
    assert FleetStore().get_template('ot-sites')['version'] == v
    with pytest.raises(ValueError):
        manage.put_template('broken', 'version: 1\nresponse_mode: nuke\n')
    with pytest.raises(ValueError, match='unknown template'):
        manage.put_group('plants', template='missing')
    g = manage.put_group('plants', template='ot-sites', target_version='2.4.0')
    assert g['template'] == 'ot-sites' and g['started']


def test_enrolment_codes_are_single_use_and_group_bound():
    st = FleetStore()
    manage.put_group('branch')
    code = st.create_code('branch')
    assert st.redeem_code(code, 'site-a') == 'branch'
    assert st.redeem_code(code, 'site-b') is None
    with pytest.raises(ValueError, match='unknown group'):
        st.create_code('nope')


# ---------- live mutual TLS ----------

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


@pytest.fixture
def live(tmp_path, monkeypatch):
    monkeypatch.setattr(firewall, 'ROOT', str(tmp_path))
    monkeypatch.setattr(firewall, 'FIREWALL_DRY_RUN', True)
    monkeypatch.setenv('SENTINEL_RESPONSE_POLICY', str(tmp_path / 'policy.json'))
    monkeypatch.setattr(fleet_server, '_store', None)
    keys.init(hostnames=['localhost'], ips=['127.0.0.1'])
    port = free_port()
    config = uvicorn.Config(fleet_server.app, host='127.0.0.1', port=port, log_level='error',
                            http=fleet_server.PeerCertProtocol, **fleet_server.ssl_options())
    srv = uvicorn.Server(config)
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    deadline = time.time() + 10
    while not srv.started and time.time() < deadline:
        time.sleep(0.05)
    assert srv.started
    yield f'https://127.0.0.1:{port}'
    srv.should_exit = True
    t.join(10)


def test_enrolment_pins_the_fleet_ca(live):
    code = manage.enrolment_code()['code']
    with pytest.raises(agent.AgentError, match='fingerprint does not match'):
        agent.enroll(live, code, '00' * 32)
    site_id = agent.enroll(live, code, keys.ca_fingerprint(), name='pi-branch-1')
    assert site_id.startswith('site-') and agent.identity()['group'] == 'default'
    with pytest.raises(agent.AgentError, match='refused'):
        agent.enroll(live, code, keys.ca_fingerprint())                 # single use


def test_report_applies_the_template_and_the_rollout(live, monkeypatch):
    manage.put_template('office', preset='office')
    manage.put_group('default', template='office', target_version='9.0.0', stages=[{'percent': 100, 'hours': 0}])
    site_id = agent.enroll(live, manage.enrolment_code()['code'], keys.ca_fingerprint(), name='pi-1')
    state = agent.report_once()
    assert state['last_error'] is None and state['template_status'] == 'applied'
    assert state['desired_version'] == '9.0.0'
    with open(os.path.join(agent.agent_dir(), 'desired_version')) as f:
        assert f.read().strip() == '9.0.0'
    from enforcement import policy
    assert policy.current()['response_mode'] == 'auto_block'             # the office preset is in force
    assert agent.report_once()['template_status'] == 'unchanged'
    site = FleetStore().get_site(site_id)
    assert site['report']['hostname'] == socket.gethostname() and site['version'] == agent.version()
    assert set(site['report']) >= {'alerts_24h', 'trust', 'restrictions', 'segmentation', 'system'}


def test_a_failed_update_pauses_the_rollout(live):
    manage.put_group('default', target_version='9.0.0', stages=[{'percent': 100, 'hours': 0}])
    agent.enroll(live, manage.enrolment_code()['code'], keys.ca_fingerprint(), name='pi-canary')
    with open(os.path.join(agent.agent_dir(), 'update_result.json'), 'w') as f:
        json.dump({'version': '9.0.0', 'ok': False, 'message': 'health check failed, rolled back'}, f)
    state = agent.report_once()
    assert state['desired_version'] is None
    assert not os.path.exists(os.path.join(agent.agent_dir(), 'desired_version'))
    assert 'failed on pi-canary' in FleetStore().get_group('default')['paused']
    manage.set_rollout('default', 'resume')
    assert FleetStore().get_group('default')['paused'] is None


def test_revoked_sites_and_strangers_are_refused(live):
    site_id = agent.enroll(live, manage.enrolment_code()['code'], keys.ca_fingerprint())
    assert requests.post(f'{live}/v1/report', json={}, verify=os.path.join(agent.agent_dir(), 'ca.pem'),
                         timeout=5).status_code == 401
    FleetStore().revoke_site(site_id)
    state = agent.report_once()
    assert '403' in state['last_error']


def test_unenrolled_site_cannot_report():
    with pytest.raises(agent.AgentError, match='not enrolled'):
        agent.report_once()
