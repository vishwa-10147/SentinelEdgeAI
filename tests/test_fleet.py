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


# ---------- remote actions and fleet-wide alert search ----------

def _alert(storage, ts, src, kind='POSSIBLE_PORT_SCAN', score=70):
    storage.create_tables()
    storage.insert_alert(int(ts), src, '10.0.0.9', 40000, 443, 'TCP', score, 0.8,
                         json.dumps({'attack_type': kind, 'mitre_technique_id': 'T1046',
                                     'mitre_technique_name': 'Network Service Discovery', 'severity': 'HIGH'}))


def test_remote_actions_are_validated_and_must_expire():
    st = FleetStore()
    st.add_site('site-a', 'pi-a', 'fp', 'default')
    with pytest.raises(ValueError, match='unknown or revoked'):
        manage.queue_action('site-x', 'block', '10.0.0.5')
    with pytest.raises(ValueError, match='action must be'):
        manage.queue_action('site-a', 'wipe', '10.0.0.5')
    with pytest.raises(ValueError, match='invalid ip'):
        manage.queue_action('site-a', 'block', 'not-an-ip')
    with pytest.raises(ValueError, match='must expire'):
        manage.queue_action('site-a', 'block', '10.0.0.5', ttl=0)
    with pytest.raises(ValueError, match='release needs'):
        manage.queue_action('site-a', 'release', '10.0.0.5')
    a = manage.queue_action('site-a', 'release', '10.0.0.5', release_kind='contain')
    assert a['kind'] == 'release:contain' and a['ttl'] is None
    b = manage.queue_action('site-a', 'block', '10.0.0.6', ttl=600)
    assert manage.cancel_action(b['id'])['cancelled'] == b['id']
    with pytest.raises(ValueError, match='only queued'):
        manage.cancel_action(b['id'])
    assert [x['id'] for x in st.pending_actions('site-a')] == [a['id']]
    assert st.pending_actions('site-a', now=time.time() + 7200) == []          # undelivered actions expire
    assert st.get_action(a['id'])['status'] == 'expired'


def test_remote_action_runs_once_through_the_sites_own_checks(live, monkeypatch):
    site_id = agent.enroll(live, manage.enrolment_code()['code'], keys.ca_fingerprint(), name='pi-branch')
    from enforcement import protected
    monkeypatch.setattr(protected, 'why_protected', lambda ip: 'gateway' if ip == '10.0.0.1' else None)
    ok = manage.queue_action(site_id, 'block', '10.0.0.66', ttl=900, reason='seen at HQ', by='alice')
    refused = manage.queue_action(site_id, 'block', '10.0.0.1', ttl=900, by='alice')
    agent.report_once()
    rules = [r for r in firewall.list_rules() if r.get('blocked')]
    assert [r['ip'] for r in rules] == ['10.0.0.66'] and 'by alice' in rules[0]['reason']
    st = FleetStore()
    assert st.get_action(ok['id'])['status'] == 'done'
    failed = st.get_action(refused['id'])
    assert failed['status'] == 'failed' and 'protected host' in failed['result']['error']
    agent.report_once()                                          # nothing runs twice
    assert len([r for r in firewall.list_rules() if r.get('blocked')]) == 1
    manage.queue_action(site_id, 'unblock', '10.0.0.66')
    agent.report_once()
    assert not [r for r in firewall.list_rules() if r.get('blocked')]


def test_a_site_can_refuse_remote_actions(live, monkeypatch):
    site_id = agent.enroll(live, manage.enrolment_code()['code'], keys.ca_fingerprint())
    monkeypatch.setenv('SENTINEL_FLEET_REMOTE_ACTIONS', 'off')
    a = manage.queue_action(site_id, 'quarantine', '10.0.0.70', ttl=600)
    agent.report_once()
    assert not firewall.list_restrictions()
    assert 'turned off' in FleetStore().get_action(a['id'])['result']['error']


def test_alerts_are_shared_once_and_searchable_across_sites(live, monkeypatch, tmp_path):
    from core.storage import get_storage
    monkeypatch.chdir(tmp_path)
    os.makedirs('data', exist_ok=True)
    storage = get_storage('data/sentinel.db')
    storage.connect()
    now = time.time()
    _alert(storage, now - 300, '10.0.0.20')
    _alert(storage, now - 200, '10.0.0.21', kind='DNS_TUNNELING', score=90)
    _alert(storage, now - 3 * 86400, '10.0.0.22')                  # older than a day: not shared on first report
    site_id = agent.enroll(live, manage.enrolment_code()['code'], keys.ca_fingerprint(), name='pi-north')
    agent.report_once()
    agent.report_once()                                          # the cursor stops a resend
    res = manage.search_alerts()
    assert res['count'] == 2 and {a['site_name'] for a in res['alerts']} == {'pi-north'}
    assert manage.search_alerts(q='tunnel')['alerts'][0]['src_ip'] == '10.0.0.21'
    assert manage.search_alerts(ip='10.0.0.20')['count'] == 1
    assert manage.search_alerts(min_score=80)['count'] == 1
    assert manage.search_alerts(q='T1046')['count'] == 2
    assert manage.search_alerts(q='100%_')['count'] == 0          # LIKE wildcards are literal
    assert manage.search_alerts(site=site_id, since=int(now - 250))['count'] == 1
    with pytest.raises(ValueError, match='invalid ip'):
        manage.search_alerts(ip='nope')
    _alert(storage, time.time(), '10.0.0.23')
    monkeypatch.setenv('SENTINEL_FLEET_SHARE_ALERTS', '0')
    agent.report_once()
    assert manage.search_alerts()['count'] == 2                  # opted out: stays on the site
    assert 'alerts' not in FleetStore().get_site(site_id)['report']


def test_store_rejects_malformed_alert_summaries():
    st = FleetStore()
    st.add_site('site-a', 'pi-a', 'fp', 'default')
    now = int(time.time())
    n = st.add_alerts('site-a', [{'ts': now, 'score': 'x'}, 'junk', {'ts': 'soon'}, {'ts': now + 86400},
                                 {'ts': now, 'type': 'A' * 500, 'score': 50}])
    assert n == 1 and len(st.search_alerts()[0]['type']) == 64
