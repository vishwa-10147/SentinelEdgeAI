"""Incidents: grouping, timeline, checklist and status (Phase 10)."""
import json

from core import incidents

T0 = 1_780_000_000.0
ATT, HOST_A, HOST_B, OTHER = '10.0.0.66', '10.0.0.10', '10.0.0.11', '10.0.0.99'


def alert(src, dst, kind, ts, risk=70, **kw):
    a = {'timestamp': ts, 'initiator_ip': src, 'responder_ip': dst, 'attack_type': kind,
         'final_risk_score': risk, 'mitre_technique_id': 'T1046', 'explanation': [f'{kind} evidence']}
    a.update(kw)
    return a


def test_normalize_db_rows_and_json_entries():
    row = {'timestamp': T0, 'src_ip': ATT, 'dst_ip': HOST_A, 'score': 80, 'details':
           str({'attack_type': 'port_scan', 'mitre_technique_id': 'T1046', 'explanation': ['20 ports']})}
    n = incidents.normalize(row)
    assert n['kind'] == 'port_scan' and n['risk'] == 80 and n['evidence'] == ['20 ports']
    j = incidents.normalize(alert(ATT, HOST_A, 'brute_force', '2026-05-08 18:31:43.431154'))
    assert j['ts'] > 0 and j['kind'] == 'brute_force'
    assert incidents.normalize({'details': "__import__('os').system('x')"}) is None     # never evaluated
    assert incidents.normalize({'src_ip': ATT}) is None


def test_grouping_by_shared_internal_device_and_time():
    alerts = [alert(ATT, HOST_A, 'port_scan', T0), alert(ATT, HOST_A, 'brute_force', T0 + 600),
              alert(HOST_A, HOST_B, 'admin_share', T0 + 1200),            # A, now compromised, moves on
              alert(OTHER, '8.8.8.8', 'beaconing', T0 + 100),               # unrelated device
              alert(ATT, HOST_A, 'port_scan', T0 + 3 * 86400)]             # days later: new incident
    got = incidents.build(alerts)
    assert len(got) == 3
    chain = next(i for i in got if i['alert_count'] == 3)
    assert chain['source'] == ATT and set(chain['sources']) == {ATT, HOST_A}
    assert chain['kinds'] == ['port_scan', 'brute_force', 'admin_share'] and HOST_B in chain['targets']
    assert chain['title'].startswith('Port scan, brute force and more from 10.0.0.66')


def test_external_destinations_do_not_link_incidents():
    got = incidents.build([alert('10.0.0.1', '1.1.1.1', 'beaconing', T0),
                           alert('10.0.0.2', '1.1.1.1', 'beaconing', T0 + 10)])
    assert len(got) == 2


def test_merge_when_two_incidents_meet():
    got = incidents.build([alert('10.0.0.1', '9.9.9.9', 'beaconing', T0),
                           alert('10.0.0.2', '9.9.9.9', 'beaconing', T0 + 10),
                           alert('10.0.0.1', '10.0.0.2', 'lateral_fanout', T0 + 20)])
    assert len(got) == 1 and got[0]['alert_count'] == 3


def test_timeline_responses_and_checklist():
    actions = [{'action': 'block', 'ip': ATT, 'ttl': 3600, 'reason': 'playbook', 'ts': T0 + 30},
               {'action': 'block', 'ip': OTHER, 'ts': T0 + 30}]
    [inc] = incidents.build([alert(ATT, HOST_A, 'brute_force', T0)], actions)
    assert [e['type'] for e in inc['timeline']] == ['alert', 'response'] and inc['responses'] == 1
    assert inc['checklist'][0].startswith('The appliance already applied "block" to 10.0.0.66')
    assert any('login logs' in s for s in inc['checklist']) and inc['checklist'][-1] == incidents.CLOSING
    [ot] = incidents.build([alert('10.1.0.5', '10.1.0.9', 'ot_device_stop', T0, risk=85)])
    assert ot['severity'] == 'critical' and any('controller' in s for s in ot['checklist'])
    [other] = incidents.build([alert(ATT, HOST_A, 'something_new', T0, risk=20)])
    assert other['severity'] == 'low' and 'false positive' in other['checklist'][0]


def test_status_and_reopen_on_new_activity():
    [inc] = incidents.build([alert(ATT, HOST_A, 'port_scan', T0)])
    incidents.set_status(inc['id'], 'resolved', 'IT scanner', by='ana', now=T0 + 100)
    status = incidents.load_status()
    [same] = incidents.build([alert(ATT, HOST_A, 'port_scan', T0)], status=status)
    assert same['status'] == 'resolved' and same['note'] == 'IT scanner' and same['updated_by'] == 'ana'
    [again] = incidents.build([alert(ATT, HOST_A, 'port_scan', T0), alert(ATT, HOST_A, 'port_scan', T0 + 200)],
                              status=status)
    assert again['id'] == inc['id'] and again['status'] == 'open'
    try:
        incidents.set_status(inc['id'], 'deleted')
        raise AssertionError('accepted an unknown status')
    except ValueError:
        pass


def test_incident_endpoints(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from dashboard import dashboard_api as api
    alerts = [alert(ATT, HOST_A, 'port_scan', T0), alert(ATT, HOST_A, 'brute_force', T0 + 60)]
    monkeypatch.setattr(incidents, 'load_alerts', lambda limit=5000: alerts)
    monkeypatch.setattr(incidents, 'load_actions', lambda path=None: [])
    api.app.dependency_overrides[api.require_viewer] = lambda: {'username': 'v', 'role': 'viewer'}
    api.app.dependency_overrides[api.require_analyst] = lambda: {'username': 'ana', 'role': 'analyst'}
    try:
        c = TestClient(api.app)
        body = c.get('/api/incidents').json()
        assert body['counts']['open'] == 1 and 'timeline' not in body['incidents'][0]
        iid = body['incidents'][0]['id']
        detail = c.get(f'/api/incidents/{iid}').json()
        assert len(detail['timeline']) == 2 and detail['checklist']
        r = c.post(f'/api/incidents/{iid}/status', json={'status': 'acknowledged', 'note': 'looking'})
        assert r.status_code == 200 and r.json()['by'] == 'ana'
        assert c.get('/api/incidents?status=acknowledged').json()['counts']['acknowledged'] == 1
        assert c.post(f'/api/incidents/{iid}/status', json={'status': 'bogus'}).status_code == 400
        assert c.get('/api/incidents/nope').status_code == 404
    finally:
        api.app.dependency_overrides.clear()
