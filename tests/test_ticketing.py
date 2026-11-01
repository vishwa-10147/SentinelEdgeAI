"""Ticketing and SOAR: incidents -> Jira / ServiceNow / TheHive / webhook, and back (Phase 10)."""
import hashlib
import hmac
import json
import time

import pytest
import requests

from core import incidents
from integrations import dispatcher, ticketing

T0 = 1_780_000_000.0


class FakeResponse:
    def __init__(self, body=None, status=200):
        self._body, self.status_code = body or {}, status
        self.content = json.dumps(self._body).encode()
        self.headers = {'Content-Type': 'application/json'}

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f'{self.status_code}')


@pytest.fixture
def http(monkeypatch):
    calls = []
    replies = {}

    def request(method, url, **kw):
        calls.append((method, url, kw))
        for suffix, body in replies.items():
            if url.endswith(suffix):
                if isinstance(body, Exception):
                    raise body
                return FakeResponse(body)
        return FakeResponse({})

    monkeypatch.setattr(ticketing.requests, 'request', request)
    monkeypatch.setattr(ticketing.requests, 'post', lambda url, **kw: request('POST', url, **kw))
    return calls, replies


def make_incident(count=2, status='open', severity='high'):
    alerts = [{'timestamp': T0 + i, 'initiator_ip': '10.0.0.66', 'responder_ip': '10.0.0.10',
               'attack_type': 'brute_force', 'final_risk_score': 85 if severity == 'critical' else 60,
               'explanation': ['12 failed logins']} for i in range(count)]
    [inc] = incidents.build(alerts)
    inc['status'] = status
    return inc


JIRA = {'type': 'jira', 'name': 'jira', 'url': 'https://acme.atlassian.net', 'project': 'SEC', 'user': 'bot@acme',
        'api_token': 'tok', 'resolve_transition': 31, 'priorities': {'high': 'High'}}


def test_validation():
    with pytest.raises(ValueError, match='needs: project'):
        ticketing.build({'type': 'jira', 'name': 'j', 'url': 'https://x', 'user': 'u', 'api_token': 't'})
    with pytest.raises(ValueError, match='https'):
        ticketing.build({**JIRA, 'url': 'http://x'})
    with pytest.raises(ValueError, match='unique'):
        ticketing.validate([JIRA, JIRA])
    with pytest.raises(ValueError, match='unknown ticketing type'):
        ticketing.build({'type': 'zendesk', 'name': 'z', 'url': 'https://x'})


def test_jira_lifecycle_one_ticket_per_incident(http):
    calls, replies = http
    replies['/rest/api/2/issue'] = {'key': 'SEC-7', 'id': '10007'}
    target = ticketing.build(JIRA)
    inc = make_incident()
    assert ticketing.sync([inc], [target], now=T0) == {'created': 1, 'updated': 0, 'resolved': 0, 'failed': 0}
    method, url, kw = calls[0]
    fields = kw['json']['fields']
    assert url.endswith('/rest/api/2/issue') and fields['project'] == {'key': 'SEC'}
    assert fields['priority'] == {'name': 'High'} and 'What to do now' in fields['description']
    assert kw['auth'] == ('bot@acme', 'tok')
    assert ticketing.sync([inc], [target])['created'] == 0                 # no duplicate ticket
    more = make_incident(count=4)
    assert ticketing.sync([more], [target])['updated'] == 1
    assert calls[-1][1].endswith('/issue/SEC-7/comment') and '2 new alert(s)' in calls[-1][2]['json']['body']
    done = dict(more, status='resolved', note='password reset', updated_by='ana')
    assert ticketing.sync([done], [target])['resolved'] == 1
    assert calls[-2][1].endswith('/SEC-7/comment') and 'password reset' in calls[-2][2]['json']['body']
    assert calls[-1][1].endswith('/SEC-7/transitions') and calls[-1][2]['json'] == {'transition': {'id': '31'}}
    assert ticketing.sync([done], [target]) == {'created': 0, 'updated': 0, 'resolved': 0, 'failed': 0}
    assert ticketing.load_map()[inc['id']]['jira']['url'] == 'https://acme.atlassian.net/browse/SEC-7'


def test_minimum_severity_and_failures_retry(http):
    calls, replies = http
    target = ticketing.build({**JIRA, 'min_severity': 'critical'})
    assert ticketing.sync([make_incident()], [target])['created'] == 0 and calls == []
    replies['/rest/api/2/issue'] = requests.ConnectionError('down')
    crit = make_incident(severity='critical')
    assert ticketing.sync([crit], [target])['failed'] == 1 and ticketing.load_map() == {}
    replies['/rest/api/2/issue'] = {'key': 'SEC-8'}
    assert ticketing.sync([crit], [target])['created'] == 1


def test_servicenow_and_thehive_payloads(http):
    calls, replies = http
    replies['/api/now/table/incident'] = {'result': {'number': 'INC0010001', 'sys_id': 'abc'}}
    replies['/api/v1/alert'] = {'_id': '~123'}
    sn = ticketing.build({'type': 'servicenow', 'name': 'snow', 'url': 'https://acme.service-now.com',
                          'user': 'u', 'password': 'p', 'assignment_group': 'SecOps'})
    hive = ticketing.build({'type': 'thehive', 'name': 'hive', 'url': 'https://hive.local', 'api_token': 'k',
                            'organisation': 'acme'})
    inc = make_incident(severity='critical')
    assert ticketing.sync([inc], [sn, hive])['created'] == 2
    snow = next(kw['json'] for m, u, kw in calls if u.endswith('/api/now/table/incident'))
    assert snow['urgency'] == '1' and snow['correlation_id'] == inc['id'] and snow['assignment_group'] == 'SecOps'
    hv = next(kw for m, u, kw in calls if u.endswith('/api/v1/alert'))
    assert hv['json']['sourceRef'] == inc['id'] and hv['json']['severity'] == 4
    assert {'dataType': 'ip', 'data': '10.0.0.66'} in hv['json']['observables']
    assert hv['headers'] == {'Authorization': 'Bearer k', 'X-Organisation': 'acme'}
    ticketing.sync([dict(inc, status='resolved')], [sn, hive])
    resolve = next(kw['json'] for m, u, kw in calls if m == 'PATCH' and u.endswith('/incident/abc'))
    assert resolve['state'] == '6' and resolve['close_code']


def test_signed_webhook_events(http):
    calls, _ = http
    hook = ticketing.build({'type': 'webhook', 'name': 'soar', 'url': 'https://soar.local/hook', 'secret': 's3'})
    inc = make_incident()
    ticketing.sync([inc], [hook])
    _, _, kw = calls[0]
    body = json.loads(kw['data'])
    assert body['event'] == 'incident.opened' and body['incident']['id'] == inc['id']
    t, mac = dict(p.split('=') for p in kw['headers']['X-Sentinel-Signature'].split(',')).values()
    assert mac == hmac.new(b's3', t.encode() + b'.' + kw['data'], hashlib.sha256).hexdigest()


def test_inbound_status_changes_the_incident(http):
    _, replies = http
    replies['/rest/api/2/issue'] = {'key': 'SEC-9'}
    inc = make_incident()
    ticketing.sync([inc], [ticketing.build(JIRA)])
    assert ticketing.inbound('jira', {'ticket': 'SEC-9', 'status': 'Done', 'note': 'fixed'}) == (inc['id'], 'resolved')
    st = incidents.load_status()[inc['id']]
    assert st['status'] == 'resolved' and st['by'] == 'ticket:jira'
    assert ticketing.load_map()[inc['id']]['jira']['resolved'] is True          # not pushed back to Jira
    with pytest.raises(LookupError):
        ticketing.inbound('jira', {'ticket': 'SEC-404', 'status': 'done'})
    with pytest.raises(ValueError):
        ticketing.inbound('jira', {'ticket': 'SEC-9', 'status': 'exploded'})


def test_inbound_endpoint_authentication(http, monkeypatch):
    from fastapi.testclient import TestClient
    from dashboard import dashboard_api as api
    _, replies = http
    replies['/rest/api/2/issue'] = {'key': 'SEC-10'}
    dispatcher.save_config({'sinks': [], 'ticketing': [{**JIRA, 'inbound_token': 'in-tok',
                                                         'inbound_secret': 'in-sec'}]})
    inc = make_incident()
    ticketing.sync([inc], [ticketing.build(JIRA)])
    c = TestClient(api.app)
    body = json.dumps({'ticket': 'SEC-10', 'status': 'in progress'})
    assert c.post('/api/tickets/inbound/jira', content=body).status_code == 401
    assert c.post('/api/tickets/inbound/jira', content=body, headers={'Authorization': 'Bearer nope'}).status_code == 401
    assert c.post('/api/tickets/inbound/other', content=body, headers={'Authorization': 'Bearer in-tok'}).status_code == 401
    r = c.post('/api/tickets/inbound/jira', content=body, headers={'Authorization': 'Bearer in-tok'})
    assert r.status_code == 200 and r.json() == {'incident_id': inc['id'], 'status': 'acknowledged'}
    ts = str(int(time.time()))
    raw = json.dumps({'incident_id': inc['id'], 'status': 'resolved'}).encode()
    sig = hmac.new(b'in-sec', ts.encode() + b'.' + raw, hashlib.sha256).hexdigest()
    r = c.post('/api/tickets/inbound/jira', content=raw, headers={'X-Sentinel-Signature': f't={ts},v1={sig}'})
    assert r.status_code == 200 and incidents.load_status()[inc['id']]['status'] == 'resolved'
    # secrets are redacted and survive a round trip through the console
    api.app.dependency_overrides[api.require_admin] = lambda: {'username': 'adm', 'role': 'admin'}
    try:
        cfg = c.get('/api/integrations').json()['config']
        assert cfg['ticketing'][0]['api_token'] == '********'
        assert c.put('/api/integrations', json=cfg).status_code == 200
    finally:
        api.app.dependency_overrides.clear()
    assert dispatcher.load_config()['ticketing'][0]['api_token'] == 'tok'
