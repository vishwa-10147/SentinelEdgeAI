"""Notifications: approval requests and daily/weekly digests (Phase 10)."""
import time
from datetime import datetime

import pytest

from integrations import dispatcher, notify, sinks

SINKS = [{'type': 'slack', 'name': 'ops-slack', 'webhook_url': 'https://hooks.slack.test/x'},
         {'type': 'email', 'name': 'oncall', 'host': 'smtp.test', 'from': 'se@acme', 'to': ['oncall@acme']},
         {'type': 'syslog', 'name': 'siem', 'host': '10.0.0.5'}]


@pytest.fixture
def sent(monkeypatch):
    dispatcher.save_config({'sinks': SINKS})
    out = []

    class Resp:
        def raise_for_status(self):
            pass

    monkeypatch.setattr(sinks.requests, 'post', lambda url, **kw: out.append(('slack', url, kw['json'])) or Resp())
    monkeypatch.setattr(sinks.EmailSink, '_smtp', lambda self, msg: out.append(('email', msg['Subject'], msg.get_content())))
    monkeypatch.setattr(notify, 'enqueue', lambda names, s, t, link=None: notify.send(names, s, t, link))
    return out


def test_validation(sent):
    with pytest.raises(ValueError, match='no integration named'):
        notify.save_config({'approvals': {'enabled': True, 'sinks': ['nope']}})
    with pytest.raises(ValueError, match='syslog destination'):
        notify.save_config({'approvals': {'enabled': True, 'sinks': ['siem']}})
    with pytest.raises(ValueError, match='https'):
        notify.save_config({'console_url': 'http://sentinel.local'})
    with pytest.raises(ValueError, match='at least one'):
        notify.save_config({'digest': {'enabled': True, 'sinks': []}})
    with pytest.raises(ValueError, match='weekly'):
        notify.save_config({'digest': {'frequency': 'hourly'}})


def test_approval_request_reaches_every_channel_with_a_link(sent, tmp_path):
    notify.save_config({'console_url': 'https://sentinel.acme', 'approvals': {'enabled': True,
                                                                               'sinks': ['ops-slack', 'oncall']}})
    from tests.test_enforcement import make_playbook
    pb = make_playbook(tmp_path, approval={'required_from_risk': 75, 'until': time.time() + 3600})
    r = pb.evaluate('198.51.100.31', 80, reason='brute_force')
    assert r['status'] == 'awaiting_approval'
    slack = [m for m in sent if m[0] == 'slack'][0][2]['text']
    assert slack.startswith('*Approval needed: block 198.51.100.31*') and 'risk 80' in slack
    assert f"https://sentinel.acme/#approve/{r['pending_id']}" in slack
    mail = [m for m in sent if m[0] == 'email'][0]
    assert mail[1] == '[SentinelEdgeAI] Approval needed: block 198.51.100.31' and 'brute_force' in mail[2]
    count = len(sent)
    assert pb.evaluate('198.51.100.31', 80)['status'] == 'awaiting_approval'      # same request: no repeat
    assert len(sent) == count


def test_approvals_disabled_sends_nothing(sent):
    notify.approval_requested(1, '10.0.0.1', 'block', 90, 'x')
    assert sent == []


def test_one_failing_channel_does_not_stop_the_others(sent, monkeypatch):
    def boom(self, msg):
        raise OSError('smtp down')
    monkeypatch.setattr(sinks.EmailSink, '_smtp', boom)
    result = notify.send(['oncall', 'ops-slack'], 'S', 'T')
    assert result['ops-slack'] == 'ok' and 'smtp down' in result['oncall']


def test_digest_content():
    now = time.time()
    incidents = [
        {'id': 'a', 'title': 'Brute force from 10.0.0.66', 'severity': 'critical', 'status': 'open',
         'alert_count': 12, 'first_seen': now - 3600, 'last_seen': now - 60},
        {'id': 'b', 'title': 'Port scan from 10.0.0.9', 'severity': 'low', 'status': 'acknowledged',
         'alert_count': 2, 'first_seen': now - 5 * 86400, 'last_seen': now - 4 * 86400},
        {'id': 'c', 'title': 'Old', 'severity': 'high', 'status': 'resolved', 'alert_count': 1,
         'first_seen': now - 9000, 'last_seen': now - 8000, 'updated_at': now - 100}]
    pending = [{'action': 'block', 'ip': '10.0.0.66', 'risk': 90, 'created': now - 600}]
    subject, text = notify.build_digest(86400, now, incidents, pending, [{'text': 'Beaconing raised 9 false alarms'}])
    assert subject == 'Daily digest: 2 open incidents, 1 awaiting approval'
    assert 'Open incidents: 2 (critical 1, high 0, medium 0, low 1)' in text
    assert 'New this day: 2    Resolved this day: 1' in text
    assert text.index('[critical] Brute force') < text.index('[low] Port scan')
    assert '- block 10.0.0.66 (risk 90)' in text and 'Beaconing raised 9' in text
    assert 'Nothing needs your attention.' in notify.build_digest(86400, now, [], [], [])[1]


def test_digest_schedule(sent, monkeypatch):
    monkeypatch.setattr(notify, 'build_digest', lambda period, now=None: ('Daily digest', 'body'))
    mon_9am = datetime(2026, 11, 2, 9, 0).timestamp()           # a Monday
    cfg = notify.save_config({'digest': {'enabled': True, 'hour': 8, 'sinks': ['ops-slack']}}, now=mon_9am)
    assert notify.send_digest(cfg, now=mon_9am + 60) is None                     # enabling is not a catch-up
    assert notify.send_digest(cfg, now=mon_9am + 86400) == {'ops-slack': 'ok'}   # Tuesday 9:00
    assert notify.send_digest(cfg, now=mon_9am + 86400 + 600) is None            # once per day
    weekly = {**cfg, 'digest': {**cfg['digest'], 'frequency': 'weekly', 'weekday': 0}}
    assert datetime.fromtimestamp(notify._last_due(weekly, mon_9am + 3 * 86400)).weekday() == 0
    assert notify.send_digest(weekly, now=mon_9am + 3 * 86400) is None          # Thursday: sent Tuesday
    assert notify.send_digest(weekly, now=mon_9am + 7 * 86400) == {'ops-slack': 'ok'}


def test_endpoints(sent):
    from fastapi.testclient import TestClient
    from dashboard import dashboard_api as api
    admin = {'username': 'adm', 'role': 'admin'}
    for dep in (api.require_admin, api.require_viewer):
        api.app.dependency_overrides[dep] = lambda: admin
    try:
        c = TestClient(api.app)
        r = c.put('/api/notifications', json={'console_url': 'https://sentinel.acme',
                                               'digest': {'enabled': True, 'sinks': ['oncall']}})
        assert r.status_code == 200 and r.json()['digest']['sinks'] == ['oncall']
        assert c.put('/api/notifications', json={'approvals': {'sinks': ['siem']}}).status_code == 400
        assert c.post('/api/notifications/test', json={'sink': 'ops-slack'}).json() == {'sink': 'ops-slack',
                                                                                      'result': 'ok'}
        assert c.post('/api/notifications/test', json={'sink': 'nope'}).status_code == 404
        assert c.get('/api/notifications/digest/preview').json()['subject'].startswith('Daily digest')
        assert c.post('/api/notifications/digest/send').json()['result'] == {'oncall': 'ok'}
        assert c.get('/api/notifications').json()['last_result'] == {'oncall': 'ok'}
    finally:
        api.app.dependency_overrides.clear()


def test_approval_page_endpoint(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from dashboard import dashboard_api as api
    from enforcement import playbook
    from tests.test_enforcement import make_playbook
    pb = make_playbook(tmp_path, approval={'required_from_risk': 75, 'until': time.time() + 3600})
    monkeypatch.setattr(playbook, 'get_playbook', lambda: pb)
    pid = pb.evaluate('198.51.100.50', 80, reason='beaconing')['pending_id']
    api.app.dependency_overrides[api.require_viewer] = lambda: {'username': 'v', 'role': 'viewer'}
    try:
        c = TestClient(api.app)
        body = c.get(f'/api/playbook/pending/{pid}').json()
        assert body['ip'] == '198.51.100.50' and body['status'] == 'pending' and body['reason'] == 'beaconing'
        assert c.get('/api/playbook/pending/99999').status_code == 404
    finally:
        api.app.dependency_overrides.clear()
