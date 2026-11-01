"""Guided tuning: suggestions from false-positive labels and scoped, expiring rules (Phase 10)."""
import pytest

from detection import guided_tuning as gt
from detection.detectors import Finding
from detection.pipeline import DetectionPipeline

NOW = 1_780_000_000.0
DAY = 86400


def label(src, kind='beaconing', lbl='fp', dst='93.184.216.34', ago=DAY):
    return {'ts': NOW - ago, 'kind': kind, 'src': src, 'label': lbl, 'alert': {'responder_ip': dst}}


def finding(src, kind='beaconing', target='93.184.216.34', sev=70, prob=0.8, **details):
    return Finding(kind, src, sev, prob, 'T1071', 'evidence', {'target': target, **details}, ts=NOW)


def test_subnet_suggestion_when_several_hosts_share_the_noise():
    labels = [label(f'10.0.5.{i % 4 + 10}') for i in range(12)]
    [s] = [x for x in gt.suggest(labels, now=NOW) if 'src' in x['scope']]
    assert s['scope'] == {'src': '10.0.5.0/24'} and s['false_positives'] == 12 and s['sources'] == 4
    assert 'Beaconing raised 12 false alarms from 10.0.5.0/24 (4 devices) in the last 14 days' in s['text']
    assert s['action'] == 'downgrade' and s['can_suppress']


def test_single_host_gets_a_host_rule_not_a_subnet():
    got = gt.suggest([label('10.0.5.20') for _ in range(6)], now=NOW)
    assert [s['scope'] for s in got] == [{'src': '10.0.5.20'}]


def test_destination_suggestion_and_no_suggestion_after_a_true_positive():
    labels = [label(f'10.0.{i}.5', dst='10.0.0.53', kind='dns_tunnel') for i in range(6)]
    assert {'dst': '10.0.0.53'} in [s['scope'] for s in gt.suggest(labels, now=NOW)]
    labels.append(label('10.0.3.5', dst='10.0.0.53', kind='dns_tunnel', lbl='tp'))
    assert {'dst': '10.0.0.53'} not in [s['scope'] for s in gt.suggest(labels, now=NOW)]


def test_thresholds_window_dismissal_and_existing_rules():
    assert gt.suggest([label('10.0.5.20') for _ in range(4)], now=NOW) == []          # below min_fp
    assert gt.suggest([label('10.0.5.20', ago=20 * DAY) for _ in range(9)], now=NOW) == []   # too old
    labels = [label('10.0.5.20') for _ in range(6)]
    [s] = gt.suggest(labels, now=NOW)
    assert gt.suggest(labels, dismissed={s['id']: NOW + 1}, now=NOW) == []
    rule = {'kind': 'beaconing', 'scope': {'src': '10.0.0.0/16'}, 'expires': NOW + DAY}
    assert gt.suggest(labels, rules=[rule], now=NOW) == []                              # already covered
    assert gt.suggest(labels, rules=[{**rule, 'expires': NOW - 1}], now=NOW) != []      # expired rule


def test_rule_validation():
    with pytest.raises(ValueError, match='too wide'):
        gt.add_rule('beaconing', {'src': '10.0.0.0/8'}, now=NOW)
    with pytest.raises(ValueError, match='src or dst'):
        gt.add_rule('beaconing', {'dport': 443}, now=NOW)
    with pytest.raises(ValueError, match='never suppressed'):
        gt.add_rule('dcsync', {'src': '10.0.0.9'}, 'suppress', now=NOW)
    with pytest.raises(ValueError, match='1 to 180'):
        gt.add_rule('beaconing', {'src': '10.0.0.9'}, days=365, now=NOW)
    assert gt.add_rule('dcsync', {'src': '10.0.0.9'}, 'downgrade', now=NOW)['action'] == 'downgrade'


def test_ruleset_downgrades_suppresses_and_expires():
    gt.add_rule('beaconing', {'src': '10.0.5.0/24'}, 'downgrade', days=1, note='printers', now=NOW)
    gt.add_rule('port_scan', {'src': '10.0.9.9', 'dport': 161}, 'suppress', now=NOW)
    rules = gt.RuleSet(clock=lambda: NOW)
    out = rules.apply([finding('10.0.5.20'), finding('10.0.6.20'),
                       finding('10.0.9.9', kind='port_scan', dport=161), finding('10.0.9.9', kind='port_scan', dport=22)],
                      now=NOW)
    assert [(f.src, f.kind) for f in out] == [('10.0.5.20', 'beaconing'), ('10.0.6.20', 'beaconing'),
                                               ('10.0.9.9', 'port_scan')]
    assert out[0].severity == 45 and out[0].probability == 0.4 and out[0].details['tuned']['note'] == 'printers'
    assert out[1].severity == 70 and 'tuned' not in out[1].details
    later = gt.RuleSet(clock=lambda: NOW + 2 * DAY)
    assert later.apply([finding('10.0.5.20')], now=NOW + 2 * DAY)[0].severity == 70


def test_pipeline_applies_rules_and_downgrade_blocks_automatic_response():
    gt.add_rule('dga', {'src': '10.0.5.0/24'}, 'suppress', now=NOW)
    pipe = DetectionPipeline(models=False, clock=lambda: NOW)
    pipe.dns.observe = lambda src, q, nx, ts: [finding(src, kind='dga', target=None)]
    assert pipe.observe_dns('10.0.5.20', 'x.example.com', ts=NOW) == []
    assert pipe.fusion.recent_for('10.0.5.20', NOW) == []
    assert [f.kind for f in pipe.observe_dns('10.0.6.20', 'x.example.com', ts=NOW)] == ['dga']


def test_api_accept_dismiss_and_roles(monkeypatch):
    from fastapi.testclient import TestClient
    from dashboard import dashboard_api as api
    from detection.feedback import get_store
    for i in range(6):
        get_store().add('beaconing', 'fp', src='10.0.5.20', alert={'responder_ip': '93.184.216.34'}, by='ana')
    analyst = {'username': 'ana', 'role': 'analyst'}
    api.app.dependency_overrides[api.require_viewer] = lambda: analyst
    api.app.dependency_overrides[api.require_analyst] = lambda: analyst
    try:
        c = TestClient(api.app)
        [s] = c.get('/api/guided-tuning/suggestions').json()['suggestions']
        assert c.post(f"/api/guided-tuning/suggestions/{s['id']}/accept", json={'action': 'suppress'}).status_code == 403
        r = c.post(f"/api/guided-tuning/suggestions/{s['id']}/accept", json={'days': 7})
        assert r.status_code == 200 and r.json()['by'] == 'ana' and r.json()['source'] == 'suggestion'
        assert c.get('/api/guided-tuning/suggestions').json()['suggestions'] == []      # covered now
        [rule] = c.get('/api/guided-tuning/rules').json()['rules']
        assert c.delete(f"/api/guided-tuning/rules/{rule['id']}").status_code == 200
        [s2] = c.get('/api/guided-tuning/suggestions').json()['suggestions']
        assert c.post(f"/api/guided-tuning/suggestions/{s2['id']}/dismiss").status_code == 200
        assert c.get('/api/guided-tuning/suggestions').json()['suggestions'] == []
        bad = c.post('/api/guided-tuning/rules', json={'kind': 'beaconing', 'scope': {'src': '0.0.0.0/0'}})
        assert bad.status_code == 400
        assert c.post('/api/guided-tuning/suggestions/nope/accept', json={}).status_code == 404
    finally:
        api.app.dependency_overrides.clear()
