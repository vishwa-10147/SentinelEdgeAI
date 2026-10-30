import multiprocessing
import sqlite3

import pytest
from fastapi.testclient import TestClient

import core.audit as audit
import core.auth as auth
import dashboard.auth_routes as auth_routes
import dashboard.dashboard_api as api

PASSWORD = 'correct horse battery'


@pytest.fixture(autouse=True)
def auth_db(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTINEL_AUTH_DB', str(tmp_path / 'auth.db'))
    monkeypatch.delenv('DASHBOARD_API_KEY', raising=False)
    monkeypatch.setenv('SENTINEL_MFA_ROLES', '')
    monkeypatch.setattr(auth_routes, 'login_throttle', auth.LoginThrottle())
    yield
    auth.get_store().close()


@pytest.fixture
def log(tmp_path):
    entry_log = audit.AuditLog(str(tmp_path / 'chain.db'))
    yield entry_log
    entry_log.close()


def fill(log, n=5):
    for i in range(n):
        log.record('firewall_block', actor='alice', target=f'198.51.100.{i}', details={'i': i})


def tamper(log, sql, params=()):
    conn = sqlite3.connect(log.path)
    conn.execute(sql, params)
    conn.commit()
    conn.close()


def test_entries_are_chained(log):
    fill(log, 3)
    rows = list(reversed(log.entries()))
    assert [r['seq'] for r in rows] == [1, 2, 3]
    assert rows[0]['prev_hash'] == audit.GENESIS
    assert rows[1]['prev_hash'] == rows[0]['hash'] and rows[2]['prev_hash'] == rows[1]['hash']
    assert rows[0]['details'] == {'i': 0}
    assert log.verify() == {'ok': True, 'entries': 3, 'head': rows[2]['hash'], 'first_bad_seq': None, 'reason': None}


def test_empty_log_verifies(log):
    assert log.verify()['ok'] is True


def test_modified_entry_is_detected(log):
    fill(log)
    tamper(log, "UPDATE audit_log SET actor = 'mallory' WHERE seq = 3")
    result = log.verify()
    assert result['ok'] is False and result['first_bad_seq'] == 3 and 'modified' in result['reason']


def test_modified_entry_with_recomputed_hash_breaks_the_next_link(log):
    fill(log)
    row = log.entries(limit=1, before=3)[0]
    row['target'] = '203.0.113.99'
    row['details'] = None
    new_hash = audit.entry_hash(row)
    tamper(log, 'UPDATE audit_log SET target = ?, details = NULL, hash = ? WHERE seq = 2', (row['target'], new_hash))
    result = log.verify()
    assert result['ok'] is False and result['first_bad_seq'] == 3 and 'link' in result['reason']


def test_deleted_entry_is_detected(log):
    fill(log)
    tamper(log, 'DELETE FROM audit_log WHERE seq = 2')
    result = log.verify()
    assert result['ok'] is False and result['first_bad_seq'] == 2 and 'missing' in result['reason']


def test_truncated_head_changes_the_head_hash(log):
    # dropping the newest entries keeps a valid chain; the head hash (also
    # copied to journald) is what reveals it
    fill(log)
    head = log.verify()['head']
    tamper(log, 'DELETE FROM audit_log WHERE seq = 5')
    result = log.verify()
    assert result['ok'] is True and result['head'] != head and result['entries'] == 4


def test_filters_and_paging(log):
    fill(log, 4)
    log.record('login', actor='bob', outcome='failure')
    assert [e['actor'] for e in log.entries(action='login')] == ['bob']
    assert len(log.entries(actor='alice')) == 4
    assert [e['seq'] for e in log.entries(limit=2)] == [5, 4]
    assert [e['seq'] for e in log.entries(limit=2, before=4)] == [3, 2]


def test_long_fields_are_clipped(log):
    e = log.record('login', actor='x' * 1000, target='y' * 1000)
    assert len(e['actor']) == audit.MAX_FIELD and len(e['target']) == audit.MAX_FIELD
    assert log.verify()['ok']


def test_record_helper_never_raises(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError('disk full')
    monkeypatch.setattr(audit.AuditLog, 'record', boom)
    assert audit.record('firewall_block', actor='engine') is None


def _writer(path, n):
    entry_log = audit.AuditLog(path)
    for i in range(n):
        entry_log.record('firewall_block', actor='engine', target=str(i))
    entry_log.close()


def test_concurrent_processes_keep_one_chain(tmp_path):
    path = str(tmp_path / 'shared.db')
    audit.AuditLog(path).verify()  # create the table first
    procs = [multiprocessing.get_context('fork').Process(target=_writer, args=(path, 25)) for _ in range(4)]
    for p in procs:
        p.start()
    for p in procs:
        p.join(30)
    entry_log = audit.AuditLog(path)
    result = entry_log.verify()
    entry_log.close()
    assert result['ok'] and result['entries'] == 100


def test_cli_verify_and_tail(log, capsys):
    fill(log, 2)
    assert audit.main(['--db', log.path, 'verify']) == 0
    assert 'intact: 2 entries' in capsys.readouterr().out
    assert audit.main(['--db', log.path, 'tail', '-n', '5']) == 0
    assert '198.51.100.1' in capsys.readouterr().out
    tamper(log, "UPDATE audit_log SET outcome = 'x' WHERE seq = 1")
    assert audit.main(['--db', log.path, 'verify']) == 1
    assert 'BROKEN at entry 1' in capsys.readouterr().err


# ---------- what the API records ----------

def client():
    return TestClient(api.app, client=('203.0.113.30', 50000))


def login(c, username='root', password=PASSWORD):
    r = c.post('/api/auth/login', json={'username': username, 'password': password})
    return {'Authorization': f"Bearer {r.json()['access_token']}"} if r.status_code == 200 else r


def actions():
    return [(e['action'], e['actor'], e['outcome']) for e in reversed(audit.get_log().entries())]


def test_sign_ins_are_recorded():
    auth.get_store().create_user('root', PASSWORD, 'admin')
    c = client()
    login(c, password='wrong password!!')
    login(c)
    assert actions() == [('login', 'root', 'failure'), ('login', 'root', 'success')]
    entry = audit.get_log().entries(limit=1)[0]
    assert entry['client_ip'] == '203.0.113.30' and entry['role'] == 'admin' and entry['actor_kind'] == 'user'


def test_user_and_token_changes_are_recorded():
    auth.get_store().create_user('root', PASSWORD, 'admin')
    c = client()
    h = login(c)
    c.post('/api/users', json={'username': 'ana', 'password': PASSWORD, 'role': 'viewer'}, headers=h)
    c.patch('/api/users/ana', json={'role': 'analyst'}, headers=h)
    token = c.post('/api/tokens', json={'name': 'ci', 'role': 'viewer'}, headers=h).json()
    c.delete(f"/api/tokens/{token['id']}", headers=h)
    c.delete('/api/users/ana', headers=h)
    got = [a for a, _, _ in actions()]
    assert got == ['login', 'user_create', 'user_update', 'token_create', 'token_revoke', 'user_delete']
    update = audit.get_log().entries(action='user_update')[0]
    assert update['target'] == 'ana' and update['details'] == {'role': 'analyst'}
    # the token secret is never written to the audit log
    assert token['token'] not in str(audit.get_log().entries())


def test_firewall_actions_are_recorded(monkeypatch):
    auth.get_store().create_user('root', PASSWORD, 'admin')
    c = client()
    h = login(c)
    monkeypatch.setattr(api.firewall, 'add_block', lambda ip, ttl=None, reason='': {'ip': ip, 'dry_run': True})
    monkeypatch.setattr(api.firewall, 'remove_block', lambda ip: {'removed': 1, 'rules_left': 0})
    c.post('/api/firewall/block', json={'ip': '198.51.100.9', 'reason': 'test'}, headers=h)
    c.post('/api/firewall/unblock', json={'ip': '198.51.100.9'}, headers=h)
    block = audit.get_log().entries(action='firewall_block')[0]
    assert block['actor'] == 'root' and block['target'] == '198.51.100.9'
    assert block['details']['reason'] == 'test'
    assert audit.get_log().entries(action='firewall_unblock')[0]['details'] == {'removed': 1}


def test_rejected_block_is_recorded(monkeypatch):
    auth.get_store().create_user('root', PASSWORD, 'admin')
    c = client()
    h = login(c)

    def refuse(ip, ttl=None, reason=''):
        raise ValueError('refusing to block whitelisted IP')
    monkeypatch.setattr(api.firewall, 'add_block', refuse)
    assert c.post('/api/firewall/block', json={'ip': '198.51.100.9'}, headers=h).status_code == 400
    assert audit.get_log().entries(action='firewall_block')[0]['outcome'] == 'rejected'


def test_only_admins_can_read_and_verify():
    store = auth.get_store()
    store.create_user('root', PASSWORD, 'admin')
    store.create_user('oper', PASSWORD, 'operator')
    c = client()
    h_op = login(c, 'oper')
    assert c.get('/api/audit', headers=h_op).status_code == 403
    assert c.get('/api/audit/verify', headers=h_op).status_code == 403
    h = login(c)
    entries = c.get('/api/audit', headers=h).json()
    assert [e['actor'] for e in entries] == ['root', 'oper']
    assert c.get('/api/audit?action=login&limit=1', headers=h).json()[0]['seq'] == 2
    v = c.get('/api/audit/verify', headers=h).json()
    assert v['ok'] is True and v['entries'] == 2
