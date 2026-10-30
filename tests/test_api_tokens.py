import time

import pytest
from fastapi.testclient import TestClient

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
def store():
    s = auth.get_store()
    s.create_user('root', PASSWORD, 'admin')
    s.create_user('ana', PASSWORD, 'analyst')
    return s


def client():
    return TestClient(api.app, client=('203.0.113.20', 50000))


def admin_headers(c):
    r = c.post('/api/auth/login', json={'username': 'root', 'password': PASSWORD})
    assert r.status_code == 200, r.text
    return {'Authorization': f"Bearer {r.json()['access_token']}"}


def bearer(token):
    return {'Authorization': f'Bearer {token}'}


def test_token_is_shown_once_and_stored_hashed(store):
    token = store.create_api_token('root', 'ci', 'viewer')
    assert token['token'].startswith('sak1.' + token['id'] + '.')
    secret = token['token'].split('.', 2)[2]
    row = store._fetchone('SELECT token_hash FROM api_tokens WHERE id = ?', (token['id'],))
    assert secret not in row['token_hash']
    assert 'token' not in store.get_api_token(token['id'])
    assert all('token' not in t for t in store.list_api_tokens())


def test_token_authenticates_with_its_scope(store):
    token = store.create_api_token('root', 'grafana', 'viewer')['token']
    c = client()
    assert c.get('/api/live_stats', headers=bearer(token)).status_code != 401
    assert c.get('/api/live_stats', headers={'X-API-Key': token}).status_code != 401
    # viewer scope: operator actions are refused even though the owner is an admin
    r = c.post('/api/firewall/block', json={'ip': '198.51.100.7'}, headers=bearer(token))
    assert r.status_code == 403
    principal = store.verify_api_token(token)
    assert principal['kind'] == 'api_token' and principal['role'] == 'viewer'
    assert principal['owner'] == 'root'


def test_token_cannot_exceed_owner_role(store):
    with pytest.raises(ValueError):
        store.create_api_token('ana', 'too-much', 'operator')
    token = store.create_api_token('ana', 'ok', 'analyst')['token']
    # owner demoted later: the token is capped at the owner's current role
    store.update_user('ana', role='viewer')
    assert store.verify_api_token(token)['role'] == 'viewer'


def test_wrong_revoked_expired_or_disabled_tokens_fail(store):
    token = store.create_api_token('ana', 'svc', 'viewer')
    tid, secret = token['id'], token['token'].split('.', 2)[2]
    assert store.verify_api_token(f'sak1.{tid}.wrong') is None
    assert store.verify_api_token(f'sak1.nope.{secret}') is None
    assert store.verify_api_token('sak1.') is None

    store._execute('UPDATE api_tokens SET expires = ? WHERE id = ?', (int(time.time()) - 1, tid))
    assert store.verify_api_token(token['token']) is None
    assert store.get_api_token(tid)['expired'] is True

    other = store.create_api_token('ana', 'svc2', 'viewer')['token']
    store.update_user('ana', disabled=True)
    assert store.verify_api_token(other) is None
    store.update_user('ana', disabled=False)
    assert store.verify_api_token(other) is not None

    third = store.create_api_token('ana', 'svc3', 'viewer')
    store.revoke_api_token(third['id'])
    assert store.verify_api_token(third['token']) is None


def test_token_deleted_with_owner(store):
    token = store.create_api_token('ana', 'svc', 'viewer')['token']
    store.delete_user('ana')
    assert store.verify_api_token(token) is None


@pytest.mark.parametrize('days', [0, auth.API_TOKEN_MAX_DAYS + 1, 'x'])
def test_expiry_must_be_bounded(store, days):
    with pytest.raises(ValueError):
        store.create_api_token('root', 'svc', 'viewer', days)


def test_name_is_validated(store):
    with pytest.raises(ValueError):
        store.create_api_token('root', '<script>', 'viewer')


def test_admin_endpoints_create_list_revoke(store):
    c = client()
    h = admin_headers(c)
    r = c.post('/api/tokens', json={'name': 'backup job', 'role': 'operator', 'expires_days': 30}, headers=h)
    assert r.status_code == 201, r.text
    created = r.json()
    assert created['role'] == 'operator' and created['owner'] == 'root'
    assert created['expires'] - created['created'] == 30 * 86400

    listed = c.get('/api/tokens', headers=h).json()
    assert [t['id'] for t in listed] == [created['id']]
    assert 'token' not in listed[0]

    assert c.get('/api/live_stats', headers=bearer(created['token'])).status_code != 401
    assert c.delete(f"/api/tokens/{created['id']}", headers=h).json() == {'status': 'revoked'}
    assert c.get('/api/live_stats', headers=bearer(created['token'])).status_code == 401
    assert c.delete('/api/tokens/missing', headers=h).status_code == 404


def test_tokens_cannot_manage_tokens(store):
    token = store.create_api_token('root', 'admin-automation', 'admin')['token']
    c = client()
    assert c.get('/api/tokens', headers=bearer(token)).status_code == 403
    r = c.post('/api/tokens', json={'name': 'child', 'role': 'admin'}, headers=bearer(token))
    assert r.status_code == 403


def test_non_admins_cannot_manage_tokens(store):
    c = client()
    r = c.post('/api/auth/login', json={'username': 'ana', 'password': PASSWORD})
    h = bearer(r.json()['access_token'])
    assert c.get('/api/tokens', headers=h).status_code == 403
    assert c.post('/api/tokens', json={'name': 'x', 'role': 'viewer'}, headers=h).status_code == 403


def test_token_works_alongside_shared_key(store, monkeypatch):
    monkeypatch.setenv('DASHBOARD_API_KEY', 'shared-secret')
    token = store.create_api_token('root', 'svc', 'viewer')['token']
    c = client()
    assert c.get('/api/live_stats', headers=bearer(token)).status_code != 401
    assert c.get('/api/live_stats', headers={'X-API-Key': 'shared-secret'}).status_code != 401


def test_cli_create_list_revoke(store, capsys):
    db = store.path
    assert auth.main(['--db', db, 'create-token', '--owner', 'root', '--name', 'cli', '--role', 'viewer', '--days', '7']) == 0
    out = capsys.readouterr().out
    token = out.strip().splitlines()[-1]
    assert token.startswith('sak1.')
    tid = token.split('.')[1]
    assert auth.main(['--db', db, 'list-tokens']) == 0
    assert tid in capsys.readouterr().out
    assert auth.main(['--db', db, 'revoke-token', '--id', tid]) == 0
    assert auth.main(['--db', db, 'revoke-token', '--id', 'missing']) == 1
    assert 'no such token' in capsys.readouterr().err
