import time

import pytest
from fastapi.testclient import TestClient

import core.auth as auth
import dashboard.auth_routes as auth_routes
import dashboard.dashboard_api as api

PASSWORD = 'correct horse battery'
CSRF = {'X-Sentinel-CSRF': '1'}


@pytest.fixture(autouse=True)
def auth_db(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTINEL_AUTH_DB', str(tmp_path / 'auth.db'))
    monkeypatch.delenv('DASHBOARD_API_KEY', raising=False)
    monkeypatch.delenv('SENTINEL_API_KEY_ROLE', raising=False)
    # role and session tests run without the MFA requirement; MFA tests opt in
    monkeypatch.setenv('SENTINEL_MFA_ROLES', '')
    monkeypatch.setattr(auth_routes, 'login_throttle', auth.LoginThrottle())
    yield
    auth.get_store().close()


@pytest.fixture
def store():
    return auth.get_store()


def make_client(host='testclient'):
    return TestClient(api.app, client=(host, 50000))


def login(client, username, password=PASSWORD):
    r = client.post('/api/auth/login', json={'username': username, 'password': password})
    assert r.status_code == 200, r.text
    return r.json()['access_token']


def bearer(token):
    return {'Authorization': f'Bearer {token}'}


# ---------- store ----------

def test_passwords_are_hashed_with_argon2id(store):
    store.create_user('alice', PASSWORD, 'viewer')
    row = store._get('alice')
    assert row['password_hash'].startswith('$argon2id$')
    assert PASSWORD not in row['password_hash']


@pytest.mark.parametrize('username,password,role', [
    ('al', PASSWORD, 'viewer'),            # username too short
    ('bad name', PASSWORD, 'viewer'),      # space
    ('alice', 'short', 'viewer'),          # weak password
    ('alice', PASSWORD, 'root'),           # unknown role
    ('correcthorsebattery', 'CorrectHorseBattery', 'viewer'),  # password == username
])
def test_create_user_validation(store, username, password, role):
    with pytest.raises(ValueError):
        store.create_user(username, password, role)


def test_usernames_are_case_insensitive(store):
    store.create_user('Alice', PASSWORD, 'viewer')
    with pytest.raises(ValueError, match='exists'):
        store.create_user('alice', PASSWORD, 'viewer')
    assert store.authenticate('ALICE', PASSWORD)['username'] == 'Alice'


def test_lockout_after_repeated_failures(store):
    store.create_user('bob', PASSWORD, 'viewer')
    for _ in range(auth.MAX_FAILED_LOGINS):
        with pytest.raises(auth.AuthError):
            store.authenticate('bob', 'wrong password!!')
    with pytest.raises(auth.AuthError) as exc:
        store.authenticate('bob', PASSWORD)
    assert exc.value.status == 423


def test_disabled_user_cannot_sign_in(store):
    store.create_user('root', PASSWORD, 'admin')
    store.create_user('carol', PASSWORD, 'viewer')
    store.update_user('carol', disabled=True)
    with pytest.raises(auth.AuthError):
        store.authenticate('carol', PASSWORD)


def test_last_admin_cannot_be_removed(store):
    store.create_user('root', PASSWORD, 'admin')
    with pytest.raises(ValueError, match='last active admin'):
        store.update_user('root', role='viewer')
    with pytest.raises(ValueError, match='last active admin'):
        store.update_user('root', disabled=True)
    with pytest.raises(ValueError, match='last active admin'):
        store.delete_user('root')


def test_access_token_tampering_and_expiry(store, monkeypatch):
    store.create_user('dave', PASSWORD, 'operator')
    tokens = store.create_session('dave')
    assert store.verify_access_token(tokens['access_token'])['role'] == 'operator'
    head, sid, exp, sig = tokens['access_token'].split('.')
    assert store.verify_access_token(f'{head}.{sid}.{int(exp) + 3600}.{sig}') is None
    monkeypatch.setattr(auth.time, 'time', lambda: int(exp) + 1)
    assert store.verify_access_token(tokens['access_token']) is None


def test_refresh_rotates_and_detects_reuse(store):
    store.create_user('erin', PASSWORD, 'viewer')
    first = store.create_session('erin')
    second = store.refresh(first['refresh_token'])
    assert second['refresh_token'] != first['refresh_token']
    with pytest.raises(auth.AuthError, match='reuse'):
        store.refresh(first['refresh_token'])
    # the whole session is revoked once reuse is detected
    with pytest.raises(auth.AuthError):
        store.refresh(second['refresh_token'])
    assert store.verify_access_token(second['access_token']) is None


def test_role_change_applies_to_existing_tokens(store):
    store.create_user('root', PASSWORD, 'admin')
    store.create_user('frank', PASSWORD, 'operator')
    tokens = store.create_session('frank')
    store.update_user('frank', role='viewer')
    assert store.verify_access_token(tokens['access_token'])['role'] == 'viewer'


def test_password_change_signs_out_other_sessions(store):
    store.create_user('gina', PASSWORD, 'viewer')
    keep = store.create_session('gina')
    other = store.create_session('gina')
    store.set_password('gina', 'another long password', keep_session=keep['session_id'])
    assert store.verify_access_token(keep['access_token']) is not None
    assert store.verify_access_token(other['access_token']) is None


def test_login_throttle():
    throttle = auth.LoginThrottle(max_attempts=3, window_seconds=60)
    assert all(throttle.allow('1.2.3.4', now=100 + i) for i in range(3))
    assert not throttle.allow('1.2.3.4', now=110)
    assert throttle.allow('5.6.7.8', now=110)
    assert throttle.allow('1.2.3.4', now=170)


def test_cli_bootstrap_admin(tmp_path, store):
    pw_file = tmp_path / 'initial-admin-password'
    assert auth.main(['bootstrap-admin', '--password-file', str(pw_file)]) == 0
    password = pw_file.read_text().strip()
    user = store.authenticate('admin', password)
    assert user['role'] == 'admin' and user['must_change_password'] is True
    # second run is a no-op and does not overwrite the password file
    assert auth.main(['bootstrap-admin', '--password-file', str(pw_file)]) == 0
    assert pw_file.read_text().strip() == password


# ---------- API ----------

def test_remote_requests_need_auth_even_without_users():
    r = make_client().get('/api/alerts')
    assert r.status_code == 401


def test_localhost_dev_mode_only_until_first_user(store):
    local = make_client('127.0.0.1')
    assert local.get('/api/auth/me').json()['username'] == 'local'
    store.create_user('root', PASSWORD, 'admin')
    assert local.get('/api/auth/me').status_code == 401


def test_live_stats_and_auth_status():
    client = make_client()
    assert client.get('/api/live_stats').status_code == 401
    status = client.get('/api/auth/status').json()
    assert status['accounts_enabled'] is False


def test_login_refresh_logout_flow(store):
    store.create_user('root', PASSWORD, 'admin')
    client = make_client()
    r = client.post('/api/auth/login', json={'username': 'root', 'password': PASSWORD})
    assert r.status_code == 200
    body = r.json()
    assert body['user'] == {'username': 'root', 'role': 'admin', 'must_change_password': False,
                            'mfa_enabled': False, 'mfa_setup_required': False, 'setup_required': True}
    cookie = r.headers['set-cookie'].lower()
    assert 'httponly' in cookie and 'samesite=strict' in cookie and 'path=/api/auth' in cookie

    assert client.get('/api/auth/me', headers=bearer(body['access_token'])).json()['username'] == 'root'

    assert client.post('/api/auth/refresh').status_code == 403          # missing CSRF header
    r = client.post('/api/auth/refresh', headers=CSRF)
    assert r.status_code == 200
    new_token = r.json()['access_token']

    assert client.post('/api/auth/logout', headers={**CSRF, **bearer(new_token)}).status_code == 200
    assert client.get('/api/auth/me', headers=bearer(new_token)).status_code == 401
    assert client.post('/api/auth/refresh', headers=CSRF).status_code == 401


def test_login_errors_do_not_reveal_usernames(store):
    store.create_user('root', PASSWORD, 'admin')
    client = make_client()
    unknown = client.post('/api/auth/login', json={'username': 'nobody', 'password': PASSWORD})
    wrong = client.post('/api/auth/login', json={'username': 'root', 'password': 'wrong password!!'})
    assert unknown.status_code == wrong.status_code == 401
    assert unknown.json() == wrong.json()


def test_login_is_rate_limited(store, monkeypatch):
    monkeypatch.setattr(auth_routes, 'login_throttle', auth.LoginThrottle(max_attempts=2))
    client = make_client()
    for _ in range(2):
        client.post('/api/auth/login', json={'username': 'x' * 5, 'password': 'y' * 12})
    r = client.post('/api/auth/login', json={'username': 'x' * 5, 'password': 'y' * 12})
    assert r.status_code == 429


@pytest.mark.parametrize('role,method,path,body,allowed', [
    ('viewer', 'get', '/api/alerts', None, True),
    ('viewer', 'get', '/api/firewall/policy', None, True),
    ('viewer', 'post', '/api/alerts/explain', {}, False),
    ('analyst', 'post', '/api/alerts/explain', {}, True),
    ('analyst', 'post', '/api/firewall/expire', None, False),
    ('operator', 'post', '/api/firewall/expire', None, True),
    ('operator', 'post', '/api/firewall/policy', {}, False),
    ('operator', 'get', '/api/users', None, False),
    ('admin', 'get', '/api/users', None, True),
])
def test_role_enforcement(store, role, method, path, body, allowed):
    store.create_user('root', PASSWORD, 'admin')
    if role != 'admin':
        store.create_user(role, PASSWORD, role)
    client = make_client()
    token = login(client, 'root' if role == 'admin' else role)
    kwargs = {'headers': bearer(token)}
    if body is not None:
        kwargs['json'] = body
    r = getattr(client, method)(path, **kwargs)
    if allowed:
        assert r.status_code not in (401, 403), r.text
    else:
        assert r.status_code == 403


def test_must_change_password_blocks_other_endpoints(store):
    store.create_user('root', PASSWORD, 'admin', must_change_password=True)
    client = make_client()
    token = login(client, 'root')
    assert client.get('/api/alerts', headers=bearer(token)).status_code == 403
    assert client.get('/api/auth/me', headers=bearer(token)).json()['must_change_password'] is True
    r = client.post('/api/auth/password', headers=bearer(token),
                    json={'current_password': PASSWORD, 'new_password': 'a brand new passphrase'})
    assert r.status_code == 200
    assert client.get('/api/alerts', headers=bearer(token)).status_code != 403


def test_admin_user_management(store):
    store.create_user('root', PASSWORD, 'admin')
    client = make_client()
    h = bearer(login(client, 'root'))
    r = client.post('/api/users', headers=h, json={'username': 'ops1', 'password': PASSWORD, 'role': 'operator'})
    assert r.status_code == 201 and r.json()['must_change_password'] is True
    assert client.patch('/api/users/ops1', headers=h, json={'role': 'analyst'}).json()['role'] == 'analyst'
    assert client.patch('/api/users/root', headers=h, json={'disabled': True}).status_code == 400
    assert client.delete('/api/users/root', headers=h).status_code == 400
    assert client.delete('/api/users/ops1', headers=h).status_code == 200
    assert client.delete('/api/users/ops1', headers=h).status_code == 404


def test_api_key_still_works_with_configured_role(store, monkeypatch):
    monkeypatch.setenv('DASHBOARD_API_KEY', 'k' * 32)
    client = make_client()
    assert client.get('/api/auth/me', headers={'X-API-Key': 'k' * 32}).json()['role'] == 'admin'
    assert client.get('/api/alerts', headers={'X-API-Key': 'wrong'}).status_code == 401
    monkeypatch.setenv('SENTINEL_API_KEY_ROLE', 'viewer')
    assert client.post('/api/firewall/expire', headers={'X-API-Key': 'k' * 32}).status_code == 403


def test_websocket_requires_auth(store):
    store.create_user('root', PASSWORD, 'admin')
    client = make_client()
    with client.websocket_connect('/ws/packets') as ws:
        ws.send_json({'type': 'auth', 'token': 'nope'})
        with pytest.raises(Exception):
            ws.receive_text()
    token = login(client, 'root')
    with client.websocket_connect('/ws/packets') as ws:
        ws.send_json({'type': 'auth', 'token': token})
        assert ws.receive_json()['type'] == 'auth_ok'
