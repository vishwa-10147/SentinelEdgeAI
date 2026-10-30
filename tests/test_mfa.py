import base64
import sqlite3
import time

import pytest
from fastapi.testclient import TestClient

import core.auth as auth
import dashboard.auth_routes as auth_routes
import dashboard.dashboard_api as api

PASSWORD = 'correct horse battery'
RFC_SECRET = base64.b32encode(b'12345678901234567890').decode()


@pytest.fixture(autouse=True)
def auth_db(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTINEL_AUTH_DB', str(tmp_path / 'auth.db'))
    monkeypatch.delenv('DASHBOARD_API_KEY', raising=False)
    monkeypatch.delenv('SENTINEL_API_KEY_ROLE', raising=False)
    monkeypatch.setenv('SENTINEL_MFA_ROLES', 'operator,admin')
    monkeypatch.setattr(auth_routes, 'login_throttle', auth.LoginThrottle())
    yield
    auth.get_store().close()


@pytest.fixture
def store():
    return auth.get_store()


def make_client():
    return TestClient(api.app, client=('testclient', 50000))


def bearer(token):
    return {'Authorization': f'Bearer {token}'}


def current_code(secret, offset_steps=0):
    return auth.totp_code(secret, int(time.time()) // auth.TOTP_PERIOD + offset_steps)


def wrong_code(secret):
    # a six-digit code outside the accepted window
    return current_code(secret, 5)


def enrol(store, username):
    secret = store.begin_mfa_enrolment(username)['secret']
    codes = store.enable_mfa(username, current_code(secret, -1))
    return secret, codes


# ---------- TOTP ----------

def test_totp_matches_rfc6238_vectors():
    # RFC 6238 appendix B (SHA1): T=59 -> 94287082, T=1111111109 -> 07081804
    assert auth.totp_code(RFC_SECRET, 59 // 30, digits=8) == '94287082'
    assert auth.totp_code(RFC_SECRET, 59 // 30) == '287082'
    assert auth.totp_code(RFC_SECRET, 1111111109 // 30, digits=8) == '07081804'


def test_totp_drift_window_and_replay():
    now = 1_000_000_000
    step = now // 30
    code = lambda s: auth.totp_code(RFC_SECRET, s)  # noqa: E731
    assert auth.totp_match(RFC_SECRET, code(step), now=now) == step
    assert auth.totp_match(RFC_SECRET, code(step - 1), now=now) == step - 1
    assert auth.totp_match(RFC_SECRET, code(step + 1), now=now) == step + 1
    assert auth.totp_match(RFC_SECRET, code(step - 2), now=now) is None
    # a step at or before the last one used is refused (no replay)
    assert auth.totp_match(RFC_SECRET, code(step), after_step=step, now=now) is None
    assert auth.totp_match(RFC_SECRET, 'abcdef', now=now) is None
    assert auth.totp_match(RFC_SECRET, f' {code(step)[:3]} {code(step)[3:]} ', now=now) == step


def test_mfa_roles_setting(monkeypatch):
    monkeypatch.setenv('SENTINEL_MFA_ROLES', 'admin, bogus')
    assert auth.mfa_roles() == {'admin'}
    assert auth.mfa_required_for('admin') and not auth.mfa_required_for('operator')
    monkeypatch.setenv('SENTINEL_MFA_ROLES', '')
    assert auth.mfa_roles() == set()


# ---------- store ----------

def test_enrolment_returns_qr_and_recovery_codes(store):
    store.create_user('ops', PASSWORD, 'operator')
    assert store.get_user('ops')['mfa_setup_required'] is True
    enrolment = store.begin_mfa_enrolment('ops')
    assert enrolment['otpauth_uri'].startswith('otpauth://totp/SentinelEdgeAI:ops?secret=')
    assert '<svg' in enrolment['qr_svg']
    with pytest.raises(ValueError, match='does not match'):
        store.enable_mfa('ops', wrong_code(enrolment['secret']))
    codes = store.enable_mfa('ops', current_code(enrolment['secret']))
    assert len(codes) == auth.RECOVERY_CODE_COUNT and len(set(codes)) == len(codes)
    user = store.get_user('ops')
    assert user['mfa_enabled'] is True and user['mfa_setup_required'] is False
    with pytest.raises(ValueError, match='already enabled'):
        store.begin_mfa_enrolment('ops')


def test_login_needs_second_factor_once_enabled(store):
    store.create_user('ops', PASSWORD, 'operator')
    secret, _ = enrol(store, 'ops')
    with pytest.raises(auth.AuthError) as exc:
        store.authenticate('ops', PASSWORD)
    assert exc.value.code == 'mfa_required'
    assert store._get('ops')['failed_logins'] == 0          # correct password is not a failure
    code = current_code(secret)
    assert store.authenticate('ops', PASSWORD, code)['username'] == 'ops'
    with pytest.raises(auth.AuthError) as exc:              # same code twice
        store.authenticate('ops', PASSWORD, code)
    assert exc.value.code == 'mfa_invalid'


def test_wrong_codes_count_toward_lockout(store):
    store.create_user('ops', PASSWORD, 'operator')
    secret, _ = enrol(store, 'ops')
    for _ in range(auth.MAX_FAILED_LOGINS):
        with pytest.raises(auth.AuthError):
            store.authenticate('ops', PASSWORD, wrong_code(secret))
    with pytest.raises(auth.AuthError) as exc:
        store.authenticate('ops', PASSWORD, current_code(secret))
    assert exc.value.status == 423


def test_recovery_codes_work_once(store):
    store.create_user('ops', PASSWORD, 'operator')
    _, codes = enrol(store, 'ops')
    assert store.authenticate('ops', PASSWORD, codes[0].upper())['username'] == 'ops'
    assert store.recovery_codes_left('ops') == auth.RECOVERY_CODE_COUNT - 1
    with pytest.raises(auth.AuthError):
        store.authenticate('ops', PASSWORD, codes[0])
    assert store.authenticate('ops', PASSWORD, codes[1].replace('-', ''))['username'] == 'ops'


def test_reset_mfa_signs_out_and_requires_new_enrolment(store):
    store.create_user('ops', PASSWORD, 'operator')
    enrol(store, 'ops')
    tokens = store.create_session('ops')
    store.reset_mfa('ops')
    assert store.verify_access_token(tokens['access_token']) is None
    user = store.authenticate('ops', PASSWORD)               # password alone works again
    assert user['mfa_enabled'] is False and user['mfa_setup_required'] is True
    assert store.recovery_codes_left('ops') == 0


def test_old_database_is_migrated(tmp_path):
    path = tmp_path / 'old.db'
    conn = sqlite3.connect(path)
    conn.executescript(
        'CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, '
        'username TEXT NOT NULL UNIQUE COLLATE NOCASE, password_hash TEXT NOT NULL, role TEXT NOT NULL, '
        'disabled INTEGER NOT NULL DEFAULT 0, must_change_password INTEGER NOT NULL DEFAULT 0, '
        'failed_logins INTEGER NOT NULL DEFAULT 0, locked_until INTEGER NOT NULL DEFAULT 0, '
        'created INTEGER NOT NULL, updated INTEGER NOT NULL, last_login INTEGER);'
    )
    conn.execute(
        "INSERT INTO users(username, password_hash, role, created, updated) VALUES (?, ?, 'admin', 0, 0)",
        ('legacy', auth._hasher.hash(PASSWORD)),
    )
    conn.commit()
    conn.close()
    old = auth.AuthStore(str(path))
    try:
        user = old.authenticate('legacy', PASSWORD)
        assert user['mfa_enabled'] is False and user['mfa_setup_required'] is True
    finally:
        old.close()


def test_cli_reset_mfa(store):
    store.create_user('ops', PASSWORD, 'operator')
    enrol(store, 'ops')
    assert auth.main(['reset-mfa', '--username', 'ops']) == 0
    assert store.get_user('ops')['mfa_enabled'] is False


# ---------- API ----------

def test_api_enrolment_then_login_with_code(store):
    store.create_user('root', PASSWORD, 'admin')
    client = make_client()
    r = client.post('/api/auth/login', json={'username': 'root', 'password': PASSWORD})
    assert r.status_code == 200 and r.json()['user']['mfa_setup_required'] is True
    token = r.json()['access_token']
    h = bearer(token)

    # nothing else works until enrolment is finished, including the live stream
    assert client.get('/api/alerts', headers=h).status_code == 403
    assert client.get('/api/auth/me', headers=h).json()['mfa_setup_required'] is True
    with client.websocket_connect('/ws/packets') as ws:
        ws.send_json({'type': 'auth', 'token': token})
        with pytest.raises(Exception):
            ws.receive_text()

    enrolment = client.post('/api/auth/mfa/setup', headers=h).json()
    assert enrolment['secret'] and '<svg' in enrolment['qr_svg']
    assert client.post('/api/auth/mfa/enable', headers=h, json={'code': '12'}).status_code == 400
    r = client.post('/api/auth/mfa/enable', headers=h, json={'code': current_code(enrolment['secret'], -1)})
    assert r.status_code == 200 and len(r.json()['recovery_codes']) == auth.RECOVERY_CODE_COUNT
    assert client.get('/api/alerts', headers=h).status_code != 403
    assert client.get('/api/auth/mfa', headers=h).json() == {
        'enabled': True, 'required': True, 'recovery_codes_left': auth.RECOVERY_CODE_COUNT}

    fresh = make_client()
    r = fresh.post('/api/auth/login', json={'username': 'root', 'password': PASSWORD})
    assert r.status_code == 401 and r.json()['detail'] == 'mfa_required'
    r = fresh.post('/api/auth/login', json={'username': 'root', 'password': PASSWORD,
                                            'otp': wrong_code(enrolment['secret'])})
    assert r.status_code == 401 and r.json()['detail'] == 'mfa_invalid'
    r = fresh.post('/api/auth/login', json={'username': 'root', 'password': PASSWORD,
                                            'otp': current_code(enrolment['secret'])})
    assert r.status_code == 200 and r.json()['user']['mfa_enabled'] is True


def test_password_change_comes_before_enrolment(store):
    store.create_user('root', PASSWORD, 'admin', must_change_password=True)
    client = make_client()
    token = client.post('/api/auth/login', json={'username': 'root', 'password': PASSWORD}).json()['access_token']
    assert client.post('/api/auth/mfa/setup', headers=bearer(token)).status_code == 403


def test_wrong_password_never_reaches_mfa_step(store):
    store.create_user('ops', PASSWORD, 'operator')
    enrol(store, 'ops')
    r = make_client().post('/api/auth/login', json={'username': 'ops', 'password': 'wrong password!!'})
    assert r.status_code == 401 and r.json()['detail'] == 'invalid username or password'


def test_admin_can_reset_mfa(store, monkeypatch):
    monkeypatch.setenv('SENTINEL_MFA_ROLES', 'operator')     # admin signs in with a password only
    store.create_user('root', PASSWORD, 'admin')
    store.create_user('ops', PASSWORD, 'operator')
    enrol(store, 'ops')
    client = make_client()
    token = client.post('/api/auth/login', json={'username': 'root', 'password': PASSWORD}).json()['access_token']
    r = client.patch('/api/users/ops', headers=bearer(token), json={'reset_mfa': True})
    assert r.status_code == 200
    assert r.json()['mfa_enabled'] is False and r.json()['mfa_setup_required'] is True


def test_viewers_are_not_forced_to_enrol(store):
    store.create_user('root', PASSWORD, 'admin')
    store.create_user('watcher', PASSWORD, 'viewer')
    client = make_client()
    r = client.post('/api/auth/login', json={'username': 'watcher', 'password': PASSWORD})
    assert r.json()['user']['mfa_setup_required'] is False
    assert client.get('/api/alerts', headers=bearer(r.json()['access_token'])).status_code != 403
