import pytest
from fastapi.testclient import TestClient

import core.auth as auth
import dashboard.dashboard_api as api


@pytest.fixture(autouse=True)
def auth_db(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTINEL_AUTH_DB', str(tmp_path / 'auth.db'))
    monkeypatch.delenv('DASHBOARD_API_KEY', raising=False)
    yield
    auth.get_store().close()


def limit(monkeypatch, read=None, write=None):
    if read is not None:
        monkeypatch.setattr(api, 'RATE_LIMIT_READ', read)
        monkeypatch.setattr(api, 'read_limiter', auth.SlidingWindowLimiter(read, 60))
    if write is not None:
        monkeypatch.setattr(api, 'RATE_LIMIT_WRITE', write)
        monkeypatch.setattr(api, 'write_limiter', auth.SlidingWindowLimiter(write, 60))


def test_reads_are_limited_per_client(monkeypatch):
    limit(monkeypatch, read=3)
    client = TestClient(api.app, client=('203.0.113.5', 50000))
    for _ in range(3):
        assert client.get('/api/auth/status').status_code == 200
    r = client.get('/api/auth/status')
    assert r.status_code == 429
    assert 1 <= int(r.headers['retry-after']) <= 60
    # another client has its own window
    other = TestClient(api.app, client=('203.0.113.6', 50000))
    assert other.get('/api/auth/status').status_code == 200


def test_writes_have_their_own_stricter_limit(monkeypatch):
    limit(monkeypatch, read=100, write=2)
    client = TestClient(api.app, client=('203.0.113.7', 50000))
    for _ in range(2):
        assert client.post('/api/auth/logout').status_code != 429
    assert client.post('/api/auth/logout').status_code == 429
    # reads are still allowed
    assert client.get('/api/auth/status').status_code == 200


def test_non_api_paths_are_not_limited(monkeypatch):
    limit(monkeypatch, read=1)
    client = TestClient(api.app, client=('203.0.113.8', 50000))
    for _ in range(3):
        assert client.get('/metrics').status_code != 429


def test_zero_disables_the_limit(monkeypatch):
    limit(monkeypatch, read=0)
    client = TestClient(api.app, client=('203.0.113.9', 50000))
    for _ in range(5):
        assert client.get('/api/auth/status').status_code == 200


def test_retry_after():
    limiter = auth.SlidingWindowLimiter(2, 60)
    assert limiter.allow('a', now=100.0) and limiter.allow('a', now=110.0)
    assert not limiter.allow('a', now=120.0)
    assert limiter.retry_after('a', now=120.0) == 40
    assert limiter.retry_after('b', now=120.0) == 0


def test_rate_limited_responses_carry_security_headers(monkeypatch):
    limit(monkeypatch, read=1)
    client = TestClient(api.app, client=('203.0.113.10', 50000))
    client.get('/api/auth/status')
    r = client.get('/api/auth/status')
    assert r.status_code == 429
    assert r.headers['x-frame-options'] == 'DENY'
    assert 'content-security-policy' in r.headers
