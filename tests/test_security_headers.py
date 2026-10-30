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


@pytest.mark.parametrize('path', ['/api/auth/status', '/api/live_stats', '/does-not-exist'])
def test_security_headers_on_every_response(path):
    r = TestClient(api.app).get(path)
    assert r.headers['x-frame-options'] == 'DENY'
    assert r.headers['x-content-type-options'] == 'nosniff'
    assert r.headers['referrer-policy'] == 'no-referrer'
    assert r.headers['cross-origin-opener-policy'] == 'same-origin'
    assert 'camera=()' in r.headers['permissions-policy']
    assert r.headers['cross-origin-embedder-policy'] == 'require-corp'
    assert r.headers['cross-origin-resource-policy'] == 'same-origin'
    assert r.headers['cache-control'] == 'no-store'


def test_csp_is_strict():
    csp = TestClient(api.app).get('/api/auth/status').headers['content-security-policy']
    directives = dict(d.strip().split(' ', 1) for d in csp.split(';'))
    assert directives['default-src'] == "'self'"
    assert directives['script-src'] == "'self'"
    assert directives['object-src'] == "'none'"
    assert directives['frame-ancestors'] == "'none'"
    # the TOTP enrolment QR code is rendered from a data: URI
    assert directives['img-src'] == "'self' data:"
    assert 'unsafe-inline' not in csp and 'unsafe-eval' not in csp


def test_fingerprinted_assets_are_cacheable(tmp_path, monkeypatch):
    from fastapi import FastAPI
    from fastapi.staticfiles import StaticFiles
    (tmp_path / 'index-abc123.js').write_text('console.log(1)')
    sub = FastAPI()
    sub.mount('/assets', StaticFiles(directory=str(tmp_path)))
    sub.middleware('http')(api.security_headers_middleware)
    c = TestClient(sub)
    assert c.get('/assets/index-abc123.js').headers['cache-control'] == api.ASSET_CACHE
    assert c.get('/assets/missing.js').headers['cache-control'] == 'no-store'
