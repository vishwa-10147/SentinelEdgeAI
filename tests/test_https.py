import pytest
from fastapi.testclient import TestClient

import core.auth as auth
import dashboard.dashboard_api as api
from dashboard import serve


@pytest.fixture(autouse=True)
def auth_db(tmp_path, monkeypatch):
    monkeypatch.setenv('SENTINEL_AUTH_DB', str(tmp_path / 'auth.db'))
    monkeypatch.delenv('DASHBOARD_API_KEY', raising=False)
    yield
    auth.get_store().close()


def test_plain_http_when_no_certificate():
    assert serve.tls_files({}) is None
    assert serve.tls_files({'SENTINEL_TLS_CERT': '', 'SENTINEL_TLS_KEY': ' '}) is None
    opts = serve.uvicorn_options({'SENTINEL_HOST': '0.0.0.0', 'SENTINEL_PORT': '9001'})
    assert opts == {'host': '0.0.0.0', 'port': 9001}


def test_https_options_when_configured(tmp_path):
    cert, key = tmp_path / 'cert.pem', tmp_path / 'key.pem'
    cert.write_text('c')
    key.write_text('k')
    opts = serve.uvicorn_options({'SENTINEL_TLS_CERT': str(cert), 'SENTINEL_TLS_KEY': str(key)})
    assert opts['ssl_certfile'] == str(cert) and opts['ssl_keyfile'] == str(key)
    assert opts['host'] == '127.0.0.1' and opts['port'] == 9000


@pytest.mark.parametrize('env', [
    {'SENTINEL_TLS_CERT': '/etc/sentinel/tls/cert.pem'},
    {'SENTINEL_TLS_KEY': '/etc/sentinel/tls/key.pem'},
])
def test_half_configured_tls_refuses_to_start(env):
    # never silently fall back to plain HTTP
    with pytest.raises(serve.TLSConfigError, match='both'):
        serve.tls_files(env)


def test_missing_certificate_file_refuses_to_start(tmp_path):
    key = tmp_path / 'key.pem'
    key.write_text('k')
    with pytest.raises(serve.TLSConfigError, match='not found'):
        serve.tls_files({'SENTINEL_TLS_CERT': str(tmp_path / 'nope.pem'), 'SENTINEL_TLS_KEY': str(key)})


def test_main_exits_with_error_on_bad_tls(monkeypatch, capsys):
    monkeypatch.setenv('SENTINEL_TLS_CERT', '/nope.pem')
    monkeypatch.setenv('SENTINEL_TLS_KEY', '/nope.key')
    assert serve.main() == 2
    assert 'not found' in capsys.readouterr().err


def test_hsts_only_over_https():
    assert 'strict-transport-security' not in TestClient(api.app).get('/api/auth/status').headers
    r = TestClient(api.app, base_url='https://testserver').get('/api/auth/status')
    assert r.headers['strict-transport-security'] == 'max-age=31536000'
