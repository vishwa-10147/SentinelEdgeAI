import pytest

import core.audit as audit
import core.auth as auth
import dashboard.dashboard_api as api


@pytest.fixture(autouse=True)
def isolated_audit_log(tmp_path, monkeypatch):
    # every test gets its own audit database, never the repository's data/
    monkeypatch.setenv('SENTINEL_AUDIT_DB', str(tmp_path / 'audit.db'))
    yield
    audit.get_log().close()


@pytest.fixture(autouse=True)
def fresh_rate_limiters(monkeypatch):
    # every test starts with empty API rate-limit windows
    monkeypatch.setattr(api, 'read_limiter', auth.SlidingWindowLimiter(api.RATE_LIMIT_READ, api.RATE_LIMIT_WINDOW))
    monkeypatch.setattr(api, 'write_limiter', auth.SlidingWindowLimiter(api.RATE_LIMIT_WRITE, api.RATE_LIMIT_WINDOW))
