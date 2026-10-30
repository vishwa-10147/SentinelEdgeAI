import pytest

import core.auth as auth
import dashboard.dashboard_api as api


@pytest.fixture(autouse=True)
def fresh_rate_limiters(monkeypatch):
    # every test starts with empty API rate-limit windows
    monkeypatch.setattr(api, 'read_limiter', auth.SlidingWindowLimiter(api.RATE_LIMIT_READ, api.RATE_LIMIT_WINDOW))
    monkeypatch.setattr(api, 'write_limiter', auth.SlidingWindowLimiter(api.RATE_LIMIT_WRITE, api.RATE_LIMIT_WINDOW))
