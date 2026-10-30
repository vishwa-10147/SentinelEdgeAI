import pytest
from fastapi import HTTPException

import dashboard.auth_routes as auth_routes
import dashboard.dashboard_api as api


def test_api_key_accepts_x_api_key(monkeypatch):
    monkeypatch.setenv("DASHBOARD_API_KEY", "secret")

    principal = auth_routes.resolve_principal(None, "203.0.113.1", key="secret")
    assert principal["kind"] == "api_key"


def test_api_key_rejects_missing_header(monkeypatch):
    monkeypatch.setenv("DASHBOARD_API_KEY", "secret")

    assert auth_routes.resolve_principal(None, "203.0.113.1") is None
    assert auth_routes.resolve_principal("wrong", "203.0.113.1") is None


def test_firewall_block_rejects_invalid_ip():
    with pytest.raises(HTTPException) as exc:
        api.firewall_block({"ip": "1.2.3.4; id"}, principal={"role": "admin"})
    assert exc.value.status_code == 400
