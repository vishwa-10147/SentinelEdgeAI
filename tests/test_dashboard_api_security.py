import pytest
from fastapi import HTTPException

import dashboard.dashboard_api as api


def test_api_key_accepts_x_api_key(monkeypatch):
    monkeypatch.setattr(api, "API_KEY", "secret")

    assert api.require_api_key(x_api_key="secret", authorization=None) is True


def test_api_key_rejects_missing_header(monkeypatch):
    monkeypatch.setattr(api, "API_KEY", "secret")

    with pytest.raises(HTTPException) as exc:
        api.require_api_key(x_api_key=None, authorization=None)
    assert exc.value.status_code == 401


def test_firewall_block_rejects_invalid_ip(monkeypatch):
    monkeypatch.setattr(api, "API_KEY", None)

    with pytest.raises(HTTPException) as exc:
        api.firewall_block({"ip": "1.2.3.4; id"}, api_ok=True)
    assert exc.value.status_code == 400
