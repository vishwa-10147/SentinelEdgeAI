import os
import base64
import time
import requests
from core.health_server import start_health_server


class FakeMonitor:
    def get_status(self):
        return {"status": "ok"}


def _basic_auth_header(user, pwd):
    token = base64.b64encode(f"{user}:{pwd}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


def test_health_server_no_auth(monkeypatch):
    # Ensure no env auth
    monkeypatch.delenv("HEALTH_USER", raising=False)
    monkeypatch.delenv("HEALTH_PASS", raising=False)
    server = start_health_server(FakeMonitor(), host="127.0.0.1", port=58123)
    time.sleep(0.1)
    r = requests.get("http://127.0.0.1:58123/health")
    assert r.status_code == 200
    assert r.json().get("status") == "ok"
    server.shutdown()


def test_health_server_with_auth(monkeypatch):
    monkeypatch.setenv("HEALTH_USER", "u")
    monkeypatch.setenv("HEALTH_PASS", "p")
    server = start_health_server(FakeMonitor(), host="127.0.0.1", port=58124)
    time.sleep(0.1)
    r = requests.get("http://127.0.0.1:58124/health")
    assert r.status_code == 401
    headers = _basic_auth_header("u", "p")
    r2 = requests.get("http://127.0.0.1:58124/health", headers=headers)
    assert r2.status_code == 200
    server.shutdown()
