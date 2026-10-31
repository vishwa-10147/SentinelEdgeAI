import pytest

import core.audit as audit
import core.auth as auth
import dashboard.dashboard_api as api


@pytest.fixture(autouse=True)
def isolated_audit_log(tmp_path, monkeypatch):
    # every test gets its own audit database, never the repository's data/
    monkeypatch.setenv('SENTINEL_AUDIT_DB', str(tmp_path / 'audit.db'))
    monkeypatch.setenv('SENTINEL_SETUP_FILE', str(tmp_path / 'setup.json'))
    monkeypatch.setenv('SENTINEL_SENSOR_DIR', str(tmp_path / 'sensor'))
    monkeypatch.setenv('SENTINEL_SENSOR_BUFFER', str(tmp_path / 'sensor_buffer.db'))
    monkeypatch.setenv('SENTINEL_BRAIN_DIR', str(tmp_path / 'brain'))
    monkeypatch.setenv('SENTINEL_BRAIN_DB', str(tmp_path / 'brain.db'))
    monkeypatch.setenv('SENTINEL_DEVICES_DB', str(tmp_path / 'devices.db'))
    monkeypatch.setenv('SENTINEL_OT_DB', str(tmp_path / 'ot.db'))
    monkeypatch.setenv('SENTINEL_PEERS_DB', str(tmp_path / 'peers.db'))
    monkeypatch.setenv('SENTINEL_FLEET_DB', str(tmp_path / 'fleet.db'))
    monkeypatch.setenv('SENTINEL_FLEET_DIR', str(tmp_path / 'fleet'))
    monkeypatch.setenv('SENTINEL_FLEET_AGENT_DIR', str(tmp_path / 'fleet_agent'))
    monkeypatch.setenv('SENTINEL_OT_SEGMENTATION', str(tmp_path / 'ot_segmentation.json'))
    monkeypatch.setenv('SENTINEL_PLAYBOOK_DB', str(tmp_path / 'playbook.db'))
    monkeypatch.setenv('SENTINEL_RESPONSE_POLICY', str(tmp_path / 'response_policy.json'))
    monkeypatch.setenv('SENTINEL_WATCHDOG_STATE', str(tmp_path / 'watchdog.json'))
    monkeypatch.setenv('SENTINEL_FEEDBACK_DB', str(tmp_path / 'feedback.db'))
    monkeypatch.setenv('SENTINEL_MODEL_REGISTRY', str(tmp_path / 'models'))
    monkeypatch.setenv('SENTINEL_JA3_BLOCKLIST', str(tmp_path / 'ja3_blocklist.txt'))
    monkeypatch.setenv('SENTINEL_INTEL_DB', str(tmp_path / 'intel.db'))
    monkeypatch.setenv('SENTINEL_INTEGRATIONS', str(tmp_path / 'integrations.json'))
    yield
    audit.get_log().close()


@pytest.fixture(autouse=True)
def fresh_rate_limiters(monkeypatch):
    # every test starts with empty API rate-limit windows
    monkeypatch.setattr(api, 'read_limiter', auth.SlidingWindowLimiter(api.RATE_LIMIT_READ, api.RATE_LIMIT_WINDOW))
    monkeypatch.setattr(api, 'write_limiter', auth.SlidingWindowLimiter(api.RATE_LIMIT_WRITE, api.RATE_LIMIT_WINDOW))
