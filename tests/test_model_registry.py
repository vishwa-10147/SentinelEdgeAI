import json
import os
from sklearn.ensemble import IsolationForest

from detection.ml_engine import MLEngine
from detection import registry


def _write_registry_model(tmp_path, monkeypatch, tamper=False):
    """Register an Isolation Forest through the Ed25519 registry and return its version."""
    monkeypatch.setenv("SENTINEL_MODEL_REGISTRY", str(tmp_path / "models"))
    engine = MLEngine()
    model = IsolationForest(n_estimators=1, random_state=42)
    model.fit([[0, 0, 0, 0], [1, 1, 1, 1], [2, 2, 2, 2]])
    engine._model = model
    engine.trained = True
    version = registry.register('isolation_forest', model,
                                metrics={'contamination': 0.02},
                                features=['duration', 'total_bytes', 'total_packets', 'byte_ratio'],
                                notes='pytest')
    registry.set_stage('isolation_forest', version, 'active')
    if tamper:
        # Corrupt the stored model file so its sha256 no longer matches the signature
        d = os.path.join(str(tmp_path / "models"), 'isolation_forest', str(version))
        with open(os.path.join(d, 'model.joblib'), 'ab') as handle:
            handle.write(b"tamper")
    return version


def test_signed_model_verifies_and_loads(tmp_path, monkeypatch):
    version = _write_registry_model(tmp_path, monkeypatch)
    engine = MLEngine()
    assert engine.trained is True

    meta = registry.verify('isolation_forest', version)
    assert meta['name'] == 'isolation_forest'
    assert meta['version'] == version


def test_tampered_model_is_refused(tmp_path, monkeypatch):
    _write_registry_model(tmp_path, monkeypatch, tamper=True)
    # A fresh engine cannot load a tampered active model; it falls back to untrained
    engine = MLEngine()
    assert engine.trained is False


def test_unsigned_model_is_refused_in_strict_mode(tmp_path, monkeypatch):
    # No model in the registry at all, strict mode -> untrained (no crash, no unsigned load)
    monkeypatch.setenv("SENTINEL_MODEL_REGISTRY", str(tmp_path / "models"))
    monkeypatch.delenv("SENTINEL_ALLOW_UNSIGNED_MODELS", raising=False)
    engine = MLEngine()
    assert engine.trained is False


def test_unsigned_dev_override_starts_untrained(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_MODEL_REGISTRY", str(tmp_path / "models"))
    monkeypatch.setenv("SENTINEL_ALLOW_UNSIGNED_MODELS", "1")
    engine = MLEngine()
    assert engine.trained is False


def test_predict_returns_0_when_untrained(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_MODEL_REGISTRY", str(tmp_path / "models"))
    engine = MLEngine()
    features = {'duration': 1.0, 'total_bytes': 100, 'total_packets': 10, 'byte_ratio': 1.0}
    assert engine.predict(features) == 0
