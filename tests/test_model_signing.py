import joblib
import pytest
from sklearn.ensemble import IsolationForest

from detection.ml_engine import MLEngine
from security.model_signing import ModelSignatureError, sign_model, verify_model_signature


def _write_model(path):
    model = IsolationForest(n_estimators=1, random_state=42)
    model.fit([[0, 0, 0, 0], [1, 1, 1, 1], [2, 2, 2, 2]])
    joblib.dump(model, path)


def test_signed_model_verifies_and_loads(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_MODEL_SIGNING_KEY", "test-signing-key")
    path = tmp_path / "model.pkl"
    _write_model(path)
    sign_model(path, signer="pytest")

    signature = verify_model_signature(path)
    engine = MLEngine(model_path=str(path))

    assert signature["signer"] == "pytest"
    assert engine.trained is True


def test_unsigned_existing_model_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_MODEL_SIGNING_KEY", "test-signing-key")
    path = tmp_path / "model.pkl"
    _write_model(path)

    with pytest.raises(ModelSignatureError, match="signature not found"):
        MLEngine(model_path=str(path))


def test_tampered_model_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_MODEL_SIGNING_KEY", "test-signing-key")
    path = tmp_path / "model.pkl"
    _write_model(path)
    sign_model(path, signer="pytest")
    with open(path, "ab") as handle:
        handle.write(b"tamper")

    with pytest.raises(ModelSignatureError, match="sha256"):
        MLEngine(model_path=str(path))


def test_unsigned_dev_override_loads(tmp_path, monkeypatch):
    monkeypatch.delenv("SENTINEL_MODEL_SIGNING_KEY", raising=False)
    monkeypatch.setenv("SENTINEL_ALLOW_UNSIGNED_MODELS", "1")
    path = tmp_path / "model.pkl"
    _write_model(path)

    engine = MLEngine(model_path=str(path))

    assert engine.trained is True
