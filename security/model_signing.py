import base64
import hashlib
import hmac
import json
import os
import time
from pathlib import Path


SIGNATURE_VERSION = 1
DEFAULT_KEY_ENV = "SENTINEL_MODEL_SIGNING_KEY"
DEFAULT_KEY_FILE_ENV = "SENTINEL_MODEL_SIGNING_KEY_FILE"


class ModelSignatureError(RuntimeError):
    pass


def signature_path(model_path):
    return Path(f"{model_path}.sig")


def load_signing_key(required=True):
    key = os.environ.get(DEFAULT_KEY_ENV)
    key_file = os.environ.get(DEFAULT_KEY_FILE_ENV)
    if key_file:
        try:
            key = Path(key_file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            raise ModelSignatureError(f"failed to read model signing key file: {key_file}") from exc
    if not key:
        if required:
            raise ModelSignatureError(
                f"missing model signing key; set {DEFAULT_KEY_ENV} or {DEFAULT_KEY_FILE_ENV}"
            )
        return None
    return key.encode("utf-8")


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _model_hmac(model_path, key):
    digest = hmac.new(key, digestmod=hashlib.sha256)
    with open(model_path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return base64.b64encode(digest.digest()).decode("ascii")


def sign_model(model_path, key=None, signer="local"):
    model_path = Path(model_path)
    if not model_path.exists():
        raise ModelSignatureError(f"model not found: {model_path}")
    key = key or load_signing_key(required=True)
    document = {
        "version": SIGNATURE_VERSION,
        "algorithm": "hmac-sha256",
        "model": model_path.name,
        "sha256": file_sha256(model_path),
        "signature": _model_hmac(model_path, key),
        "signed_at": int(time.time()),
        "signer": signer,
    }
    sig_path = signature_path(model_path)
    sig_path.write_text(json.dumps(document, indent=2, sort_keys=True), encoding="utf-8")
    return document


def verify_model_signature(model_path, key=None):
    model_path = Path(model_path)
    if not model_path.exists():
        raise ModelSignatureError(f"model not found: {model_path}")
    sig_path = signature_path(model_path)
    if not sig_path.exists():
        raise ModelSignatureError(f"model signature not found: {sig_path}")

    try:
        document = json.loads(sig_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ModelSignatureError(f"invalid model signature file: {sig_path}") from exc

    if document.get("version") != SIGNATURE_VERSION:
        raise ModelSignatureError("unsupported model signature version")
    if document.get("algorithm") != "hmac-sha256":
        raise ModelSignatureError("unsupported model signature algorithm")
    if document.get("sha256") != file_sha256(model_path):
        raise ModelSignatureError("model sha256 does not match signature metadata")

    key = key or load_signing_key(required=True)
    expected = _model_hmac(model_path, key)
    actual = document.get("signature", "")
    if not hmac.compare_digest(expected, actual):
        raise ModelSignatureError("model signature verification failed")
    return document
