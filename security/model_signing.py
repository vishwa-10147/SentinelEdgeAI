"""Ed25519 signatures for the release model artifacts (model/*.pkl).

Devices and CI hold only the public key (security/release_model.pub, shipped
in every package); the private key never leaves the maintainer's machine.
A signature file `<model>.sig` is a JSON document:

    {"version": 2, "algorithm": "ed25519", "model": "isolation_forest.pkl",
     "sha256": "...", "signed_at": 1793..., "signer": "...", "kid": "<key id>",
     "signature": "<base64 Ed25519 over the canonical JSON of every other field>"}

Up to v2.16 the release model carried an HMAC-SHA256 signature, which meant
every device and CI job needed the secret key; those (version 1) signatures
are refused.

    python scripts/sign_model.py --generate-key ~/.sentinel/release_model.key   # once, offline
    SENTINEL_MODEL_SIGNING_KEY_FILE=~/.sentinel/release_model.key python scripts/sign_model.py model/isolation_forest.pkl
    python scripts/sign_model.py model/isolation_forest.pkl --verify
"""
import base64
import hashlib
import json
import os
import time
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SIGNATURE_VERSION = 2
ALGORITHM = "ed25519"
DEFAULT_KEY_ENV = "SENTINEL_MODEL_SIGNING_KEY"                 # private key PEM (signing only)
DEFAULT_KEY_FILE_ENV = "SENTINEL_MODEL_SIGNING_KEY_FILE"       # path to the private key PEM (signing only)
PUBLIC_KEY_FILE_ENV = "SENTINEL_MODEL_PUBLIC_KEY_FILE"          # override of the shipped public key
PUBLIC_KEY_FILE = Path(__file__).resolve().parent / "release_model.pub"


class ModelSignatureError(RuntimeError):
    pass


def signature_path(model_path):
    return Path(f"{model_path}.sig")


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical(document):
    body = {k: v for k, v in document.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def key_id(public_pem):
    return hashlib.sha256(public_pem.strip().encode("ascii")).hexdigest()[:16]


def generate_keypair():
    """(private_pem, public_pem) for a new release signing key."""
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode("ascii")
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    return private, public


def load_signing_key(required=True):
    """The private key PEM from the environment (only the maintainer's signing machine has it)."""
    key = os.environ.get(DEFAULT_KEY_ENV)
    key_file = os.environ.get(DEFAULT_KEY_FILE_ENV)
    if key_file:
        try:
            key = Path(key_file).expanduser().read_text(encoding="utf-8")
        except OSError as exc:
            raise ModelSignatureError(f"failed to read model signing key file: {key_file}") from exc
    if not key:
        if required:
            raise ModelSignatureError(f"missing model signing key; set {DEFAULT_KEY_FILE_ENV} to the Ed25519 "
                                      "private key (scripts/sign_model.py --generate-key creates one)")
        return None
    return key


def load_public_key(path=None):
    path = Path(path or os.environ.get(PUBLIC_KEY_FILE_ENV) or PUBLIC_KEY_FILE)
    try:
        return path.read_text(encoding="ascii")
    except OSError as exc:
        raise ModelSignatureError(f"model public key not found: {path}") from exc


def _private(pem):
    try:
        key = serialization.load_pem_private_key(pem.encode("ascii"), None)
    except (ValueError, TypeError) as exc:
        raise ModelSignatureError("model signing key is not a PEM private key (an old HMAC key?)") from exc
    if not isinstance(key, Ed25519PrivateKey):
        raise ModelSignatureError("model signing key is not an Ed25519 key")
    return key


def _public(pem):
    try:
        key = serialization.load_pem_public_key(pem.encode("ascii"))
    except (ValueError, TypeError) as exc:
        raise ModelSignatureError("model public key is not a PEM public key") from exc
    if not isinstance(key, Ed25519PublicKey):
        raise ModelSignatureError("model public key is not an Ed25519 key")
    return key


def sign_model(model_path, key=None, signer="local"):
    """Sign `model_path` with the Ed25519 private key PEM `key` (default: from the environment)."""
    model_path = Path(model_path)
    if not model_path.exists():
        raise ModelSignatureError(f"model not found: {model_path}")
    private = _private(key or load_signing_key(required=True))
    public_pem = private.public_key().public_bytes(serialization.Encoding.PEM,
                                                   serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    document = {
        "version": SIGNATURE_VERSION,
        "algorithm": ALGORITHM,
        "model": model_path.name,
        "sha256": file_sha256(model_path),
        "signed_at": int(time.time()),
        "signer": signer,
        "kid": key_id(public_pem),
    }
    document["signature"] = base64.b64encode(private.sign(_canonical(document))).decode("ascii")
    signature_path(model_path).write_text(json.dumps(document, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return document


def verify_model_signature(model_path, public_key=None):
    """Return the signature document if `model_path` is signed by the release key, else raise."""
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
    if not isinstance(document, dict):
        raise ModelSignatureError(f"invalid model signature file: {sig_path}")
    if document.get("version") != SIGNATURE_VERSION or document.get("algorithm") != ALGORITHM:
        raise ModelSignatureError("unsupported model signature (only version 2, Ed25519, is accepted)")
    if document.get("model") != model_path.name:
        raise ModelSignatureError("signature is for a different model file")
    public_pem = public_key or load_public_key()
    if document.get("kid") != key_id(public_pem):
        raise ModelSignatureError("model was signed with a different key")
    if document.get("sha256") != file_sha256(model_path):
        raise ModelSignatureError("model sha256 does not match signature metadata")
    try:
        signature = base64.b64decode(document.get("signature", ""), validate=True)
        _public(public_pem).verify(signature, _canonical(document))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ModelSignatureError("model signature verification failed") from exc
    return document
