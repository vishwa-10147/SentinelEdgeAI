"""Ed25519 signatures for brain-to-sensor commands.

A command is a JSON object signed over its canonical encoding (sorted keys,
no whitespace). The sensor checks the signature with the brain's public key
it received at enrolment, then the sequence number and expiry.
"""
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


class SignatureError(ValueError):
    pass


def generate_keypair():
    """Return (private_pem, public_pem)."""
    key = Ed25519PrivateKey.generate()
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption()).decode('ascii')
    public = key.public_key().public_bytes(serialization.Encoding.PEM,
                                           serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')
    return private, public


def canonical(payload):
    return json.dumps(payload, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode('ascii')


def key_id(public_pem):
    """Short id of a public key, carried in envelopes so key rotation is visible."""
    return hashlib.sha256(public_pem.strip().encode('ascii')).hexdigest()[:16]


def sign(private_pem, payload, public_pem=None):
    key = serialization.load_pem_private_key(private_pem.encode('ascii'), None)
    if not isinstance(key, Ed25519PrivateKey):
        raise SignatureError('not an Ed25519 private key')
    envelope = {'payload': payload, 'sig': base64.b64encode(key.sign(canonical(payload))).decode('ascii')}
    if public_pem:
        envelope['kid'] = key_id(public_pem)
    return envelope


def verify(public_pem, envelope):
    """Return the payload if the signature is valid, else raise SignatureError."""
    if not isinstance(envelope, dict) or not isinstance(envelope.get('payload'), dict):
        raise SignatureError('malformed envelope')
    key = serialization.load_pem_public_key(public_pem.encode('ascii'))
    if not isinstance(key, Ed25519PublicKey):
        raise SignatureError('not an Ed25519 public key')
    try:
        signature = base64.b64decode(envelope.get('sig', ''), validate=True)
        key.verify(signature, canonical(envelope['payload']))
    except (InvalidSignature, ValueError, TypeError):
        raise SignatureError('signature verification failed')
    return envelope['payload']
