"""High availability for the brain: active/standby pairs (Phase 7).

Two brains share
  - their key material (CA and command signing key), moved once in an encrypted
    pairing bundle, so sensor certificates and command signatures work on both
  - their state, by pointing both at the same PostgreSQL (SENTINEL_BRAIN_DATABASE_URL)
Both accept flows, health and command polls from sensors at any time (the state is
shared), and sensors fail over between them on their own (`python -m sensor add-brain`).
Only the *active* brain issues new commands: it holds a lease in the shared database
and renews it every few seconds; when it stops, the standby takes the lease within
LEASE_TTL seconds. A single brain on SQLite is always active.
"""
import json
import os
import secrets
import socket
import threading

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from brain import keys

LEASE = 'brain-leader'
LEASE_TTL = 30
RENEW_EVERY = 10
MAGIC = b'SEHA1\n'
SHARED = ('ca.key', 'ca.pem', 'signing.key', 'signing.pub')


def instance_id():
    """This brain's stable identity in the lease (hostname + a random id kept in the brain directory)."""
    path = keys.path('instance')
    try:
        with open(path, 'r', encoding='ascii') as f:
            return f.read().strip()
    except OSError:
        os.makedirs(keys.brain_dir(), mode=0o700, exist_ok=True)
        ident = f'{socket.gethostname()}-{secrets.token_hex(4)}'
        with open(path, 'w', encoding='ascii') as f:
            f.write(ident)
        return ident


def renew(store):
    """Take or renew the leader lease. True if this brain is active."""
    return store.acquire_lease(LEASE, instance_id(), LEASE_TTL)


def role(store):
    """'active' or 'standby' (and renews the lease when this brain holds it or it has lapsed)."""
    return 'active' if renew(store) else 'standby'


def status(store):
    lease = store.lease(LEASE) or {}
    me = instance_id()
    return {'instance': me, 'role': 'active' if lease.get('holder') == me else 'standby',
            'active': lease.get('holder'), 'lease_expires': lease.get('expires'),
            'shared_database': bool(getattr(store, 'url', None))}


def start_renewal(store, stop=None):
    """Keep the lease while this brain runs (a daemon thread)."""
    stop = stop or threading.Event()

    def loop():
        while not stop.is_set():
            try:
                renew(store)
            except Exception:
                pass
            stop.wait(RENEW_EVERY)
    threading.Thread(target=loop, daemon=True, name='brain-lease').start()
    return stop


def _key(passphrase, salt):
    from ops.backup import _key as derive
    return derive(passphrase, salt)


def export_bundle(out_path, passphrase):
    """Write the shared key material, encrypted with `passphrase` (scrypt + AES-256-GCM)."""
    material = {name: keys.read(name) for name in SHARED}
    salt, nonce = os.urandom(16), os.urandom(12)
    sealed = AESGCM(_key(passphrase, salt)).encrypt(nonce, json.dumps(material).encode(), MAGIC)
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(MAGIC + salt + nonce + sealed)
    return {'file': out_path, 'ca_fingerprint': keys.ca_fingerprint()}


def import_bundle(path, passphrase, force=False):
    """Install a partner brain's key material here; this brain gets its own server certificate."""
    with open(path, 'rb') as f:
        blob = f.read()
    if not blob.startswith(MAGIC):
        raise ValueError('not a SentinelEdgeAI brain pairing bundle')
    salt, nonce, sealed = blob[len(MAGIC):len(MAGIC) + 16], blob[len(MAGIC) + 16:len(MAGIC) + 28], blob[len(MAGIC) + 28:]
    try:
        material = json.loads(AESGCM(_key(passphrase, salt)).decrypt(nonce, sealed, MAGIC))
    except InvalidTag:
        raise ValueError('wrong passphrase or damaged bundle')
    if os.path.exists(keys.path('ca.pem')) and not force:
        from common import pki
        if pki.fingerprint(keys.read('ca.pem')) != pki.fingerprint(material['ca.pem']):
            raise ValueError('this brain already has a different CA; its sensors would stop working (use --force)')
    os.makedirs(keys.brain_dir(), mode=0o700, exist_ok=True)
    for name in SHARED:
        fd = os.open(keys.path(name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if name.endswith('.key') else 0o644)
        with os.fdopen(fd, 'w', encoding='ascii') as f:
            f.write(material[name])
    for name in ('server.key', 'server.pem'):            # a new server certificate for this host, from the shared CA
        try:
            os.remove(keys.path(name))
        except OSError:
            pass
    keys.init()
    return {'ca_fingerprint': keys.ca_fingerprint()}
