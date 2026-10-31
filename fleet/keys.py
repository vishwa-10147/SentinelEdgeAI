"""The fleet server's key material: its own CA and site-facing server certificate.

Kept in SENTINEL_FLEET_DIR (default data/fleet), private keys mode 600. Separate
from the brain CA, so a site certificate can never act as a sensor and back.
"""
import os

from brain.keys import local_names
from common import pki

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
FILES = ('ca.key', 'ca.pem', 'server.key', 'server.pem')


def fleet_dir():
    return os.environ.get('SENTINEL_FLEET_DIR') or os.path.join(ROOT, 'data', 'fleet')


def path(name):
    return os.path.join(fleet_dir(), name)


def _write(name, text, private):
    fd = os.open(path(name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, 'w', encoding='ascii') as f:
        f.write(text)


def read(name):
    with open(path(name), 'r', encoding='ascii') as f:
        return f.read()


def marker():
    # a systemd path unit starts the fleet server when this file exists
    return path('enabled')


def enabled():
    return os.path.exists(marker())


def init(hostnames=None, ips=None):
    """Create any missing key material and mark this device as a fleet server. True if keys were created."""
    os.makedirs(fleet_dir(), mode=0o700, exist_ok=True)
    created = False
    if not (os.path.exists(path('ca.key')) and os.path.exists(path('ca.pem'))):
        key, cert = pki.generate_ca('SentinelEdgeAI fleet CA')
        _write('ca.key', key, True)
        _write('ca.pem', cert, False)
        created = True
    if created or not os.path.exists(path('server.pem')):
        default_names, default_ips = local_names()
        key, cert = pki.issue_server_cert(read('ca.key'), read('ca.pem'), hostnames or default_names, ips or default_ips)
        _write('server.key', key, True)
        _write('server.pem', cert, False)
        created = True
    open(marker(), 'a').close()
    return created


def ca_fingerprint():
    return pki.fingerprint(read('ca.pem'))
