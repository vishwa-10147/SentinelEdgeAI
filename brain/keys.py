"""The brain's key material: CA, sensor-facing server certificate, command signing key.

Kept in SENTINEL_BRAIN_DIR (default data/brain), private keys mode 600.
"""
import os
import socket

import psutil

from common import pki, signing

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
FILES = ('ca.key', 'ca.pem', 'server.key', 'server.pem', 'signing.key', 'signing.pub')


def brain_dir():
    return os.environ.get('SENTINEL_BRAIN_DIR') or os.path.join(ROOT, 'data', 'brain')


def path(name):
    return os.path.join(brain_dir(), name)


def _write(name, text, private):
    p = path(name)
    fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, 'w', encoding='ascii') as f:
        f.write(text)


def read(name):
    with open(path(name), 'r', encoding='ascii') as f:
        return f.read()


def initialised():
    return all(os.path.exists(path(n)) for n in FILES)


def local_names():
    host = socket.gethostname()
    names = [host, f'{host}.local', 'localhost']
    ips = ['127.0.0.1']
    for addrs in psutil.net_if_addrs().values():
        for a in addrs:
            if a.family == socket.AF_INET and not a.address.startswith('127.') and a.address not in ips:
                ips.append(a.address)
    return names, ips


def init(hostnames=None, ips=None):
    """Create any missing key material. Returns True if something was created."""
    os.makedirs(brain_dir(), mode=0o700, exist_ok=True)
    created = False
    if not (os.path.exists(path('ca.key')) and os.path.exists(path('ca.pem'))):
        key, cert = pki.generate_ca()
        _write('ca.key', key, True)
        _write('ca.pem', cert, False)
        created = True
    if created or not os.path.exists(path('server.pem')):
        default_names, default_ips = local_names()
        key, cert = pki.issue_server_cert(read('ca.key'), read('ca.pem'),
                                          hostnames or default_names, ips or default_ips)
        _write('server.key', key, True)
        _write('server.pem', cert, False)
        created = True
    if not os.path.exists(path('signing.key')):
        private, public = signing.generate_keypair()
        _write('signing.key', private, True)
        _write('signing.pub', public, False)
        created = True
    return created


def ca_fingerprint():
    return pki.fingerprint(read('ca.pem'))
