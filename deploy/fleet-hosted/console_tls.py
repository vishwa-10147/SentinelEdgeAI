"""First start of the hosted console: a self-signed HTTPS certificate unless one is already there.

Replace data/console-tls/cert.pem and key.pem with your own certificate (or put a reverse proxy in front).
"""
import os
import sys

sys.path.insert(0, '/app')
from common import pki  # noqa: E402

d = '/app/data/console-tls'
os.makedirs(d, mode=0o700, exist_ok=True)
if not os.path.exists(os.path.join(d, 'cert.pem')):
    name = os.environ.get('FLEET_HOSTNAME') or 'localhost'
    ca_key, ca = pki.generate_ca('SentinelEdgeAI hosted console')
    key, cert = pki.issue_server_cert(ca_key, ca, [name, 'localhost'], ['127.0.0.1'])
    for fname, text, mode in (('key.pem', key, 0o600), ('cert.pem', cert + ca, 0o644)):
        fd = os.open(os.path.join(d, fname), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with os.fdopen(fd, 'w') as f:
            f.write(text)
    print(f'console certificate created for {name}; SHA-256 {pki.fingerprint(cert)}')
