"""Run the API and console, over HTTPS when a certificate is configured.

    python -m dashboard.serve

SENTINEL_HOST / SENTINEL_PORT choose the address (default 127.0.0.1:9000).
SENTINEL_TLS_CERT and SENTINEL_TLS_KEY (PEM files) turn on HTTPS; sentinelctl
creates a certificate for the device at install. Leave both empty for plain
HTTP, e.g. behind a reverse proxy that terminates TLS.
"""
import os
import sys


class TLSConfigError(RuntimeError):
    pass


def tls_files(env=None):
    """Return (cert, key) when HTTPS is configured, None for plain HTTP."""
    env = os.environ if env is None else env
    cert = (env.get('SENTINEL_TLS_CERT') or '').strip()
    key = (env.get('SENTINEL_TLS_KEY') or '').strip()
    if not cert and not key:
        return None
    if not cert or not key:
        # refuse to fall back to plain HTTP when HTTPS was half configured
        raise TLSConfigError('set both SENTINEL_TLS_CERT and SENTINEL_TLS_KEY, or neither')
    for name, path in (('SENTINEL_TLS_CERT', cert), ('SENTINEL_TLS_KEY', key)):
        if not os.path.isfile(path):
            raise TLSConfigError(f'{name} file not found: {path}')
        if not os.access(path, os.R_OK):
            raise TLSConfigError(f'{name} file not readable: {path}')
    return cert, key


def uvicorn_options(env=None):
    env = os.environ if env is None else env
    options = {
        'host': env.get('SENTINEL_HOST', '127.0.0.1'),
        'port': int(env.get('SENTINEL_PORT', '9000')),
    }
    files = tls_files(env)
    if files:
        options['ssl_certfile'], options['ssl_keyfile'] = files
    return options


def main():
    import uvicorn

    try:
        options = uvicorn_options()
    except (TLSConfigError, ValueError) as exc:
        print(f'sentineledgeai: {exc}', file=sys.stderr)
        return 2
    scheme = 'https' if 'ssl_certfile' in options else 'http'
    print(f"sentineledgeai: serving {scheme}://{options['host']}:{options['port']}", flush=True)
    uvicorn.run('dashboard.dashboard_api:app', **options)
    return 0


if __name__ == '__main__':
    sys.exit(main())
