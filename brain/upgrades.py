"""Sensor upgrades distributed by the brain (Phase 2), with signed update channels (Phase 8).

Sensors often have no internet access. The brain stages one verified release
package (from a local file, or downloaded from a GitHub release channel) in
data/brain/releases/ and offers it to its sensors over the mutual-TLS link
(GET /v1/upgrade, GET /v1/upgrade/package). A sensor downloads it, checks
the SHA-256 the brain announced, and (when SENTINEL_REQUIRE_SIGNATURE=1)
verifies the Ed25519 signature before staging it for the root update timer
(`sentinelctl fleet-update`), which installs it with the usual health check
and automatic rollback.

Channels:
  stable  -> v{v} tag (production releases)
  beta    -> v{v}-beta tag (pre-release channel)
"""
import hashlib
import json
import os
import re
import shutil
import tempfile

import core.audit as audit
from brain import keys
from common import signing

VERSION = re.compile(r'^\d+\.\d+\.\d+$')
RELEASE_URL = ('https://github.com/vishwa-10147/SentinelEdgeAI/releases/download/'
               '{channel}/sentineledgeai-pi-{version}.tar.gz')
CHANNELS = {'stable': 'v{version}', 'beta': 'v{version}-beta'}


def releases_dir():
    return os.path.join(keys.brain_dir(), 'releases')


def _target_file():
    return os.path.join(releases_dir(), 'target.json')


def target():
    """{'version', 'sha256', 'size', 'file'} of the staged release, or None."""
    try:
        with open(_target_file(), 'r', encoding='utf-8') as f:
            t = json.load(f)
    except (OSError, ValueError):
        return None
    return t if os.path.exists(os.path.join(releases_dir(), t.get('file', ''))) else None


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _update_signing_key():
    """The Ed25519 public key used to verify update signatures, or None."""
    key_file = os.environ.get('SENTINEL_UPDATE_SIGNING_KEY_FILE')
    if key_file:
        try:
            with open(key_file, 'r', encoding='ascii') as f:
                return f.read()
        except OSError:
            return None
    # Fall back to the brain's command-signing public key.
    try:
        return keys.read('signing.pub')
    except OSError:
        return None


def require_signature():
    return os.environ.get('SENTINEL_REQUIRE_SIGNATURE', '0') == '1'


def _verify_signature(pkg_path, sig_path):
    """Verify an Ed25519 signature over the package's sha256.

    Signature file format:
        {"algorithm": "ed25519", "sha256": "...", "signature": "base64"}
    """
    public = _update_signing_key()
    if not public:
        raise ValueError('no update signing public key available; cannot verify signature')
    try:
        with open(sig_path, 'r', encoding='utf-8') as f:
            envelope = json.load(f)
    except (OSError, ValueError) as exc:
        raise ValueError(f'invalid signature file: {exc}')

    if envelope.get('algorithm') != 'ed25519':
        raise ValueError(f'unsupported signature algorithm: {envelope.get("algorithm")}')

    digest = sha256_file(pkg_path)
    if envelope.get('sha256') != digest:
        raise ValueError('signature sha256 does not match package')

    import base64
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

    try:
        key = serialization.load_pem_public_key(public.encode('ascii'))
        if not isinstance(key, Ed25519PublicKey):
            raise ValueError('update signing key is not an Ed25519 public key')
        signature = base64.b64decode(envelope.get('signature', ''), validate=True)
        key.verify(signature, digest.encode('ascii'))
    except (InvalidSignature, ValueError, TypeError) as exc:
        raise ValueError(f'update signature verification failed: {exc}')
    return digest


def _expected_sha(sha_text, name):
    for line in sha_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].lstrip('*') == name:
            return parts[0].lower()
    parts = sha_text.split()
    return parts[0].lower() if parts else None


def stage_file(path, sha256_path=None, sig_path=None, by='cli'):
    """Stage a local package; its .sha256 must match, and its .sig (when
    SENTINEL_REQUIRE_SIGNATURE=1) must verify against the update signing key."""
    name = os.path.basename(path)
    m = re.match(r'^sentineledgeai-pi-(\d+\.\d+\.\d+)\.tar\.gz$', name)
    if not m:
        raise ValueError('expected a package named sentineledgeai-pi-X.Y.Z.tar.gz')
    with open(sha256_path or path + '.sha256', 'r', encoding='utf-8') as f:
        expected = _expected_sha(f.read(), name)
    actual = sha256_file(path)
    if expected != actual:
        raise ValueError('checksum mismatch; refusing to stage this package')
    if require_signature():
        sig = sig_path or path + '.sig'
        _verify_signature(path, sig)
    os.makedirs(releases_dir(), mode=0o750, exist_ok=True)
    dest = os.path.join(releases_dir(), name)
    if os.path.abspath(path) != os.path.abspath(dest):
        shutil.copyfile(path, dest + '.tmp')
        os.replace(dest + '.tmp', dest)
    t = {'version': m.group(1), 'sha256': actual, 'size': os.path.getsize(dest), 'file': name,
         'signed': require_signature()}
    tmp = _target_file() + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(t, f, indent=2)
    os.replace(tmp, _target_file())
    for old in os.listdir(releases_dir()):                 # keep only the staged release
        if old.endswith('.tar.gz') and old != name:
            os.remove(os.path.join(releases_dir(), old))
    audit.record('sensor_upgrade_stage', actor=by, target=t['version'],
                 details={'sha256': actual, 'signed': t['signed']})
    return t


def _channel_url(channel, version):
    template = CHANNELS.get(channel)
    if template is None:
        raise ValueError(f'unknown channel {channel!r}; use one of {sorted(CHANNELS)}')
    tag = template.format(version=version)
    return RELEASE_URL.format(channel=tag, version=version)


def stage_release(version, channel='stable', by='cli', session=None, url_template=None):
    """Download a published release from a channel and its checksum, then stage it.

    When SENTINEL_REQUIRE_SIGNATURE=1, the release's .sig attachment is also
    downloaded and verified before staging.
    """
    import requests
    if not VERSION.match(str(version)):
        raise ValueError('version must look like 2.4.1')
    session = session or requests
    if url_template is None:
        url = _channel_url(channel, version)
    else:
        url = url_template.format(channel=channel, version=version)
    name = f'sentineledgeai-pi-{version}.tar.gz'
    work = tempfile.mkdtemp(prefix='sentinel-release-')
    try:
        pkg = os.path.join(work, name)
        for src, dst in ((url, pkg), (url + '.sha256', pkg + '.sha256')):
            r = session.get(src, timeout=600, stream=True)
            if r.status_code != 200:
                raise ValueError(f'could not download {src} (HTTP {r.status_code})')
            with open(dst, 'wb') as f:
                for chunk in r.iter_content(1 << 20):
                    f.write(chunk)
        if require_signature():
            sig_url = url + '.sig'
            sig_path = pkg + '.sig'
            r = session.get(sig_url, timeout=600, stream=True)
            if r.status_code != 200:
                raise ValueError(f'could not download signature {sig_url} (HTTP {r.status_code})')
            with open(sig_path, 'wb') as f:
                for chunk in r.iter_content(1 << 20):
                    f.write(chunk)
            return stage_file(pkg, pkg + '.sha256', sig_path, by=by)
        return stage_file(pkg, pkg + '.sha256', by=by)
    finally:
        shutil.rmtree(work, ignore_errors=True)


def clear(by='cli'):
    try:
        os.remove(_target_file())
    except OSError:
        pass
    audit.record('sensor_upgrade_clear', actor=by)


def offer(sensor_version):
    """What GET /v1/upgrade tells a sensor running `sensor_version`."""
    t = target()
    if not t or t['version'] == sensor_version:
        return {'version': None}
    return {'version': t['version'], 'sha256': t['sha256'], 'size': t['size'],
            'signed': t.get('signed', False)}
