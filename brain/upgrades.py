"""Sensor upgrades distributed by the brain (Phase 2).

Sensors often have no internet access. The brain stages one verified release
package (from a local file, or downloaded from the GitHub release) in
data/brain/releases/ and offers it to its sensors over the mutual-TLS link
(GET /v1/upgrade, GET /v1/upgrade/package). A sensor downloads it, checks
the SHA-256 the brain announced, and stages it for the root update timer
(`sentinelctl fleet-update`), which installs it with the usual health check
and automatic rollback.
"""
import hashlib
import json
import os
import re
import shutil
import tempfile

import core.audit as audit
from brain import keys

VERSION = re.compile(r'^\d+\.\d+\.\d+$')
RELEASE_URL = 'https://github.com/vishwa-10147/SentinelEdgeAI/releases/download/v{v}/sentineledgeai-pi-{v}.tar.gz'


def releases_dir():
    return os.path.join(keys.brain_dir(), 'releases')


def _target_file():
    return os.path.join(releases_dir(), 'target.json')


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def target():
    """{'version', 'sha256', 'size', 'file'} of the staged release, or None."""
    try:
        with open(_target_file(), 'r', encoding='utf-8') as f:
            t = json.load(f)
    except (OSError, ValueError):
        return None
    return t if os.path.exists(os.path.join(releases_dir(), t.get('file', ''))) else None


def _expected_sha(sha_text, name):
    for line in sha_text.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].lstrip('*') == name:
            return parts[0].lower()
    parts = sha_text.split()
    return parts[0].lower() if parts else None


def stage_file(path, sha256_path=None, by='cli'):
    """Stage a local package; its .sha256 (next to it by default) must match."""
    name = os.path.basename(path)
    m = re.match(r'^sentineledgeai-pi-(\d+\.\d+\.\d+)\.tar\.gz$', name)
    if not m:
        raise ValueError('expected a package named sentineledgeai-pi-X.Y.Z.tar.gz')
    with open(sha256_path or path + '.sha256', 'r', encoding='utf-8') as f:
        expected = _expected_sha(f.read(), name)
    actual = sha256_file(path)
    if expected != actual:
        raise ValueError('checksum mismatch; refusing to stage this package')
    os.makedirs(releases_dir(), mode=0o750, exist_ok=True)
    dest = os.path.join(releases_dir(), name)
    if os.path.abspath(path) != os.path.abspath(dest):
        shutil.copyfile(path, dest + '.tmp')
        os.replace(dest + '.tmp', dest)
    t = {'version': m.group(1), 'sha256': actual, 'size': os.path.getsize(dest), 'file': name}
    tmp = _target_file() + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(t, f, indent=2)
    os.replace(tmp, _target_file())
    for old in os.listdir(releases_dir()):                 # keep only the staged release
        if old.endswith('.tar.gz') and old != name:
            os.remove(os.path.join(releases_dir(), old))
    audit.record('sensor_upgrade_stage', actor=by, target=t['version'], details={'sha256': actual})
    return t


def stage_release(version, by='cli', session=None, url_template=RELEASE_URL):
    """Download a published release and its checksum, then stage it."""
    import requests
    if not VERSION.match(str(version)):
        raise ValueError('version must look like 2.4.1')
    session = session or requests
    url = url_template.format(v=version)
    work = tempfile.mkdtemp(prefix='sentinel-release-')
    try:
        pkg = os.path.join(work, os.path.basename(url))
        for src, dst in ((url, pkg), (url + '.sha256', pkg + '.sha256')):
            r = session.get(src, timeout=600, stream=True)
            if r.status_code != 200:
                raise ValueError(f'could not download {src} (HTTP {r.status_code})')
            with open(dst, 'wb') as f:
                for chunk in r.iter_content(1 << 20):
                    f.write(chunk)
        return stage_file(pkg, by=by)
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
    return {'version': t['version'], 'sha256': t['sha256'], 'size': t['size']}
