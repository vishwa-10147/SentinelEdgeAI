"""Extension packages: manifest, Ed25519 signature over every file, trusted publishers, installation.

A package is a directory (or a .tar.gz of one) with:
    manifest.json    {"name": "rare-port-fanout", "version": "1.0.0", "publisher": "Example Co",
                      "kind": "detector" | "action", "entry": "main.py", "events": ["flow", "dns", "http"],
                      "network": false, "memory_mb": 128, "description": "..."}
    main.py ...      the code (standard library + sentinel_sdk only)
    signature.json   written by `python -m extensions sign`: Ed25519 over the manifest and the SHA-256 of
                     every other file, with the publisher key id

`python -m extensions trust <publisher-name> publisher.pub` pins a publisher key (Admin). Installing
verifies the signature with a pinned key and that every file matches; an extension asking for network is
refused unless `--allow-network` is given. Installed extensions live in data/extensions/<name>/
(SENTINEL_EXTENSIONS_DIR) and start disabled.
"""
import hashlib
import json
import os
import re
import shutil
import tarfile
import tempfile
import time

from common import signing

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
NAME_RE = re.compile(r'^[a-z0-9][a-z0-9-]{1,40}$')
KINDS = ('detector', 'action')
EVENTS = ('flow', 'dns', 'http', 'action')
MAX_FILES, MAX_BYTES = 200, 5 * 1024 * 1024


class ExtensionError(ValueError):
    pass


def base_dir():
    return os.environ.get('SENTINEL_EXTENSIONS_DIR') or os.path.join(ROOT, 'data', 'extensions')


def _path(*parts):
    return os.path.join(base_dir(), *parts)


def validate_manifest(m):
    if not isinstance(m, dict):
        raise ExtensionError('manifest.json must be an object')
    if not NAME_RE.match(str(m.get('name', ''))):
        raise ExtensionError('name: 2-41 lowercase letters, digits and dashes')
    if not re.match(r'^\d+\.\d+\.\d+$', str(m.get('version', ''))):
        raise ExtensionError('version must look like 1.0.0')
    if not m.get('publisher'):
        raise ExtensionError('publisher is required')
    if m.get('kind') not in KINDS:
        raise ExtensionError(f'kind must be one of {", ".join(KINDS)}')
    entry = str(m.get('entry', 'main.py'))
    if '/' in entry or '..' in entry or not entry.endswith('.py'):
        raise ExtensionError('entry must be a .py file at the top of the package')
    events = m.get('events') or (['action'] if m['kind'] == 'action' else ['flow'])
    if not set(events) <= set(EVENTS) or ('action' in events) != (m['kind'] == 'action'):
        raise ExtensionError('events: flow, dns, http for detectors; action for action extensions')
    mem = int(m.get('memory_mb', 128))
    if not 32 <= mem <= 1024:
        raise ExtensionError('memory_mb must be 32-1024')
    return {**m, 'entry': entry, 'events': list(events), 'memory_mb': mem, 'network': bool(m.get('network'))}


def _files(directory):
    """{relative path: sha256} of every file except signature.json; refuses links and oversized packages."""
    out, total = {}, 0
    for dirpath, dirnames, filenames in os.walk(directory):
        dirnames[:] = sorted(d for d in dirnames if d != '__pycache__')
        for name in sorted(filenames):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, directory)
            if rel == 'signature.json':
                continue
            if os.path.islink(full) or not os.path.isfile(full):
                raise ExtensionError(f'{rel}: links and special files are not allowed')
            total += os.path.getsize(full)
            with open(full, 'rb') as f:
                out[rel] = hashlib.sha256(f.read()).hexdigest()
    if len(out) > MAX_FILES or total > MAX_BYTES:
        raise ExtensionError('package too large')
    return out


def _read_manifest(directory):
    try:
        with open(os.path.join(directory, 'manifest.json'), encoding='utf-8') as f:
            return validate_manifest(json.load(f))
    except (OSError, ValueError) as exc:
        raise ExtensionError(f'manifest.json: {exc}')


def sign(directory, private_pem, public_pem):
    manifest = _read_manifest(directory)
    payload = {'manifest': manifest, 'files': _files(directory)}
    if manifest['entry'] not in payload['files']:
        raise ExtensionError(f"entry {manifest['entry']} is missing")
    with open(os.path.join(directory, 'signature.json'), 'w', encoding='utf-8') as f:
        json.dump(signing.sign(private_pem, payload, public_pem), f, indent=1)
    return payload


def trusted_keys():
    d = _path('trusted')
    out = {}
    if os.path.isdir(d):
        for name in sorted(os.listdir(d)):
            if name.endswith('.pem'):
                with open(os.path.join(d, name), encoding='ascii') as f:
                    pem = f.read()
                out[signing.key_id(pem)] = {'publisher': name[:-4], 'public_key': pem}
    return out


def trust(publisher, public_pem):
    if not re.match(r'^[A-Za-z0-9 ._-]{2,60}$', publisher):
        raise ExtensionError('publisher name: 2-60 letters, digits, spaces, dots, dashes')
    if 'PUBLIC KEY' not in public_pem:
        raise ExtensionError('not a PEM public key')
    kid = signing.key_id(public_pem)
    os.makedirs(_path('trusted'), mode=0o750, exist_ok=True)
    with open(_path('trusted', f'{publisher}.pem'), 'w', encoding='ascii') as f:
        f.write(public_pem)
    return {'publisher': publisher, 'kid': kid}


def verify(directory):
    """(manifest, publisher) when the package is signed by a pinned key and unchanged; else ExtensionError."""
    try:
        with open(os.path.join(directory, 'signature.json'), encoding='utf-8') as f:
            envelope = json.load(f)
    except (OSError, ValueError):
        raise ExtensionError('package is not signed (signature.json missing)')
    key = trusted_keys().get(envelope.get('kid'))
    if not key:
        raise ExtensionError(f"signed with an untrusted key ({envelope.get('kid')}); "
                             'an Admin must trust the publisher first')
    try:
        payload = signing.verify(key['public_key'], envelope)
    except signing.SignatureError as exc:
        raise ExtensionError(f'signature: {exc}')
    if payload['files'] != _files(directory):
        raise ExtensionError('package files do not match the signature (changed, added or removed)')
    manifest = validate_manifest(payload['manifest'])
    if manifest != _read_manifest(directory):
        raise ExtensionError('manifest does not match the signature')
    return manifest, key['publisher']


def _unpack(archive, into):
    with tarfile.open(archive, 'r:gz') as tar:
        members = tar.getmembers()
        if len(members) > MAX_FILES + 10:
            raise ExtensionError('package too large')
        for m in members:
            if not (m.isfile() or m.isdir()) or m.name.startswith('/') or '..' in m.name.split('/'):
                raise ExtensionError(f'unsafe path in package: {m.name}')
        tar.extractall(into, filter='data')
    entries = [e for e in os.listdir(into) if not e.startswith('.')]
    return os.path.join(into, entries[0]) if len(entries) == 1 and os.path.isdir(os.path.join(into, entries[0])) else into


def install(source, allow_network=False, by='cli'):
    """Verify and install a package directory or .tar.gz; returns the installed manifest. Starts disabled."""
    tmp = tempfile.mkdtemp(prefix='ext-')
    try:
        directory = _unpack(source, tmp) if os.path.isfile(source) else source
        manifest, publisher = verify(directory)
        if manifest['network'] and not allow_network:
            raise ExtensionError(f"{manifest['name']} asks for network access; install with --allow-network "
                                 'only if you trust it to talk to the network')
        dest = _path('installed', manifest['name'])
        if os.path.exists(dest):
            shutil.rmtree(dest)
        os.makedirs(os.path.dirname(dest), mode=0o750, exist_ok=True)
        shutil.copytree(directory, dest)
        for dirpath, _, filenames in os.walk(dest):
            os.chmod(dirpath, 0o550)  # nosec B103: a directory (needs x), read-only for owner and group
            for name in filenames:
                os.chmod(os.path.join(dirpath, name), 0o440)
        state = load_state()
        state[manifest['name']] = {'enabled': False, 'publisher': publisher, 'version': manifest['version'],
                                   'kind': manifest['kind'], 'network': manifest['network'],
                                   'installed': int(time.time()), 'installed_by': by, 'disabled_reason': None}
        save_state(state)
        _audit('extension_install', manifest['name'], {'version': manifest['version'], 'publisher': publisher,
                                                       'network': manifest['network']})
        return manifest
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def remove(name, by='cli'):
    dest = _path('installed', name)
    if os.path.exists(dest):
        for dirpath, _, _ in os.walk(dest):
            os.chmod(dirpath, 0o750)  # nosec B103: a directory, made writable again only to delete it
        shutil.rmtree(dest)
    state = load_state()
    state.pop(name, None)
    save_state(state)
    _audit('extension_remove', name, {})


def load_state():
    try:
        with open(_path('state.json'), encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def save_state(state):
    os.makedirs(base_dir(), mode=0o750, exist_ok=True)
    with open(_path('state.json.tmp'), 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2)
    os.replace(_path('state.json.tmp'), _path('state.json'))


def set_enabled(name, enabled, reason=None, by='cli'):
    state = load_state()
    if name not in state:
        raise ExtensionError(f'{name} is not installed')
    if enabled:
        verify(_path('installed', name))               # re-checked: files on disk must still match
    state[name].update(enabled=bool(enabled), disabled_reason=None if enabled else reason)
    save_state(state)
    _audit('extension_enable' if enabled else 'extension_disable', name, {'reason': reason})
    return state[name]


def installed_dir(name):
    return _path('installed', name)


def pack(directory, out):
    manifest = _read_manifest(directory)
    if not os.path.exists(os.path.join(directory, 'signature.json')):
        raise ExtensionError('sign the package first')
    with tarfile.open(out, 'w:gz') as tar:
        tar.add(directory, arcname=manifest['name'], filter=lambda ti: None if '__pycache__' in ti.name else ti)
    return out


def _audit(action, target, details):
    try:
        from core import audit
        audit.record(action, actor='extensions', actor_kind='system', target=target, details=details)
    except Exception:
        pass


__all__ = ['ExtensionError', 'sign', 'verify', 'trust', 'install', 'remove', 'set_enabled', 'pack', 'load_state',
           'trusted_keys', 'installed_dir', 'validate_manifest']
