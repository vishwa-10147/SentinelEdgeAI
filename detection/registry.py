"""Versioned, Ed25519-signed model registry with shadow -> canary -> active stages.

    python -m detection.registry list
    python -m detection.registry stage autoencoder 3 canary --percent 10
    python -m detection.registry promote autoencoder 3
    python -m detection.registry rollback autoencoder

Layout (SENTINEL_MODEL_REGISTRY, default data/models):
    index.json                       stages per model
    signing.key / signing.pub        registry key (created on first use)
    <name>/<version>/model.joblib    the model
    <name>/<version>/meta.json       metrics, features, sha256, created
    <name>/<version>/meta.sig        Ed25519 signature over meta.json (which pins the sha256)

A model is loaded only if its signature verifies and its file matches the
signed hash. 'shadow' models score traffic without affecting decisions;
'canary' models decide for a share of sources; 'active' decides for the rest.
"""
import argparse
import hashlib
import json
import os
import sys
import threading
import time
import zlib

import joblib

from common import signing

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
STAGES = ('shadow', 'canary', 'active', 'retired')


class RegistryError(RuntimeError):
    pass


def registry_dir():
    return os.environ.get('SENTINEL_MODEL_REGISTRY') or os.path.join(ROOT, 'data', 'models')


def _p(*parts):
    return os.path.join(registry_dir(), *parts)


def _keys():
    os.makedirs(registry_dir(), mode=0o700, exist_ok=True)
    if not os.path.exists(_p('signing.key')):
        private, public = signing.generate_keypair()
        fd = os.open(_p('signing.key'), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(private)
        with open(_p('signing.pub'), 'w') as f:
            f.write(public)
    with open(_p('signing.key')) as f:
        private = f.read()
    with open(_p('signing.pub')) as f:
        public = f.read()
    return private, public


def _sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def index():
    try:
        with open(_p('index.json')) as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_index(idx):
    tmp = _p('index.json.tmp')
    with open(tmp, 'w') as f:
        json.dump(idx, f, indent=2)
    os.replace(tmp, _p('index.json'))


def register(name, model, metrics=None, features=None, notes=''):
    """Store and sign a model object; it starts in 'shadow'. Returns the version number."""
    private, public = _keys()
    idx = index()
    entry = idx.setdefault(name, {'versions': {}, 'active': None, 'canary': None, 'canary_percent': 10,
                                  'previous_active': None})
    version = max([int(v) for v in entry['versions']] or [0]) + 1
    d = _p(name, str(version))
    os.makedirs(d, exist_ok=True)
    joblib.dump(model, os.path.join(d, 'model.joblib'))
    meta = {'name': name, 'version': version, 'sha256': _sha256(os.path.join(d, 'model.joblib')),
            'metrics': metrics or {}, 'features': features or [], 'created': int(time.time()), 'notes': notes}
    with open(os.path.join(d, 'meta.json'), 'w') as f:
        json.dump(meta, f, indent=2)
    with open(os.path.join(d, 'meta.sig'), 'w') as f:
        json.dump(signing.sign(private, meta, public), f)
    entry['versions'][str(version)] = {'stage': 'shadow', 'created': meta['created'], 'metrics': meta['metrics']}
    _save_index(idx)
    return version


def verify(name, version):
    """Return the signed metadata, or raise RegistryError."""
    d = _p(name, str(version))
    try:
        with open(_p('signing.pub')) as f:
            public = f.read()
        with open(os.path.join(d, 'meta.sig')) as f:
            meta = signing.verify(public, json.load(f))
    except (OSError, ValueError) as exc:
        raise RegistryError(f'{name} v{version}: signature check failed ({exc})')
    if meta.get('name') != name or meta.get('version') != int(version):
        raise RegistryError(f'{name} v{version}: metadata does not match')
    if _sha256(os.path.join(d, 'model.joblib')) != meta['sha256']:
        raise RegistryError(f'{name} v{version}: model file does not match its signed hash')
    return meta


def load(name, version):
    meta = verify(name, version)
    return joblib.load(_p(name, str(version), 'model.joblib')), meta  # nosec B301 - signature and hash verified above


def set_stage(name, version, stage, percent=None):
    if stage not in STAGES:
        raise ValueError(f'stage must be one of {STAGES}')
    idx = index()
    entry = idx.get(name)
    if not entry or str(version) not in entry['versions']:
        raise KeyError(f'{name} v{version}')
    verify(name, version)
    version = str(version)
    if stage == 'active':
        if entry['active'] and entry['active'] != version:
            entry['previous_active'] = entry['active']
            entry['versions'][entry['active']]['stage'] = 'retired'
        entry['active'] = version
        if entry['canary'] == version:
            entry['canary'] = None
    elif stage == 'canary':
        if entry['canary'] and entry['canary'] != version:
            entry['versions'][entry['canary']]['stage'] = 'shadow'
        entry['canary'] = version
        if percent is not None:
            entry['canary_percent'] = max(1, min(50, int(percent)))
    else:
        if entry['active'] == version:
            raise ValueError('cannot demote the active version; promote another or roll back')
        if entry['canary'] == version:
            entry['canary'] = None
    entry['versions'][version]['stage'] = stage
    _save_index(idx)
    return entry


def rollback(name):
    idx = index()
    entry = idx.get(name)
    if not entry or not entry.get('previous_active'):
        raise ValueError(f'no previous active version of {name}')
    prev = entry['previous_active']
    entry['previous_active'] = None
    _save_index(idx)
    return set_stage(name, prev, 'active')


class ModelHandle:
    """Hot-reloading access to a model's active, canary and shadow versions."""

    def __init__(self, name, check_every=30):
        self.name = name
        self.check_every = check_every
        self._checked = 0.0
        self._mtime = None
        self._models = {}            # stage -> (version, model)
        self._lock = threading.Lock()

    def _refresh(self):
        now = time.time()
        if now - self._checked < self.check_every:
            return
        self._checked = now
        try:
            mtime = os.path.getmtime(_p('index.json'))
        except OSError:
            self._models = {}
            return
        if mtime == self._mtime:
            return
        self._mtime = mtime
        entry = index().get(self.name) or {}
        wanted = {'active': entry.get('active'), 'canary': entry.get('canary')}
        shadows = [v for v, info in (entry.get('versions') or {}).items() if info['stage'] == 'shadow']
        if shadows:
            wanted['shadow'] = max(shadows, key=int)
        models = {}
        for stage, version in wanted.items():
            if not version:
                continue
            cached = self._models.get(stage)
            if cached and cached[0] == version:
                models[stage] = cached
                continue
            try:
                models[stage] = (version, load(self.name, version)[0])
            except (RegistryError, OSError):
                continue                   # an unverifiable model is never used
        self._models = models
        self.canary_percent = entry.get('canary_percent', 10)

    def for_source(self, src):
        """(stage, version, model) that decides for this source, or None."""
        with self._lock:
            self._refresh()
            canary = self._models.get('canary')
            if canary and zlib.crc32(str(src).encode()) % 100 < getattr(self, 'canary_percent', 10):
                return ('canary',) + canary
            active = self._models.get('active')
            return ('active',) + active if active else None

    def shadow(self):
        with self._lock:
            self._refresh()
            s = self._models.get('shadow')
            return ('shadow',) + s if s else None


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m detection.registry')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('list')
    p = sub.add_parser('stage')
    p.add_argument('name')
    p.add_argument('version', type=int)
    p.add_argument('stage', choices=STAGES)
    p.add_argument('--percent', type=int)
    p = sub.add_parser('promote')
    p.add_argument('name')
    p.add_argument('version', type=int)
    p = sub.add_parser('rollback')
    p.add_argument('name')
    p = sub.add_parser('verify')
    p.add_argument('name')
    p.add_argument('version', type=int)
    args = parser.parse_args(argv)
    try:
        if args.command == 'list':
            for name, e in index().items():
                print(f"{name}: active={e['active']} canary={e['canary']} ({e.get('canary_percent')}%) "
                      f"previous={e.get('previous_active')}")
                for v, info in sorted(e['versions'].items(), key=lambda kv: int(kv[0])):
                    print(f"  v{v:<4} {info['stage']:<8} {json.dumps(info.get('metrics', {}))}")
        elif args.command == 'stage':
            set_stage(args.name, args.version, args.stage, args.percent)
            print(f'{args.name} v{args.version} -> {args.stage}')
        elif args.command == 'promote':
            set_stage(args.name, args.version, 'active')
            print(f'{args.name} v{args.version} is now active')
        elif args.command == 'rollback':
            e = rollback(args.name)
            print(f"{args.name}: rolled back to v{e['active']}")
        elif args.command == 'verify':
            print(json.dumps(verify(args.name, args.version), indent=2))
    except (KeyError, ValueError, RegistryError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
