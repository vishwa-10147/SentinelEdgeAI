"""Encrypted backup and restore of configuration, keys, policy, models and databases.

    sudo sentinelctl backup /root/sentinel-2026-10-31.seab     # wraps: python -m ops.backup create
    sudo sentinelctl restore /root/sentinel-2026-10-31.seab    # stops services, restores, restarts

The archive holds secrets (signing keys, TLS key, API key, user database),
so it is always encrypted: scrypt(passphrase) -> AES-256-GCM. The passphrase
comes from SENTINEL_BACKUP_PASSPHRASE or an interactive prompt. SQLite
databases are copied with SQLite's online backup API, so a backup taken
while the services run is consistent. Restore verifies the passphrase
(GCM tag) and every file's SHA-256 before writing anything.
"""
import argparse
import getpass
import hashlib
import io
import json
import os
import socket
import sqlite3
import sys
import tarfile
import tempfile
import time

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

MAGIC = b'SEABK1\n'
ETC_DEFAULT = '/etc/sentinel'
STATE_DEFAULT = '/var/lib/sentinel'
SQLITE_SUFFIXES = ('.db',)
SKIP = ('-wal', '-shm', '.tmp', 'initial-admin-password')


class BackupError(RuntimeError):
    pass


def _key(passphrase, salt):
    if len(passphrase) < 12:
        raise BackupError('use a passphrase of at least 12 characters')
    return Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(passphrase.encode())


def _files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames.sort()
        for name in sorted(filenames):
            if name.endswith(SKIP) or name in SKIP:
                continue
            path = os.path.join(dirpath, name)
            if os.path.islink(path) or not os.path.isfile(path):
                continue
            yield path


def _sqlite_copy(src, dst):
    source = sqlite3.connect(f'file:{src}?mode=ro', uri=True, timeout=10)
    target = sqlite3.connect(dst)
    try:
        source.backup(target)
    finally:
        target.close()
        source.close()


def create(out_path, passphrase, etc_dir=ETC_DEFAULT, state_dir=STATE_DEFAULT, version=None):
    """Write an encrypted backup; returns the manifest."""
    manifest = {'format': 1, 'created': int(time.time()), 'host': socket.gethostname(), 'version': version,
                'files': {}}
    buf = io.BytesIO()
    with tempfile.TemporaryDirectory() as tmp, tarfile.open(fileobj=buf, mode='w:gz') as tar:
        for prefix, root in (('etc', etc_dir), ('state', state_dir)):
            if not os.path.isdir(root):
                continue
            for path in _files(root):
                rel = os.path.relpath(path, root)
                arcname = f'{prefix}/{rel}'
                source = path
                if path.endswith(SQLITE_SUFFIXES):
                    source = os.path.join(tmp, hashlib.sha256(arcname.encode()).hexdigest())
                    try:
                        _sqlite_copy(path, source)
                    except sqlite3.DatabaseError:
                        source = path            # not a database after all: copy the bytes
                with open(source, 'rb') as f:
                    data = f.read()
                info = tarfile.TarInfo(arcname)
                info.size = len(data)
                info.mode = os.stat(path).st_mode & 0o777
                info.mtime = int(os.stat(path).st_mtime)
                tar.addfile(info, io.BytesIO(data))
                manifest['files'][arcname] = {'sha256': hashlib.sha256(data).hexdigest(), 'mode': info.mode,
                                              'size': len(data)}
        meta = json.dumps(manifest, indent=2).encode()
        info = tarfile.TarInfo('manifest.json')
        info.size = len(meta)
        tar.addfile(info, io.BytesIO(meta))
    salt, nonce = os.urandom(16), os.urandom(12)
    sealed = AESGCM(_key(passphrase, salt)).encrypt(nonce, buf.getvalue(), MAGIC)
    fd = os.open(out_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(MAGIC + salt + nonce + sealed)
    _log_backup(state_dir, out_path, manifest)
    return manifest


def backup_log_file(state_dir=STATE_DEFAULT):
    return os.environ.get('SENTINEL_BACKUP_LOG') or os.path.join(state_dir, 'data', 'backup_log.json')


def _log_backup(state_dir, out_path, manifest):
    """Remember when backups were made (evidence for the compliance packs); never fails the backup."""
    path = backup_log_file(state_dir)
    try:
        try:
            with open(path, 'r', encoding='utf-8') as f:
                log = json.load(f)
        except (OSError, ValueError):
            log = []
        log = (log + [{'ts': manifest['created'], 'file': os.path.abspath(out_path), 'files': len(manifest['files'])}])[-50:]
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + '.tmp', 'w', encoding='utf-8') as f:
            json.dump(log, f, indent=2)
        os.replace(path + '.tmp', path)
    except OSError:
        pass


def last_backup(state_dir=STATE_DEFAULT):
    try:
        with open(backup_log_file(state_dir), 'r', encoding='utf-8') as f:
            log = json.load(f)
        return log[-1] if log else None
    except (OSError, ValueError, IndexError):
        return None


def _open(path, passphrase):
    with open(path, 'rb') as f:
        blob = f.read()
    if not blob.startswith(MAGIC):
        raise BackupError('not a SentinelEdgeAI backup')
    salt, nonce, sealed = blob[len(MAGIC):len(MAGIC) + 16], blob[len(MAGIC) + 16:len(MAGIC) + 28], blob[len(MAGIC) + 28:]
    try:
        plain = AESGCM(_key(passphrase, salt)).decrypt(nonce, sealed, MAGIC)
    except Exception:
        raise BackupError('wrong passphrase or damaged backup')
    tar = tarfile.open(fileobj=io.BytesIO(plain), mode='r:gz')
    try:
        manifest = json.load(tar.extractfile('manifest.json'))
    except (KeyError, ValueError):
        raise BackupError('backup has no valid manifest')
    return tar, manifest


def inspect(path, passphrase):
    tar, manifest = _open(path, passphrase)
    tar.close()
    return manifest


def restore(path, passphrase, etc_dir=ETC_DEFAULT, state_dir=STATE_DEFAULT, dry_run=False):
    """Verify everything first, then write. Returns the list of restored files."""
    tar, manifest = _open(path, passphrase)
    roots = {'etc': os.path.abspath(etc_dir), 'state': os.path.abspath(state_dir)}
    staged = []
    with tar:
        for arcname, meta in manifest['files'].items():
            prefix, _, rel = arcname.partition('/')
            if prefix not in roots or not rel or rel.startswith('/') or '..' in rel.split('/'):
                raise BackupError(f'unsafe path in backup: {arcname}')
            member = tar.getmember(arcname)
            if not member.isfile():
                raise BackupError(f'{arcname} is not a regular file')
            data = tar.extractfile(member).read()
            if hashlib.sha256(data).hexdigest() != meta['sha256']:
                raise BackupError(f'{arcname} does not match its checksum')
            target = os.path.join(roots[prefix], rel)
            if os.path.commonpath([roots[prefix], os.path.abspath(target)]) != roots[prefix]:
                raise BackupError(f'unsafe path in backup: {arcname}')
            staged.append((target, data, meta['mode']))
    if dry_run:
        return [t for t, _, _ in staged]
    for target, data, mode in staged:
        os.makedirs(os.path.dirname(target), exist_ok=True)
        tmp = target + '.restore-tmp'
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode or 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(data)
        os.chmod(tmp, mode or 0o600)
        for stale in (target + '-wal', target + '-shm'):
            if os.path.exists(stale):
                os.remove(stale)          # a WAL from the old database must not be replayed
        os.replace(tmp, target)
    return [t for t, _, _ in staged]


def _passphrase(confirm=False):
    value = os.environ.get('SENTINEL_BACKUP_PASSPHRASE')
    if value:
        return value
    value = getpass.getpass('Backup passphrase: ')
    if confirm and value != getpass.getpass('Repeat passphrase: '):
        raise BackupError('passphrases do not match')
    return value


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m ops.backup')
    parser.add_argument('--etc', default=ETC_DEFAULT)
    parser.add_argument('--state', default=STATE_DEFAULT)
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('create')
    p.add_argument('file')
    p = sub.add_parser('restore')
    p.add_argument('file')
    p.add_argument('--dry-run', action='store_true')
    p = sub.add_parser('inspect')
    p.add_argument('file')
    args = parser.parse_args(argv)
    try:
        if args.command == 'create':
            version = None
            try:
                with open(os.path.join(os.path.dirname(__file__), '..', 'VERSION')) as f:
                    version = f.read().strip()
            except OSError:
                pass
            m = create(args.file, _passphrase(confirm=True), args.etc, args.state, version)
            print(f"backup written: {args.file} ({len(m['files'])} files)")
        elif args.command == 'inspect':
            m = inspect(args.file, _passphrase())
            print(json.dumps({k: v for k, v in m.items() if k != 'files'} | {'files': len(m['files'])}, indent=2))
        else:
            files = restore(args.file, _passphrase(), args.etc, args.state, args.dry_run)
            print(f"{'would restore' if args.dry_run else 'restored'} {len(files)} files")
    except (BackupError, OSError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
