"""Signed update channels: `stable` and `beta` (Phase 8).

A channel is a small manifest naming one release and the SHA-256 of its exact
package, signed with the maintainer's Ed25519 release key (the same key as
the release model, security/release_model.pub; pinned on a device in
/etc/sentinel/release_signing.pub at its first install):

    {"payload": {"channel": "stable", "version": "2.16.0", "sha256": "...",
                 "tarball": "https://github.com/.../sentineledgeai-pi-2.16.0.tar.gz",
                 "issued_at": 1793..., "expires_at": 1809..., "serial": 7},
     "sig": "<base64 Ed25519 over the canonical payload>", "kid": "<key id>"}

`beta` gets every release once it is published; `stable` gets it after the
beta has run without trouble. `sentinelctl update` on a channel installs only
what the manifest names, and only if the downloaded package has the signed
SHA-256, so neither a compromised CI job nor a swapped GitHub release can push
a package to devices. Manifests expire (default 120 days), so a stale manifest
replayed by a mirror stops working, and a device refuses a manifest whose
serial or version is lower than the last one it accepted (rollback).

Maintainer (where the private key lives):
    python -m ops.channels sign --channel beta --version 2.17.0 --key ~/.sentinel/release_model.key
    python -m ops.channels promote --from beta --to stable --key ~/.sentinel/release_model.key
Device (sentinelctl calls this):
    python -m ops.channels verify --channel stable --file stable.json --public-key /etc/sentinel/release_signing.pub \\
        --state /var/lib/sentinel/data/update_channel.json
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time
import urllib.request

from common import signing

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CHANNELS = ('stable', 'beta')
CHANNEL_DIR = os.path.join(ROOT, 'channels')
REPO = 'vishwa-10147/SentinelEdgeAI'
DEFAULT_EXPIRY_DAYS = 120
VERSION_RE = re.compile(r'^\d+\.\d+\.\d+$')
SHA_RE = re.compile(r'^[0-9a-f]{64}$')


class ChannelError(ValueError):
    pass


def _version_key(v):
    return tuple(int(x) for x in v.split('.'))


def tarball_url(version):
    return f'https://github.com/{REPO}/releases/download/v{version}/sentineledgeai-pi-{version}.tar.gz'


def fetch_sha256(version, url=None):
    """The published SHA-256 of a release package (its .sha256 asset)."""
    url = (url or tarball_url(version)) + '.sha256'
    if not url.startswith('https://'):
        raise ChannelError('release URLs must be https')
    with urllib.request.urlopen(url, timeout=30) as resp:      # nosec B310: https only, checked above
        text = resp.read(4096).decode('ascii', 'replace')
    sha = text.split()[0].lower() if text.split() else ''
    if not SHA_RE.match(sha):
        raise ChannelError(f'no SHA-256 in {url}')
    return sha


def make_manifest(private_pem, public_pem, channel, version, sha256, tarball=None, serial=None,
                  expiry_days=DEFAULT_EXPIRY_DAYS, now=None):
    if channel not in CHANNELS:
        raise ChannelError(f'channel must be one of {", ".join(CHANNELS)}')
    if not VERSION_RE.match(version or ''):
        raise ChannelError('version must look like 2.17.0')
    if not SHA_RE.match((sha256 or '').lower()):
        raise ChannelError('sha256 must be 64 hex characters')
    if not 1 <= int(expiry_days) <= 400:
        raise ChannelError('expiry must be 1-400 days')
    now = int(now if now is not None else time.time())
    payload = {'channel': channel, 'version': version, 'sha256': sha256.lower(),
               'tarball': tarball or tarball_url(version), 'issued_at': now,
               'expires_at': now + int(expiry_days) * 86400, 'serial': int(serial if serial is not None else now)}
    return signing.sign(private_pem, payload, public_pem)


def verify_manifest(envelope, public_pem, channel, now=None, last=None):
    """The payload of a valid manifest for `channel`, else ChannelError.

    `last` is the payload accepted before on this device: a lower serial or an older version is refused.
    """
    try:
        payload = signing.verify(public_pem, envelope)
    except signing.SignatureError as exc:
        raise ChannelError(f'channel manifest signature: {exc}')
    if envelope.get('kid') and envelope['kid'] != signing.key_id(public_pem):
        raise ChannelError('channel manifest signed with a different key')
    now = time.time() if now is None else now
    if payload.get('channel') != channel:
        raise ChannelError(f'manifest is for channel {payload.get("channel")!r}, not {channel!r}')
    if not VERSION_RE.match(str(payload.get('version'))) or not SHA_RE.match(str(payload.get('sha256'))):
        raise ChannelError('malformed channel manifest')
    if not str(payload.get('tarball', '')).startswith(('https://', 'file://')):
        raise ChannelError('channel manifest tarball must be https (or a file:// mirror)')
    if now > payload.get('expires_at', 0):
        raise ChannelError('channel manifest has expired (the maintainer re-signs channels regularly; '
                           'a stale copy is being served)')
    if payload.get('issued_at', 0) > now + 86400:
        raise ChannelError('channel manifest is dated in the future (check the device clock)')
    if last and last.get('channel') == channel:
        if payload['serial'] < last.get('serial', 0):
            raise ChannelError('channel manifest is older than the one this device already accepted')
        if _version_key(payload['version']) < _version_key(last.get('version', '0.0.0')):
            raise ChannelError(f'channel now names {payload["version"]}, older than {last["version"]}: refused')
    return payload


def _read_json(path):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _write_json(path, doc):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(doc, f, indent=2, sort_keys=True)
        f.write('\n')
    os.replace(tmp, path)


def file_sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _keys(path):
    from security.model_signing import ModelSignatureError, _private
    from cryptography.hazmat.primitives import serialization
    try:
        with open(os.path.expanduser(path), encoding='ascii') as f:
            private_pem = f.read()
        public_pem = _private(private_pem).public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')
    except (OSError, ModelSignatureError) as exc:
        raise ChannelError(f'cannot use signing key {path}: {exc}')
    return private_pem, public_pem


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m ops.channels', description='signed update channels')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('sign', help='sign a channel manifest naming a release (maintainer)')
    p.add_argument('--channel', required=True, choices=CHANNELS)
    p.add_argument('--version', required=True)
    p.add_argument('--sha256', help='package SHA-256 (default: read from the published .sha256)')
    p.add_argument('--tarball', help='package URL (default: the GitHub release asset)')
    p.add_argument('--key', default=os.environ.get('SENTINEL_MODEL_SIGNING_KEY_FILE', '~/.sentinel/release_model.key'))
    p.add_argument('--expiry-days', type=int, default=DEFAULT_EXPIRY_DAYS)
    p.add_argument('--out-dir', default=CHANNEL_DIR)
    p = sub.add_parser('promote', help='re-sign the release one channel names into another (maintainer)')
    p.add_argument('--from', dest='source', default='beta', choices=CHANNELS)
    p.add_argument('--to', dest='target', default='stable', choices=CHANNELS)
    p.add_argument('--key', default=os.environ.get('SENTINEL_MODEL_SIGNING_KEY_FILE', '~/.sentinel/release_model.key'))
    p.add_argument('--expiry-days', type=int, default=DEFAULT_EXPIRY_DAYS)
    p.add_argument('--out-dir', default=CHANNEL_DIR)
    p = sub.add_parser('refresh', help='re-sign every channel unchanged with a new expiry (maintainer)')
    p.add_argument('--key', default=os.environ.get('SENTINEL_MODEL_SIGNING_KEY_FILE', '~/.sentinel/release_model.key'))
    p.add_argument('--expiry-days', type=int, default=DEFAULT_EXPIRY_DAYS)
    p.add_argument('--out-dir', default=CHANNEL_DIR)
    p = sub.add_parser('verify', help='check a manifest; prints "<version> <tarball> <sha256>" (device)')
    p.add_argument('--channel', required=True, choices=CHANNELS)
    p.add_argument('--file', required=True)
    p.add_argument('--public-key', required=True)
    p.add_argument('--state', help='where the last accepted manifest is kept (rollback protection)')
    p = sub.add_parser('accept', help='record a manifest as installed (after a successful update)')
    p.add_argument('--channel', required=True, choices=CHANNELS)
    p.add_argument('--file', required=True)
    p.add_argument('--public-key', required=True)
    p.add_argument('--state', required=True)
    p = sub.add_parser('check-file', help='does a downloaded package have the SHA-256 a manifest names?')
    p.add_argument('--sha256', required=True)
    p.add_argument('package')
    args = parser.parse_args(argv)
    try:
        if args.command in ('sign', 'promote', 'refresh'):
            private_pem, public_pem = _keys(args.key)
            jobs = []
            if args.command == 'sign':
                sha = args.sha256 or fetch_sha256(args.version, args.tarball)
                jobs.append((args.channel, args.version, sha, args.tarball))
            else:
                pairs = [(args.source, args.target)] if args.command == 'promote' else [(c, c) for c in CHANNELS]
                for src, dst in pairs:
                    doc = _read_json(os.path.join(args.out_dir, f'{src}.json'))
                    if doc is None:
                        if args.command == 'refresh':
                            continue
                        raise ChannelError(f'no {src} manifest in {args.out_dir}')
                    cur = verify_manifest(doc, public_pem, src, now=doc['payload'].get('issued_at'))
                    jobs.append((dst, cur['version'], cur['sha256'], cur['tarball']))
            for channel, version, sha, tarball in jobs:
                path = os.path.join(args.out_dir, f'{channel}.json')
                old = _read_json(path)
                serial = max(int(time.time()), (old or {}).get('payload', {}).get('serial', 0) + 1)
                doc = make_manifest(private_pem, public_pem, channel, version, sha, tarball, serial, args.expiry_days)
                _write_json(path, doc)
                print(f'{channel}: {version} (sha256 {sha[:16]}..., expires '
                      f'{time.strftime("%Y-%m-%d", time.gmtime(doc["payload"]["expires_at"]))}) -> {path}')
            return 0
        if args.command == 'check-file':
            if file_sha256(args.package) != args.sha256.lower():
                raise ChannelError('the downloaded package does not have the SHA-256 the signed channel names')
            return 0
        with open(args.public_key, encoding='ascii') as f:
            public_pem = f.read()
        doc = _read_json(args.file)
        if doc is None:
            raise ChannelError(f'cannot read channel manifest {args.file}')
        last = _read_json(args.state) if args.state else None
        payload = verify_manifest(doc, public_pem, args.channel, last=last)
        if args.command == 'accept':
            _write_json(args.state, payload)
        else:
            print(payload['version'], payload['tarball'], payload['sha256'])
        return 0
    except (ChannelError, OSError) as exc:
        print(f'channel error: {exc}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())
