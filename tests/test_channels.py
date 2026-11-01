"""Signed update channels (stable / beta)."""
import json
import os

import pytest

from common import signing
from ops import channels as ch

SHA = 'a' * 64
NOW = 1_800_000_000


@pytest.fixture()
def keys():
    return signing.generate_keypair()


def manifest(keys, channel='stable', version='2.17.0', sha=SHA, serial=1, now=NOW, **kw):
    return ch.make_manifest(keys[0], keys[1], channel, version, sha, serial=serial, now=now, **kw)


def test_round_trip(keys):
    doc = manifest(keys)
    p = ch.verify_manifest(doc, keys[1], 'stable', now=NOW + 10)
    assert p['version'] == '2.17.0' and p['sha256'] == SHA
    assert p['tarball'].endswith('/v2.17.0/sentineledgeai-pi-2.17.0.tar.gz')
    assert doc['kid'] == signing.key_id(keys[1])


def test_refusals(keys):
    doc = manifest(keys)
    with pytest.raises(ch.ChannelError, match='not .beta'):
        ch.verify_manifest(doc, keys[1], 'beta', now=NOW)
    with pytest.raises(ch.ChannelError, match='expired'):
        ch.verify_manifest(doc, keys[1], 'stable', now=NOW + 121 * 86400)
    with pytest.raises(ch.ChannelError, match='future'):
        ch.verify_manifest(doc, keys[1], 'stable', now=NOW - 2 * 86400)
    other = signing.generate_keypair()
    with pytest.raises(ch.ChannelError, match='signature'):
        ch.verify_manifest(doc, other[1], 'stable', now=NOW)
    forged = json.loads(json.dumps(doc))
    forged['payload']['sha256'] = 'b' * 64                 # point the channel at another package
    with pytest.raises(ch.ChannelError, match='signature'):
        ch.verify_manifest(forged, keys[1], 'stable', now=NOW)
    with pytest.raises(ch.ChannelError):
        manifest(keys, channel='nightly')
    with pytest.raises(ch.ChannelError):
        manifest(keys, version='2.17')
    bad = ch.make_manifest(keys[0], keys[1], 'stable', '2.17.0', SHA, tarball='http://plain/x.tar.gz', now=NOW)
    with pytest.raises(ch.ChannelError, match='https'):
        ch.verify_manifest(bad, keys[1], 'stable', now=NOW)


def test_rollback_protection(keys):
    accepted = ch.verify_manifest(manifest(keys, version='2.17.0', serial=5), keys[1], 'stable', now=NOW)
    with pytest.raises(ch.ChannelError, match='older than the one'):
        ch.verify_manifest(manifest(keys, version='2.18.0', serial=4), keys[1], 'stable', now=NOW, last=accepted)
    with pytest.raises(ch.ChannelError, match='older than 2.17.0'):
        ch.verify_manifest(manifest(keys, version='2.16.0', serial=6), keys[1], 'stable', now=NOW, last=accepted)
    # a refresh (same release, new serial and expiry) and a newer release are fine
    assert ch.verify_manifest(manifest(keys, serial=6), keys[1], 'stable', now=NOW, last=accepted)
    assert ch.verify_manifest(manifest(keys, version='2.18.0', serial=7), keys[1], 'stable', now=NOW, last=accepted)


def test_cli_sign_promote_verify_accept(tmp_path, keys):
    key = tmp_path / 'release.key'
    key.write_text(keys[0])
    pub = tmp_path / 'release.pub'
    pub.write_text(keys[1])
    out = str(tmp_path / 'channels')
    assert ch.main(['sign', '--channel', 'beta', '--version', '2.17.0', '--sha256', SHA, '--key', str(key),
                    '--out-dir', out]) == 0
    assert ch.main(['promote', '--from', 'beta', '--to', 'stable', '--key', str(key), '--out-dir', out]) == 0
    state = str(tmp_path / 'state.json')
    stable = os.path.join(out, 'stable.json')
    assert ch.main(['verify', '--channel', 'stable', '--file', stable, '--public-key', str(pub), '--state', state]) == 0
    assert ch.main(['accept', '--channel', 'stable', '--file', stable, '--public-key', str(pub), '--state', state]) == 0
    assert json.load(open(state))['version'] == '2.17.0'
    # an older release signed later is refused by a device that accepted 2.17.0
    assert ch.main(['sign', '--channel', 'stable', '--version', '2.16.0', '--sha256', SHA, '--key', str(key),
                    '--out-dir', out]) == 0
    assert ch.main(['verify', '--channel', 'stable', '--file', stable, '--public-key', str(pub), '--state', state]) == 2
    assert ch.main(['refresh', '--key', str(key), '--out-dir', out]) == 0
    pkg = tmp_path / 'p.tar.gz'
    pkg.write_bytes(b'package')
    import hashlib
    assert ch.main(['check-file', '--sha256', hashlib.sha256(b'package').hexdigest(), str(pkg)]) == 0
    assert ch.main(['check-file', '--sha256', SHA, str(pkg)]) == 2


def test_committed_channels_verify_with_the_release_key():
    from security.model_signing import load_public_key
    public = load_public_key()
    found = 0
    for name in ch.CHANNELS:
        path = os.path.join(ch.CHANNEL_DIR, f'{name}.json')
        if os.path.exists(path):
            doc = json.load(open(path))
            assert ch.verify_manifest(doc, public, name, now=doc['payload']['issued_at'])
            found += 1
    assert found == 2
