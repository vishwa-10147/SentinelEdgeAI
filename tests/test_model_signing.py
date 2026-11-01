"""Ed25519 signatures for the release model (devices and CI hold only the public key)."""
import json
import os
import shutil
import subprocess
import sys

import pytest

from security import model_signing as ms

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
MODEL = os.path.join(ROOT, 'model', 'isolation_forest.pkl')


def test_committed_release_model_verifies_with_the_shipped_public_key():
    doc = ms.verify_model_signature(MODEL)
    assert doc['algorithm'] == 'ed25519' and doc['version'] == 2
    assert doc['kid'] == ms.key_id(ms.load_public_key())
    assert 'PRIVATE' not in ms.load_public_key()


def _keys(tmp_path):
    private, public = ms.generate_keypair()
    (tmp_path / 'pub.pem').write_text(public)
    return private, public


def _copy(tmp_path):
    dst = tmp_path / 'isolation_forest.pkl'
    shutil.copy(MODEL, dst)
    return dst


def test_sign_and_verify_round_trip(tmp_path):
    private, public = _keys(tmp_path)
    model = _copy(tmp_path)
    ms.sign_model(model, key=private, signer='test')
    assert ms.verify_model_signature(model, public_key=public)['signer'] == 'test'


def test_tampering_is_refused(tmp_path):
    private, public = _keys(tmp_path)
    model = _copy(tmp_path)
    ms.sign_model(model, key=private)
    sig = model.with_name(model.name + '.sig')
    doc = json.loads(sig.read_text())

    # metadata changed (signer) without re-signing
    sig.write_text(json.dumps({**doc, 'signer': 'attacker'}))
    with pytest.raises(ms.ModelSignatureError, match='verification failed'):
        ms.verify_model_signature(model, public_key=public)
    sig.write_text(json.dumps(doc))

    with open(model, 'ab') as f:
        f.write(b'tamper')
    with pytest.raises(ms.ModelSignatureError, match='sha256'):
        ms.verify_model_signature(model, public_key=public)


def test_other_key_and_hmac_signatures_are_refused(tmp_path):
    private, _ = _keys(tmp_path)
    _, other_public = ms.generate_keypair()
    model = _copy(tmp_path)
    ms.sign_model(model, key=private)
    with pytest.raises(ms.ModelSignatureError, match='different key'):
        ms.verify_model_signature(model, public_key=other_public)
    # a forged document claiming the other key's id still fails the signature check
    sig = model.with_name(model.name + '.sig')
    doc = json.loads(sig.read_text())
    sig.write_text(json.dumps({**doc, 'kid': ms.key_id(other_public)}))
    with pytest.raises(ms.ModelSignatureError, match='verification failed'):
        ms.verify_model_signature(model, public_key=other_public)
    # version 1 (HMAC) documents, as signed up to v2.16
    sig.write_text(json.dumps({'version': 1, 'algorithm': 'hmac-sha256', 'model': model.name,
                               'sha256': ms.file_sha256(model), 'signature': 'x'}))
    with pytest.raises(ms.ModelSignatureError, match='only version 2'):
        ms.verify_model_signature(model)
    # an HMAC secret is not accepted as a signing key
    with pytest.raises(ms.ModelSignatureError, match='not a PEM private key'):
        ms.sign_model(model, key='0123456789abcdef' * 4)


def test_signature_for_another_file_is_refused(tmp_path):
    private, public = _keys(tmp_path)
    model = _copy(tmp_path)
    ms.sign_model(model, key=private)
    other = tmp_path / 'other.pkl'
    shutil.copy(model, other)
    shutil.copy(model.with_name(model.name + '.sig'), tmp_path / 'other.pkl.sig')
    with pytest.raises(ms.ModelSignatureError, match='different model'):
        ms.verify_model_signature(other, public_key=public)


def test_cli_generate_sign_verify(tmp_path):
    key, pub = tmp_path / 'k' / 'release.key', tmp_path / 'release.pub'
    model = _copy(tmp_path)
    run = lambda *a, **env: subprocess.run([sys.executable, 'scripts/sign_model.py', *a], cwd=ROOT,  # noqa: E731
                                           capture_output=True, text=True, env={**os.environ, **env})
    assert run('--generate-key', str(key), '--public-key', str(pub)).returncode == 0
    assert oct(os.stat(key).st_mode & 0o777) == '0o600'
    assert run('--generate-key', str(key), '--public-key', str(pub)).returncode == 2       # never overwrites
    env = {'SENTINEL_MODEL_SIGNING_KEY_FILE': str(key), 'SENTINEL_MODEL_PUBLIC_KEY_FILE': str(pub)}
    assert run(str(model), '--quiet', **env).returncode == 0
    assert run(str(model), '--verify', '--quiet', **env).returncode == 0
    # verifying with the shipped key (a different key) fails
    assert run(str(model), '--verify', '--quiet').returncode == 2
