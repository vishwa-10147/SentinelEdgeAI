"""Web Push: RFC 8291 encryption, VAPID, subscriptions and delivery (Phase 10)."""
import base64
import json

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core import auth
from integrations import webpush as wp

FCM = 'https://fcm.googleapis.com/fcm/send/abc123'
PASSWORD = 'correct horse battery staple 42'


def browser_keys():
    """A browser's subscription keys (the user agent side)."""
    priv = ec.generate_private_key(ec.SECP256R1())
    from cryptography.hazmat.primitives import serialization
    pub = priv.public_key().public_bytes(serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint)
    return priv, wp.b64url(pub), wp.b64url(b'0123456789abcdef')


def ua_decrypt(body, ua_priv, p256dh, auth_secret):
    """Receiver side of RFC 8291, independent of encrypt()'s code path where it can be."""
    salt, rs, idlen = body[:16], int.from_bytes(body[16:20], 'big'), body[20]
    as_public = body[21:21 + idlen]
    ct = body[21 + idlen:]
    assert rs == 4096 and idlen == 65
    shared = ua_priv.exchange(ec.ECDH(), ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), as_public))
    prk_key = wp._hmac(wp.unb64url(auth_secret), shared)
    ikm = wp._hmac(prk_key, b'WebPush: info\x00' + wp.unb64url(p256dh) + as_public + b'\x01')
    prk = wp._hmac(salt, ikm)
    cek = wp._hmac(prk, b'Content-Encoding: aes128gcm\x00\x01')[:16]
    nonce = wp._hmac(prk, b'Content-Encoding: nonce\x00\x01')[:12]
    plain = AESGCM(cek).decrypt(nonce, ct, None)
    assert plain.endswith(b'\x02')
    return plain[:-1]


def test_rfc8291_appendix_a_vector():
    as_priv = ec.derive_private_key(int.from_bytes(wp.unb64url('yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw'), 'big'),
                                    ec.SECP256R1())
    body = wp.encrypt(b'When I grow up, I want to be a watermelon',
                      'BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4',
                      'BTBZMqHH6r4Tts7J_aSIgg', salt=wp.unb64url('DGv6ra1nlYgDCS1FRnbzlw'), private_key=as_priv)
    assert wp.b64url(body) == ('DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3vCYLocIn'
                               'mYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPXLWyouBWLVWGNW'
                               'QexSgSxsj_Qulcy4a-fN')


def test_round_trip_with_fresh_keys():
    priv, p256dh, auth_secret = browser_keys()
    msg = json.dumps(wp.approval_message(7, '10.0.0.5', 'block', 82, 'port scan')).encode()
    assert ua_decrypt(wp.encrypt(msg, p256dh, auth_secret), priv, p256dh, auth_secret) == msg
    with pytest.raises(wp.PushError):
        wp.encrypt(b'x' * 5000, p256dh, auth_secret)
    with pytest.raises(wp.PushError):
        wp.encrypt(b'x', wp.b64url(b'\x04' + b'\x00' * 64), auth_secret)       # not a point on the curve


def test_vapid_jwt_verifies_with_the_public_key():
    header = wp.vapid_header(FCM, 'mailto:ops@example.org', now=1_800_000_000)
    t = header.split('t=')[1].split(',')[0]
    k = header.split('k=')[1]
    assert k == wp.public_key()
    head, claims, sig = t.split('.')
    assert json.loads(wp.unb64url(claims)) == {'aud': 'https://fcm.googleapis.com', 'exp': 1_800_000_000 + 43200,
                                               'sub': 'mailto:ops@example.org'}
    assert json.loads(wp.unb64url(head))['alg'] == 'ES256'
    raw = wp.unb64url(sig)
    pub = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), wp.unb64url(k))
    pub.verify(encode_dss_signature(int.from_bytes(raw[:32], 'big'), int.from_bytes(raw[32:], 'big')),
               f'{head}.{claims}'.encode(), ec.ECDSA(hashes.SHA256()))
    import os
    assert oct(os.stat(wp._vapid_file()).st_mode & 0o777) == '0o600'


def sub_for(endpoint=FCM):
    _, p256dh, auth_secret = browser_keys()
    return {'endpoint': endpoint, 'keys': {'p256dh': p256dh, 'auth': auth_secret}}


def test_subscriptions_only_for_push_services():
    for bad in ('http://fcm.googleapis.com/x', 'https://10.0.0.1/x', 'https://evil.example.com/x',
                'https://fcm.googleapis.com.evil.com/x', 'https://localhost/x'):
        with pytest.raises(wp.PushError):
            wp.subscribe('op', sub_for(bad))
    for ok in (FCM, 'https://updates.push.services.mozilla.com/wpush/v2/x', 'https://web.push.apple.com/Q',
               'https://wns2-bl2p.notify.windows.com/w/?token=x'):
        assert wp.subscribe('op', sub_for(ok))['service']
    with pytest.raises(wp.PushError):
        wp.subscribe('op', {'endpoint': FCM, 'keys': {'p256dh': 'AAAA', 'auth': 'BBBB'}})
    listed = wp.list_subscriptions('op')
    assert len(listed) == 4 and all('p256dh' not in s and 'endpoint' not in s for s in listed)


def test_ownership_and_limits():
    a = wp.subscribe('alice', sub_for())
    assert wp.unsubscribe(sub_id=a['id'], username='bob') == 0
    assert wp.unsubscribe(sub_id=a['id'], username='alice') == 1
    for _ in range(wp.MAX_PER_USER + 3):
        wp.subscribe('alice', sub_for(f'{FCM}{_}'))
    assert len(wp.list_subscriptions('alice')) == wp.MAX_PER_USER


def make_user(name, role, disabled=False):
    store = auth.get_store()
    store.create_user(name, PASSWORD, role)
    if disabled:
        store.update_user(name, disabled=True)


def test_delivery_to_current_operators_only_and_gone_subscriptions_removed():
    make_user('opal', 'operator')
    make_user('vic', 'viewer')
    make_user('olda', 'operator')
    make_user('admin2', 'admin')
    auth.get_store().update_user('olda', disabled=True)
    subs = {u: wp.subscribe(u, sub_for(f'{FCM}-{u}')) for u in ('opal', 'vic', 'olda', 'admin2')}
    sent = []

    def poster(endpoint, body, headers):
        sent.append((endpoint, headers))
        return 410 if endpoint.endswith('admin2') else 201

    out = wp.deliver(wp.approval_message(3, '10.0.0.9', 'quarantine', 90, 'beaconing'), poster=poster, now=100)
    assert out[subs['opal']['id']] == 201 and out[subs['admin2']['id']] == 410
    assert out[subs['vic']['id']] == out[subs['olda']['id']] == 'not an Operator or Admin'
    assert {e.rsplit('-', 1)[1] for e, _ in sent} == {'opal', 'admin2'}
    _, headers = sent[0]
    assert headers['Content-Encoding'] == 'aes128gcm' and headers['Authorization'].startswith('vapid t=')
    remaining = {s['username']: s for s in wp.list_subscriptions()}
    assert 'admin2' not in remaining and remaining['opal']['last_ok'] == 100


def test_approval_hook_does_nothing_without_subscriptions(monkeypatch):
    calls = []
    monkeypatch.setattr(wp, 'enqueue', lambda m: calls.append(m))
    from integrations import notify
    notify.approval_requested(5, '10.0.0.5', 'block', 80, 'scan')
    assert calls == []
    wp.subscribe('opal', sub_for())
    notify.approval_requested(5, '10.0.0.5', 'block', 80, 'scan')
    assert calls[0]['url'] == '/#approve/5' and calls[0]['require'] is True


def test_push_endpoints():
    from fastapi.testclient import TestClient
    from dashboard import dashboard_api as api
    make_user('opal', 'operator')
    op = {'username': 'opal', 'role': 'operator'}
    api.app.dependency_overrides[api.require_viewer] = lambda: op
    api.app.dependency_overrides[api.require_operator] = lambda: op
    try:
        c = TestClient(api.app)
        info = c.get('/api/push').json()
        assert info['can_subscribe'] and len(wp.unb64url(info['public_key'])) == 65
        r = c.post('/api/push/subscriptions', json={'subscription': sub_for(), 'label': 'phone'})
        assert r.status_code == 200 and r.json()['service'] == 'fcm.googleapis.com'
        assert c.post('/api/push/subscriptions', json={'subscription': sub_for('https://169.254.169.254/')}).status_code == 400
        sid = r.json()['id']
        assert [s['id'] for s in c.get('/api/push').json()['subscriptions']] == [sid]
        assert c.delete('/api/push/subscriptions/nope').status_code == 404
        assert c.delete(f'/api/push/subscriptions/{sid}').json() == {'removed': 1}
    finally:
        api.app.dependency_overrides.clear()
