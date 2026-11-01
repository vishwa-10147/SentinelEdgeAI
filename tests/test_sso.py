"""Single sign-on with OpenID Connect against a fake identity provider (Phase 10)."""
import base64
import json
import time
from urllib.parse import parse_qs, urlparse

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from core import auth, sso

ISSUER = 'https://idp.example.com/tenant'
CLIENT = 'sentinel-console'


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def num(n, size=None):
    size = size or (n.bit_length() + 7) // 8
    return b64(n.to_bytes(size, 'big'))


class FakeIdP:
    def __init__(self):
        self.rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.ec = ec.generate_private_key(ec.SECP256R1())
        rn, en = self.rsa.public_key().public_numbers().n, self.rsa.public_key().public_numbers().e
        pn = self.ec.public_key().public_numbers()
        self.jwks = {'keys': [{'kty': 'RSA', 'kid': 'r1', 'use': 'sig', 'alg': 'RS256', 'n': num(rn), 'e': num(en)},
                              {'kty': 'EC', 'kid': 'e1', 'crv': 'P-256', 'x': num(pn.x, 32), 'y': num(pn.y, 32)}]}
        self.next_claims = {}
        self.token_calls = []
        self.alg = 'RS256'

    def sign(self, claims, alg=None, kid=None):
        alg = alg or self.alg
        header = {'alg': alg, 'kid': kid or ('r1' if alg == 'RS256' else 'e1'), 'typ': 'JWT'}
        signing_input = f"{b64(json.dumps(header).encode())}.{b64(json.dumps(claims).encode())}".encode()
        if alg == 'RS256':
            sig = self.rsa.sign(signing_input, padding.PKCS1v15(), hashes.SHA256())
        elif alg == 'ES256':
            r, s = decode_dss_signature(self.ec.sign(signing_input, ec.ECDSA(hashes.SHA256())))
            sig = r.to_bytes(32, 'big') + s.to_bytes(32, 'big')
        else:
            sig = b''
        return f'{signing_input.decode()}.{b64(sig)}'

    def claims(self, expected_nonce, **over):
        now = int(time.time())
        c = {'iss': ISSUER, 'aud': CLIENT, 'sub': 'u-123', 'email': 'alice@acme.com', 'nonce': expected_nonce,
             'iat': now, 'exp': now + 300, 'groups': ['secops'], 'amr': ['pwd', 'mfa']}
        c.update(over)
        return {k: v for k, v in c.items() if v is not None}

    def get(self, url, timeout=None):
        if url.endswith('/.well-known/openid-configuration'):
            body = {'issuer': ISSUER, 'authorization_endpoint': ISSUER + '/authorize',
                    'token_endpoint': ISSUER + '/token', 'jwks_uri': ISSUER + '/keys'}
        elif url.endswith('/keys'):
            body = self.jwks
        else:
            raise AssertionError(url)
        return Resp(body)

    def post(self, url, data=None, auth=None, timeout=None, headers=None):
        self.token_calls.append({'data': data, 'auth': auth})
        token = self.next_token(data) if callable(getattr(self, 'next_token', None)) else None
        return Resp({'id_token': token, 'token_type': 'Bearer'})


class Resp:
    def __init__(self, body, status=200):
        self.body, self.status_code = body, status

    def json(self):
        return self.body

    def raise_for_status(self):
        pass


@pytest.fixture
def idp(monkeypatch):
    fake = FakeIdP()
    monkeypatch.setattr(sso.requests, 'get', fake.get)
    monkeypatch.setattr(sso.requests, 'post', fake.post)
    sso._cache.clear()
    sso.save_config({'enabled': True, 'issuer': ISSUER, 'client_id': CLIENT, 'client_secret': 'shh',
                     'redirect_uri': 'https://console.local/api/auth/oidc/callback', 'label': 'Sign in with Acme',
                     'group_roles': {'secops': 'operator', 'it-admins': 'admin', 'helpdesk': 'viewer'}})
    return fake


@pytest.fixture
def client(idp, monkeypatch):
    from fastapi.testclient import TestClient
    from dashboard import auth_routes
    from dashboard import dashboard_api as api
    monkeypatch.setattr(auth_routes, 'login_throttle', auth.LoginThrottle())
    auth.get_store().create_user('admin', 'a-long-local-password', 'admin')     # accounts enabled
    return TestClient(api.app, follow_redirects=False)


def sign_in(client, idp, **claims):
    r = client.get('/api/auth/oidc/login')
    assert r.status_code == 303
    params = parse_qs(urlparse(r.headers['location']).query)
    assert params['code_challenge_method'] == ['S256'] and params['client_id'] == [CLIENT]
    nonce, state = params['nonce'][0], params['state'][0]
    idp.next_token = lambda data: idp.sign(idp.claims(nonce, **claims))
    return client.get('/api/auth/oidc/callback', params={'code': 'abc', 'state': state})


def test_full_sign_in_creates_an_sso_account(client, idp):
    assert client.get('/api/auth/status').json()['sso'] == {'enabled': True, 'label': 'Sign in with Acme'}
    r = sign_in(client, idp)
    assert r.status_code == 303 and r.headers['location'] == '/'
    call = idp.token_calls[-1]
    assert call['data']['client_secret'] == 'shh' and call['data']['code_verifier']
    me = client.post('/api/auth/refresh', headers={'X-Sentinel-CSRF': '1'}).json()['user']
    assert me['username'] == 'alice.acme.com' and me['role'] == 'operator'
    assert me['mfa_setup_required'] is False                      # MFA was done at the IdP (amr)
    user = auth.get_store().get_user('alice.acme.com')
    assert user['auth_source'] == 'oidc'
    with pytest.raises(auth.AuthError):
        auth.get_store().authenticate('alice.acme.com', 'anything at all', None)
    with pytest.raises(ValueError):
        auth.get_store().set_password('alice.acme.com', 'a-long-new-password')


def test_role_follows_groups_and_unmapped_users_are_refused(client, idp):
    assert sign_in(client, idp, groups=['secops', 'it-admins']).status_code == 303
    assert auth.get_store().get_user('alice.acme.com')['role'] == 'admin'
    sign_in(client, idp, groups=['helpdesk'], amr=['pwd'])
    assert auth.get_store().get_user('alice.acme.com')['role'] == 'viewer'      # demoted at the next sign-in
    r = sign_in(client, idp, groups=['marketing'])
    assert r.headers['location'] == '/?sso_error=no_role'


def test_mfa_required_for_privileged_roles(client, idp):
    r = sign_in(client, idp, amr=['pwd'])
    assert r.headers['location'] == '/?sso_error=mfa_required'
    cfg = sso.load_config()
    sso.save_config({**cfg, 'trust_idp_mfa': True})
    assert sign_in(client, idp, amr=None).headers['location'] == '/'


@pytest.mark.parametrize('claims,error', [
    ({'iss': 'https://evil.example.com'}, 'invalid_token'),
    ({'aud': 'someone-else'}, 'invalid_token'),
    ({'aud': [CLIENT, 'other'], 'azp': 'other'}, 'invalid_token'),
    ({'exp': int(time.time()) - 3600}, 'invalid_token'),
    ({'nonce': 'replayed'}, 'invalid_token'),
])
def test_bad_id_tokens_are_refused(client, idp, claims, error):
    assert sign_in(client, idp, **claims).headers['location'] == f'/?sso_error={error}'
    assert auth.get_store().get_user('alice.acme.com') is None


def test_signature_algorithms(idp):
    cfg = sso.load_config()
    good = idp.claims('n1')
    assert sso.verify_id_token(cfg, idp.sign(good, 'ES256'), 'n1')['sub'] == 'u-123'
    for alg in ('none', 'HS256'):
        with pytest.raises(sso.SSOError, match='not accepted'):
            sso.verify_id_token(cfg, idp.sign(good, alg, kid='r1'), 'n1')
    other = FakeIdP()                                          # same kid, different key
    with pytest.raises(sso.SSOError, match='signature'):
        sso.verify_id_token(cfg, other.sign(good), 'n1')
    head, body, sig = idp.sign(good).split('.')
    tampered = json.loads(base64.urlsafe_b64decode(body + '=='))
    tampered['groups'] = ['it-admins']
    with pytest.raises(sso.SSOError, match='signature'):
        sso.verify_id_token(cfg, f"{head}.{b64(json.dumps(tampered).encode())}.{sig}", 'n1')


def test_state_cookie_is_required_and_bound(client, idp):
    r = client.get('/api/auth/oidc/login')
    state = parse_qs(urlparse(r.headers['location']).query)['state'][0]
    client.cookies.clear()
    assert client.get('/api/auth/oidc/callback', params={'code': 'x', 'state': state}).headers['location'] \
        == '/?sso_error=state'
    sign_in_url = client.get('/api/auth/oidc/login')
    assert sign_in_url.status_code == 303
    assert client.get('/api/auth/oidc/callback', params={'code': 'x', 'state': 'forged'}).headers['location'] \
        == '/?sso_error=state'
    assert client.get('/api/auth/oidc/callback', params={'error': 'access_denied'}).headers['location'] \
        == '/?sso_error=denied'


def test_sso_never_takes_over_a_local_account(client, idp):
    auth.get_store().create_user('bob', 'a-long-local-password', 'viewer')
    assert sign_in(client, idp, email='bob', sub='other').headers['location'] == '/?sso_error=sso_conflict'
    sign_in(client, idp, email='carol@acme.com', sub='carol-1')
    # a different IdP subject with the same email does not get carol's account
    assert sign_in(client, idp, email='carol@acme.com', sub='carol-2').headers['location'] \
        == '/?sso_error=sso_conflict'
    auth.get_store().update_user('carol.acme.com', disabled=True)
    assert sign_in(client, idp, email='carol@acme.com', sub='carol-1').headers['location'] \
        == '/?sso_error=disabled'


def test_admin_config_is_validated_and_redacted(client, idp):
    from dashboard import dashboard_api as api
    api.app.dependency_overrides[api.require_admin] = lambda: {'username': 'admin', 'role': 'admin'}
    try:
        cfg = client.get('/api/sso').json()
        assert cfg['client_secret'] == '********'
        assert client.put('/api/sso', json={**cfg, 'label': 'Acme SSO'}).status_code == 200
        assert sso.load_config()['client_secret'] == 'shh'                  # kept
        assert client.put('/api/sso', json={**cfg, 'group_roles': {'x': 'god'}}).status_code == 400
        assert client.put('/api/sso', json={**cfg, 'issuer': 'http://plain'}).status_code == 400
    finally:
        api.app.dependency_overrides.clear()


def test_disabled_sso_is_not_reachable(client, idp):
    sso.save_config({**sso.load_config(), 'enabled': False})
    assert client.get('/api/auth/oidc/login').status_code == 404
    assert client.get('/api/auth/oidc/callback', params={'code': 'x'}).status_code == 404
