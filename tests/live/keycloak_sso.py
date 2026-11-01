"""Live OIDC and SAML sign-in against a real Keycloak 26 (scripted browser)."""
import html
import os
import re
import sys
import tempfile
from urllib.parse import parse_qs, urlsplit

HERE = os.environ.get('KC_CERTS') or os.path.dirname(os.path.abspath(__file__))
os.environ['REQUESTS_CA_BUNDLE'] = os.path.join(HERE, 'ca.pem')
tmp = tempfile.mkdtemp()
for k, f in (('SENTINEL_AUTH_DB', 'auth.db'), ('SENTINEL_AUDIT_DB', 'audit.db'), ('SENTINEL_SSO', 'sso.json'),
             ('SENTINEL_SAML', 'saml.json'), ('SENTINEL_LDAP', 'ldap.json')):
    os.environ[k] = os.path.join(tmp, f)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..')))
import requests  # noqa: E402

KC = 'https://localhost:8443'
REALM = 'sentinel'
CONSOLE = 'https://sentinel.test'

# ---------- realm setup through the admin REST API ----------
tok = requests.post(f'{KC}/realms/master/protocol/openid-connect/token',
                    data={'grant_type': 'password', 'client_id': 'admin-cli', 'username': 'admin',
                          'password': 'adminpass'}).json()['access_token']
H = {'Authorization': f'Bearer {tok}'}
A = f'{KC}/admin/realms'
requests.delete(f'{A}/{REALM}', headers=H)
requests.post(A, headers=H, json={'realm': REALM, 'enabled': True}).raise_for_status()
for g in ('SecOps-Analysts', 'SecOps-Operators'):
    requests.post(f'{A}/{REALM}/groups', headers=H, json={'name': g}).raise_for_status()
groups = {g['name']: g['id'] for g in requests.get(f'{A}/{REALM}/groups', headers=H).json()}
for user, group in (('alice', 'SecOps-Analysts'), ('oscar', 'SecOps-Operators'), ('nora', None)):
    requests.post(f'{A}/{REALM}/users', headers=H, json={
        'username': user, 'enabled': True, 'email': f'{user}@corp.example', 'emailVerified': True,
        'firstName': user.title(), 'lastName': 'Test',
        'credentials': [{'type': 'password', 'value': f'{user}-Pass-123', 'temporary': False}]}).raise_for_status()
    uid = requests.get(f'{A}/{REALM}/users', headers=H, params={'username': user, 'exact': 'true'}).json()[0]['id']
    if group:
        requests.put(f'{A}/{REALM}/users/{uid}/groups/{groups[group]}', headers=H).raise_for_status()
group_mapper = {'name': 'groups', 'protocolMapper': 'oidc-group-membership-mapper', 'protocol': 'openid-connect',
                'config': {'claim.name': 'groups', 'full.path': 'false', 'id.token.claim': 'true',
                           'access.token.claim': 'true', 'userinfo.token.claim': 'true'}}
requests.post(f'{A}/{REALM}/clients', headers=H, json={
    'clientId': 'sentinel-console', 'protocol': 'openid-connect', 'publicClient': False, 'secret': 'oidc-secret',
    'redirectUris': [f'{CONSOLE}/api/auth/oidc/callback'], 'standardFlowEnabled': True,
    'protocolMappers': [group_mapper]}).raise_for_status()
saml_mapper = {'name': 'groups', 'protocolMapper': 'saml-group-membership-mapper', 'protocol': 'saml',
               'config': {'attribute.name': 'groups', 'full.path': 'false', 'single': 'false'}}
requests.post(f'{A}/{REALM}/clients', headers=H, json={
    'clientId': f'{CONSOLE}/api/auth/saml/metadata', 'protocol': 'saml', 'enabled': True,
    'redirectUris': [f'{CONSOLE}/api/auth/saml/acs'],
    'attributes': {'saml.assertion.signature': 'true', 'saml.server.signature': 'true',
                   'saml.signature.algorithm': 'RSA_SHA256', 'saml.client.signature': 'false',
                   'saml.authnstatement': 'true', 'saml_force_name_id_format': 'true',
                   'saml_name_id_format': 'username', 'saml_assertion_consumer_url_post': f'{CONSOLE}/api/auth/saml/acs'},
    'protocolMappers': [saml_mapper]}).raise_for_status()
descriptor = requests.get(f'{KC}/realms/{REALM}/protocol/saml/descriptor').text
idp_cert = re.search(r'<(?:ds:|dsig:)?X509Certificate>([^<]+)<', descriptor).group(1)
idp_pem = '-----BEGIN CERTIFICATE-----\n' + '\n'.join(re.findall('.{1,64}', idp_cert)) + '\n-----END CERTIFICATE-----'
print('realm ready')

# ---------- console configuration ----------
from fastapi.testclient import TestClient  # noqa: E402
from core import auth, saml, sso  # noqa: E402
from dashboard import dashboard_api as api  # noqa: E402

auth.get_store().create_user('admin', 'local-admin-Pass-1', 'admin')
sso.save_config({'enabled': True, 'issuer': f'{KC}/realms/{REALM}', 'client_id': 'sentinel-console',
                 'client_secret': 'oidc-secret', 'username_claim': 'preferred_username',
                 'group_roles': {'SecOps-Analysts': 'analyst', 'SecOps-Operators': 'operator'}})
saml.save_config({'enabled': True, 'idp_entity_id': f'{KC}/realms/{REALM}',
                  'idp_sso_url': f'{KC}/realms/{REALM}/protocol/saml', 'idp_certs': [idp_pem],
                  'group_roles': {'SecOps-Analysts': 'analyst', 'SecOps-Operators': 'operator'}})


def keycloak_login(browser, url, user):
    page = browser.get(url)
    action = html.unescape(re.search(r'<form[^>]+action="([^"]+)"', page.text).group(1))
    return browser.post(action, data={'username': user, 'password': f'{user}-Pass-123', 'credentialId': ''},
                        allow_redirects=False)


def oidc(user):
    console, browser = TestClient(api.app, base_url=CONSOLE), requests.Session()
    r = console.get('/api/auth/oidc/login', follow_redirects=False)
    assert r.status_code == 303, r.text
    r = keycloak_login(browser, r.headers['location'], user)
    loc = r.headers.get('location', '')
    assert loc.startswith(f'{CONSOLE}/api/auth/oidc/callback'), (r.status_code, loc[:200], r.text[:300])
    r = console.get(loc[len(CONSOLE):], follow_redirects=False)
    return r.headers['location'], auth.get_store().get_user(user)


def saml_flow(user):
    console, browser = TestClient(api.app, base_url=CONSOLE), requests.Session()
    r = console.get('/api/auth/saml/login', follow_redirects=False)
    assert r.status_code == 303, r.text
    r = keycloak_login(browser, r.headers['location'], user)
    while r.status_code in (302, 303):
        r = browser.get(r.headers['location'], allow_redirects=False)
    form = dict(re.findall(r'name="(SAMLResponse|RelayState)"\s+value="([^"]*)"', r.text))
    assert 'SAMLResponse' in form, r.text[:500]
    r = console.post('/api/auth/saml/acs', data={k: html.unescape(v) for k, v in form.items()}, follow_redirects=False)
    return r.headers['location'], auth.get_store().get_user(user)


for name, flow in (('OIDC', oidc), ('SAML', saml_flow)):
    for user in ('alice', 'oscar', 'nora'):
        where, account = flow(user)
        print(f'{name:4} {user:6} -> {where:28} account: '
              + (f"{account['role']} via {account['auth_source']}" if account else 'none'))
        if account:                                     # next protocol: start from a clean account table
            auth.get_store()._execute('DELETE FROM users WHERE username = ?', (user,))
