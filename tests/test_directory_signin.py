"""SAML 2.0 and LDAP / Active Directory sign-in (Phase 10)."""
import base64
import datetime
import json
import zlib
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from ldap3 import MOCK_SYNC, Connection, Server
from lxml import etree
from signxml import XMLSigner

from core import auth, ldap_auth, saml

PASSWORD = 'correct horse battery staple 42'
SECRET = b'k' * 32
BASE = 'https://sentinel.example.org'
IDP = 'https://idp.example.org/saml'
NOW = 1_800_000_000


# ======================= LDAP =======================

BASE_DN = 'dc=corp,dc=example'


@pytest.fixture()
def directory(monkeypatch):
    monkeypatch.setattr(ldap_auth, 'CLIENT_STRATEGY', MOCK_SYNC)
    server = Server('ldaps://dc1.corp.example')
    setup = Connection(server, user='cn=svc,ou=svc,dc=corp,dc=example', password='svc-secret',
                       client_strategy=MOCK_SYNC)
    add = setup.strategy.add_entry
    add('cn=svc,ou=svc,dc=corp,dc=example', {'objectClass': ['user'], 'userPassword': 'svc-secret',
                                              'sAMAccountName': 'svc'})
    add('cn=Alice,ou=people,dc=corp,dc=example', {
        'objectClass': ['user'], 'sAMAccountName': 'alice', 'userPassword': 'Alice-pass-1',
        'memberOf': ['CN=SecOps,OU=Groups,DC=corp,DC=example'], 'entryUUID': '1111-aaaa'})
    add('cn=Bob,ou=people,dc=corp,dc=example', {
        'objectClass': ['user'], 'sAMAccountName': 'bob', 'userPassword': 'Bob-pass-1',
        'memberOf': ['CN=Staff,OU=Groups,DC=corp,DC=example'], 'entryUUID': '2222-bbbb'})
    add('cn=Admin2,ou=people,dc=corp,dc=example', {
        'objectClass': ['user'], 'sAMAccountName': 'admin', 'userPassword': 'Evil-pass-1',
        'memberOf': ['CN=IT-Admins,OU=Groups,DC=corp,DC=example'], 'entryUUID': '3333-cccc'})
    cfg = ldap_auth.save_config({'enabled': True, 'url': 'ldaps://dc1.corp.example', 'base_dn': BASE_DN,
                                 'bind_dn': 'cn=svc,ou=svc,dc=corp,dc=example', 'bind_password': 'svc-secret',
                                 'group_roles': {'SecOps': 'operator', 'CN=IT-Admins,OU=Groups,DC=corp,DC=example': 'admin'},
                                 'default_role': None, 'nested_groups': False})
    monkeypatch.setattr(ldap_auth, '_server', lambda c: server)
    return cfg


def test_ldap_config_requires_encryption():
    base = {'enabled': True, 'base_dn': BASE_DN, 'bind_dn': 'cn=svc'}
    with pytest.raises(ValueError, match='start_tls'):
        ldap_auth.validate({**base, 'url': 'ldap://dc1'})
    with pytest.raises(ValueError):
        ldap_auth.validate({**base, 'url': 'http://dc1'})
    assert ldap_auth.validate({**base, 'url': 'ldap://dc1', 'start_tls': True})
    assert ldap_auth.redacted(ldap_auth.validate({**base, 'url': 'ldaps://dc1', 'bind_password': 'x'}))['bind_password'] == '********'


def test_ldap_authenticate_and_roles(directory):
    name, role, ext, dn = ldap_auth.authenticate('alice', 'Alice-pass-1')
    assert (name, role, dn) == ('alice', 'operator', 'cn=Alice,ou=people,dc=corp,dc=example')
    with pytest.raises(ldap_auth.LDAPError, match='refused the password'):
        ldap_auth.authenticate('alice', 'wrong')
    with pytest.raises(ldap_auth.LDAPError, match='anonymous'):
        ldap_auth.authenticate('alice', '')                     # empty password = anonymous bind
    with pytest.raises(ldap_auth.LDAPError) as exc:
        ldap_auth.authenticate('bob', 'Bob-pass-1')
    assert exc.value.code == 'no_role'
    with pytest.raises(ldap_auth.LDAPError, match='characters'):
        ldap_auth.authenticate('*)(sAMAccountName=*', 'x')     # filter injection never reaches the directory
    with pytest.raises(ldap_auth.LDAPError, match='0 directory entries'):
        ldap_auth.authenticate('nobody', 'x')
    assert ldap_auth.lookup('alice')['role'] == 'operator'


def test_ldap_sign_in_through_the_store(directory):
    store = auth.get_store()
    user = store.authenticate('alice', 'Alice-pass-1')
    assert user['role'] == 'operator' and user['auth_source'] == 'ldap'
    assert user['mfa_setup_required'] is True                  # directory password = one factor: enrol TOTP
    with pytest.raises(auth.AuthError):
        store.authenticate('alice', 'wrong')
    with pytest.raises(ValueError):
        store.set_password('alice', 'another long password 1')     # managed in the directory


def test_ldap_never_takes_over_a_local_account(directory):
    store = auth.get_store()
    store.create_user('admin', PASSWORD, 'admin')
    # the local account signs in with its own password; the directory 'admin' cannot use it
    assert store.authenticate('admin', PASSWORD)['auth_source'] == 'local'
    with pytest.raises(auth.AuthError):
        store.authenticate('admin', 'Evil-pass-1')


def test_ldap_lockout_after_repeated_failures(directory):
    store = auth.get_store()
    store.authenticate('alice', 'Alice-pass-1')
    for _ in range(auth.MAX_FAILED_LOGINS):
        with pytest.raises(auth.AuthError):
            store.authenticate('alice', 'wrong')
    with pytest.raises(auth.AuthError) as exc:
        store.authenticate('alice', 'Alice-pass-1')
    assert exc.value.status == 423


def test_ldap_disabled_falls_back_to_local_only():
    store = auth.get_store()
    with pytest.raises(auth.AuthError, match='unknown user'):
        store.authenticate('alice', 'Alice-pass-1')


# ======================= SAML =======================

def idp_key_and_cert(cn='idp.example.org'):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.datetime(2026, 1, 1, tzinfo=datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=3650)).sign(key, hashes.SHA256()))
    return (key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                              serialization.NoEncryption()),
            cert.public_bytes(serialization.Encoding.PEM).decode())


KEY, CERT = idp_key_and_cert()
ENTITY, ACS = f'{BASE}/api/auth/saml/metadata', f'{BASE}/api/auth/saml/acs'


def iso(ts):
    return datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def assertion_xml(request_id, name_id='alice@corp.example', groups=('SecOps',), audience=ENTITY, recipient=ACS,
                  issuer=IDP, not_after=NOW + 300, aid='_a1', mfa=True):
    ctx = ('http://schemas.microsoft.com/claims/multipleauthn' if mfa
           else 'urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport')
    vals = ''.join(f'<saml:AttributeValue>{g}</saml:AttributeValue>' for g in groups)
    return (f'<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{aid}" Version="2.0" '
            f'IssueInstant="{iso(NOW)}"><saml:Issuer>{issuer}</saml:Issuer>'
            f'<saml:Subject><saml:NameID>{name_id}</saml:NameID>'
            '<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer">'
            f'<saml:SubjectConfirmationData InResponseTo="{request_id}" Recipient="{recipient}" '
            f'NotOnOrAfter="{iso(not_after)}"/></saml:SubjectConfirmation></saml:Subject>'
            f'<saml:Conditions NotBefore="{iso(NOW - 60)}" NotOnOrAfter="{iso(not_after)}">'
            f'<saml:AudienceRestriction><saml:Audience>{audience}</saml:Audience></saml:AudienceRestriction>'
            '</saml:Conditions>'
            f'<saml:AuthnStatement AuthnInstant="{iso(NOW)}"><saml:AuthnContext><saml:AuthnContextClassRef>{ctx}'
            '</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement>'
            f'<saml:AttributeStatement><saml:Attribute Name="groups">{vals}</saml:Attribute></saml:AttributeStatement>'
            '</saml:Assertion>')


def sign(xml, key=KEY, cert=CERT):
    el = etree.fromstring(xml.encode())
    signed = XMLSigner(c14n_algorithm='http://www.w3.org/2001/10/xml-exc-c14n#').sign(el, key=key, cert=cert)
    return etree.tostring(signed).decode()


def response(inner, signed_response=False):
    xml = ('<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" '
           'xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="_r1" Version="2.0" '
           f'IssueInstant="{iso(NOW)}" Destination="{ACS}"><saml:Issuer>{IDP}</saml:Issuer>'
           '<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>'
           f'{inner}</samlp:Response>')
    return sign(xml) if signed_response else xml


@pytest.fixture()
def saml_cfg():
    return saml.save_config({'enabled': True, 'idp_entity_id': IDP, 'idp_sso_url': 'https://idp.example.org/sso',
                             'idp_certs': [CERT], 'group_roles': {'SecOps': 'operator', 'Admins': 'admin'}})


def started(cfg):
    url, cookie = saml.start(cfg, BASE, SECRET, now=NOW)
    q = parse_qs(urlsplit(url).query)
    request = zlib.decompress(base64.b64decode(q['SAMLRequest'][0]), -15)
    request_id = etree.fromstring(request).get('ID')
    return request_id, q['RelayState'][0], cookie, request


def finish(cfg, xml, relay, cookie):
    return saml.complete(cfg, base64.b64encode(xml.encode()).decode(), relay, cookie, SECRET, BASE, now=NOW)


def test_authn_request_and_metadata(saml_cfg):
    rid, relay, cookie, request = started(saml_cfg)
    root = etree.fromstring(request)
    assert root.get('AssertionConsumerServiceURL') == ACS and root.get('Destination') == 'https://idp.example.org/sso'
    assert root.find('{urn:oasis:names:tc:SAML:2.0:assertion}Issuer').text == ENTITY
    md = etree.fromstring(saml.metadata(saml_cfg, BASE).encode())
    assert md.get('entityID') == ENTITY and ACS in saml.metadata(saml_cfg, BASE)


def test_signed_assertion_signs_in(saml_cfg):
    rid, relay, cookie, _ = started(saml_cfg)
    username, role, claims = finish(saml_cfg, response(sign(assertion_xml(rid))), relay, cookie)
    assert (username, role) == ('alice', 'operator') and claims['name_id'] == 'alice@corp.example'
    # a signed Response (assertion unsigned inside it) works too
    rid, relay, cookie, _ = started(saml_cfg)
    assert finish(saml_cfg, response(assertion_xml(rid, aid='_a2'), signed_response=True), relay, cookie)[1] == 'operator'


def test_refusals(saml_cfg):
    def attempt(xml_for, **kw):
        rid, relay, cookie, _ = started(saml_cfg)
        with pytest.raises(saml.SAMLError) as exc:
            finish(saml_cfg, xml_for(rid), kw.get('relay', relay), kw.get('cookie', cookie))
        return exc.value

    assert 'not signed' in attempt(lambda r: response(assertion_xml(r))).reason
    other_key, other_cert = idp_key_and_cert('evil')
    assert 'signature' in attempt(lambda r: response(sign(assertion_xml(r), other_key, other_cert))).reason
    assert 'another service' in attempt(lambda r: response(sign(assertion_xml(r, audience='https://other/sp')))).reason
    assert 'issuer' in attempt(lambda r: response(sign(assertion_xml(r, issuer='https://evil/idp')))).reason
    assert 'valid at this time' in attempt(lambda r: response(sign(assertion_xml(r, not_after=NOW - 600)))).reason
    assert 'bearer' in attempt(lambda r: response(sign(assertion_xml('_unsolicited')))).reason
    assert 'bearer' in attempt(lambda r: response(sign(assertion_xml(r, recipient='https://evil/acs')))).reason
    assert attempt(lambda r: response(sign(assertion_xml(r))), relay='forged').code == 'state'
    assert attempt(lambda r: response(sign(assertion_xml(r))), cookie='x.y').code == 'state'
    assert attempt(lambda r: response(sign(assertion_xml(r, groups=('Nobody',), aid='_n1')))).code == 'no_role'
    assert attempt(lambda r: response(sign(assertion_xml(r, groups=('Admins',), mfa=False, aid='_m1')))).code == 'mfa_required'
    assert 'DTD' in attempt(lambda r: '<!DOCTYPE x [<!ENTITY e SYSTEM "file:///etc/passwd">]>' +
                            response(sign(assertion_xml(r)))).reason


def test_tampering_and_wrapping_attacks(saml_cfg):
    def attempt(xml):
        rid, relay, cookie, _ = started(saml_cfg)
        with pytest.raises(saml.SAMLError) as exc:
            finish(saml_cfg, xml(rid), relay, cookie)
        return exc.value.reason

    # change the NameID after signing
    assert 'signature' in attempt(lambda r: response(sign(assertion_xml(r)).replace('alice@corp', 'admin@corp')))
    # escalate groups after signing
    assert 'signature' in attempt(lambda r: response(sign(assertion_xml(r)).replace('>SecOps<', '>Admins<')))
    # wrapping: a second, unsigned assertion next to the signed one
    assert 'exactly one' in attempt(lambda r: response(sign(assertion_xml(r)) +
                                                       assertion_xml(r, name_id='admin', groups=('Admins',), aid='_x')))
    # wrapping: the signed assertion hidden in an extension, an evil one in its place
    assert 'exactly one' in attempt(lambda r: response(
        assertion_xml(r, name_id='admin', groups=('Admins',), aid='_x') +
        '<samlp:Extensions>' + sign(assertion_xml(r)) + '</samlp:Extensions>'))
    # signed Response, then its assertion swapped out
    def swapped(r):
        signed = response(assertion_xml(r, aid='_ok'), signed_response=True)
        return signed.replace('alice@corp.example', 'admin@corp.example')
    assert 'signature' in attempt(swapped)


def test_comment_truncation_attack(saml_cfg):
    # the IdP signs "admin@corp.example<!---->.evil.com"; naive text extraction would read "admin@corp.example"
    rid, relay, cookie, _ = started(saml_cfg)
    signed = sign(assertion_xml(rid, name_id='admin@corp.example<!---->.evil.com'))
    username, _, claims = finish(saml_cfg, response(signed), relay, cookie)
    assert claims['name_id'] == 'admin@corp.example.evil.com'


def test_replay_is_refused(saml_cfg):
    rid, relay, cookie, _ = started(saml_cfg)
    xml = response(sign(assertion_xml(rid, aid='_once')))
    finish(saml_cfg, xml, relay, cookie)
    with pytest.raises(saml.SAMLError, match='already used'):
        finish(saml_cfg, xml, relay, cookie)


def test_saml_config_validation():
    with pytest.raises(ValueError, match='certificate'):
        saml.validate({'enabled': True, 'idp_entity_id': IDP, 'idp_sso_url': 'https://idp/sso', 'idp_certs': []})
    with pytest.raises(ValueError, match='https'):
        saml.validate({'enabled': True, 'idp_entity_id': IDP, 'idp_sso_url': 'http://idp/sso', 'idp_certs': [CERT]})
    with pytest.raises(ValueError, match='PEM'):
        saml.validate({'idp_certs': ['not a cert']})
    assert saml.validate({'idp_certs': CERT + '\n' + CERT})['idp_certs'] == [CERT.strip(), CERT.strip()]


def test_acs_endpoint_end_to_end(saml_cfg, monkeypatch):
    from fastapi.testclient import TestClient
    from dashboard import dashboard_api as api
    monkeypatch.setattr(saml.time, 'time', lambda: NOW)
    client = TestClient(api.app, base_url=BASE)
    r = client.get('/api/auth/saml/login', follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'].startswith('https://idp.example.org/sso?')
    assert 'samesite=none' in r.headers['set-cookie'].lower()
    q = parse_qs(urlsplit(r.headers['location']).query)
    rid = etree.fromstring(zlib.decompress(base64.b64decode(q['SAMLRequest'][0]), -15)).get('ID')
    body = {'SAMLResponse': base64.b64encode(response(sign(assertion_xml(rid, aid='_e2e'))).encode()).decode(),
            'RelayState': q['RelayState'][0]}
    r = client.post('/api/auth/saml/acs', data=body, follow_redirects=False)
    assert r.status_code == 303 and r.headers['location'] == '/'
    assert 'sentinel_refresh' in r.headers.get('set-cookie', '') or any('refresh' in c for c in r.headers.get_list('set-cookie'))
    user = auth.get_store().get_user('alice')
    assert user['auth_source'] == 'saml' and user['role'] == 'operator' and user['mfa_setup_required'] is False
    status = client.get('/api/auth/status').json()
    assert status['saml']['enabled'] is True
