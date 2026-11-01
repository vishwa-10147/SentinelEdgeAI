"""Single sign-on with SAML 2.0 (Phase 10): ADFS, Entra ID, Okta, Shibboleth, Keycloak, ...

SP-initiated Web Browser SSO: GET /api/auth/saml/login sends the browser to the
IdP with an AuthnRequest (HTTP-Redirect binding); the IdP posts a signed
Response to the assertion consumer service, POST /api/auth/saml/acs.
The SP metadata for the IdP is at GET /api/auth/saml/metadata.

XML signatures are checked by signxml (lxml + cryptography), never by hand.
What is checked before anyone is signed in:
  * the document is parsed without DTDs, entities or network access, and
    comments are removed (the "NameID comment" truncation attack);
  * exactly one Assertion, not encrypted; it, or the Response around it, is
    signed by the configured IdP certificate (several allowed, for rollover),
    SHA-256 or stronger; every value is read from the element the signature
    covers, never from the unsigned document (signature-wrapping attacks);
  * Issuer is the configured IdP entity id; Audience contains our entity id;
    NotBefore / NotOnOrAfter hold (2 minutes clock skew); a bearer
    SubjectConfirmation with Recipient = our ACS URL, InResponseTo = the
    request this browser started (an HMAC-signed, 10-minute cookie), so
    IdP-initiated (unsolicited) responses are refused;
  * each assertion ID is accepted once (replay cache);
  * roles from mapped groups (highest wins) or default_role, else refused;
    Operator and Admin need an MFA authentication context from the IdP unless
    trust_idp_mfa; the account is pinned to (IdP entity id, NameID) and can
    never take over a local account of the same name.

Configuration (Admin, GET/PUT /api/saml; data/saml.json, SENTINEL_SAML):
  enabled, label, idp_entity_id, idp_sso_url, idp_certs [PEM, ...],
  sp_entity_id / acs_url (default: this console's /api/auth/saml/metadata and /acs),
  username_attribute (default: the NameID), groups_attribute (default "groups";
  Entra: http://schemas.microsoft.com/ws/2008/06/identity/claims/groups),
  group_roles {group: role}, default_role, trust_idp_mfa.
"""
import base64
import datetime
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time
import zlib
from urllib.parse import urlencode

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
STATE_TTL = 600
CLOCK_SKEW = 120
MAX_RESPONSE = 256 * 1024
NS = {'samlp': 'urn:oasis:names:tc:SAML:2.0:protocol', 'saml': 'urn:oasis:names:tc:SAML:2.0:assertion',
      'ds': 'http://www.w3.org/2000/09/xmldsig#'}
BEARER = 'urn:oasis:names:tc:SAML:2.0:cm:bearer'
SUCCESS = 'urn:oasis:names:tc:SAML:2.0:status:Success'
MFA_CONTEXTS = {
    'http://schemas.microsoft.com/claims/multipleauthn',
    'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorContract',
    'urn:oasis:names:tc:SAML:2.0:ac:classes:MobileTwoFactorUnregistered',
    'urn:oasis:names:tc:SAML:2.0:ac:classes:TimeSyncToken',
    'urn:oasis:names:tc:SAML:2.0:ac:classes:Smartcard',
    'urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI',
    'urn:rsa:names:tc:SAML:2.0:ac:classes:FIDO',
    'https://refeds.org/profile/mfa',
}
DEFAULTS = {'enabled': False, 'label': 'Sign in with SAML', 'idp_entity_id': '', 'idp_sso_url': '',
            'idp_certs': [], 'sp_entity_id': '', 'acs_url': '', 'username_attribute': '',
            'groups_attribute': 'groups', 'group_roles': {}, 'default_role': None, 'trust_idp_mfa': False}
_replay_lock = threading.Lock()


class SAMLError(Exception):
    def __init__(self, code, reason):
        super().__init__(reason)
        self.code, self.reason = code, reason


# ---------------- configuration ----------------

def config_file():
    return os.environ.get('SENTINEL_SAML') or os.path.join(ROOT, 'data', 'saml.json')


def load_config():
    try:
        with open(config_file(), 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    return {**DEFAULTS, **(data if isinstance(data, dict) else {})}


def _load_cert(pem):
    from cryptography import x509
    return x509.load_pem_x509_certificate(str(pem).strip().encode('ascii'))


def validate(cfg):
    from core import auth
    cfg = {**DEFAULTS, **cfg}
    if isinstance(cfg['idp_certs'], str):
        cfg['idp_certs'] = re.findall(r'-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----', cfg['idp_certs'], re.S)
    certs = []
    for pem in cfg['idp_certs'] or []:
        try:
            _load_cert(pem)
        except (ValueError, TypeError):
            raise ValueError('idp_certs must be PEM certificates (-----BEGIN CERTIFICATE-----)')
        certs.append(str(pem).strip())
    cfg['idp_certs'] = certs
    if cfg['enabled']:
        if not cfg['idp_entity_id']:
            raise ValueError('SAML needs the IdP entity id (idp_entity_id)')
        if not str(cfg['idp_sso_url']).startswith('https://'):
            raise ValueError('idp_sso_url must be an https:// URL')
        if not certs:
            raise ValueError('SAML needs the IdP signing certificate (idp_certs)')
    if not isinstance(cfg['group_roles'], dict):
        raise ValueError('group_roles must map group names or ids to roles')
    for role in cfg['group_roles'].values():
        auth.validate_role(role)
    if cfg['default_role'] not in (None, ''):
        auth.validate_role(cfg['default_role'])
    return cfg


def save_config(cfg):
    cfg = validate(dict(cfg))
    path = config_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2)
    os.replace(path + '.tmp', path)
    return cfg


def enabled():
    return bool(load_config().get('enabled'))


def endpoints(cfg, base_url):
    """(sp_entity_id, acs_url) from the configuration or this console's address."""
    base = base_url.rstrip('/')
    return (cfg.get('sp_entity_id') or f'{base}/api/auth/saml/metadata',
            cfg.get('acs_url') or f'{base}/api/auth/saml/acs')


def metadata(cfg, base_url):
    entity, acs = endpoints(cfg, base_url)
    esc = lambda v: (v.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;'))  # noqa: E731
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{esc(entity)}">'
            '<md:SPSSODescriptor AuthnRequestsSigned="false" WantAssertionsSigned="true" '
            'protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
            '<md:NameIDFormat>urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified</md:NameIDFormat>'
            '<md:AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" '
            f'Location="{esc(acs)}" index="0" isDefault="true"/>'
            '</md:SPSSODescriptor></md:EntityDescriptor>\n')


# ---------------- request ----------------

def _b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def _b64d(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def _sign(secret, payload):
    return _b64e(hmac.new(secret, payload.encode(), hashlib.sha256).digest())


def _instant(ts):
    return datetime.datetime.fromtimestamp(int(ts), datetime.timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def start(cfg, base_url, secret, now=None):
    """(IdP redirect URL, signed state cookie) for a new sign-in."""
    now = now or time.time()
    entity, acs = endpoints(cfg, base_url)
    request_id = '_' + secrets.token_hex(20)
    esc = lambda v: (v.replace('&', '&amp;').replace('"', '&quot;').replace('<', '&lt;'))  # noqa: E731
    xml = (f'<samlp:AuthnRequest xmlns:samlp="{NS["samlp"]}" xmlns:saml="{NS["saml"]}" ID="{request_id}" '
           f'Version="2.0" IssueInstant="{_instant(now)}" Destination="{esc(cfg["idp_sso_url"])}" '
           f'AssertionConsumerServiceURL="{esc(acs)}" '
           'ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST">'
           f'<saml:Issuer>{esc(entity)}</saml:Issuer><samlp:NameIDPolicy AllowCreate="true"/>'
           '</samlp:AuthnRequest>')
    deflate = zlib.compressobj(9, zlib.DEFLATED, -15)
    encoded = base64.b64encode(deflate.compress(xml.encode()) + deflate.flush()).decode('ascii')
    relay = secrets.token_urlsafe(16)
    sep = '&' if '?' in cfg['idp_sso_url'] else '?'
    url = cfg['idp_sso_url'] + sep + urlencode({'SAMLRequest': encoded, 'RelayState': relay})
    payload = _b64e(json.dumps({'i': request_id, 'r': relay, 'e': int(now + STATE_TTL)}).encode())
    return url, f'{payload}.{_sign(secret, payload)}'


def read_state(cookie, secret, now=None):
    payload, _, mac = str(cookie or '').rpartition('.')
    if not payload or not hmac.compare_digest(mac, _sign(secret, payload)):
        raise SAMLError('state', 'sign-in state cookie missing or altered; start again from the console')
    data = json.loads(_b64d(payload))
    if data['e'] < (now or time.time()):
        raise SAMLError('state', 'sign-in took more than 10 minutes; start again')
    return data


# ---------------- response ----------------

def _parse(xml_bytes):
    from lxml import etree
    if b'<!DOCTYPE' in xml_bytes or b'<!ENTITY' in xml_bytes:
        raise SAMLError('invalid_token', 'SAML response contains a DTD')
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False, dtd_validation=False,
                             huge_tree=False, remove_comments=True, remove_pis=True)
    try:
        return etree.fromstring(xml_bytes, parser=parser)
    except etree.XMLSyntaxError as exc:
        raise SAMLError('invalid_token', f'SAML response is not valid XML: {exc}')


def _tag(name):
    prefix, local = name.split(':')
    return f'{{{NS[prefix]}}}{local}'


def _verify(element, certs):
    """The signed element (as signxml returns it) for a signature that is a direct child of `element`."""
    from lxml import etree
    from signxml import XMLVerifier
    from signxml.exceptions import InvalidInput, InvalidSignature
    data = etree.tostring(element)
    last = None
    for pem in certs:
        try:
            return XMLVerifier().verify(data, x509_cert=pem).signed_xml
        except (InvalidSignature, InvalidInput, ValueError) as exc:
            last = exc
    raise SAMLError('invalid_token', f'SAML signature not valid for the configured IdP certificate ({last})')


def _text(el):
    if el is None:
        return ''
    from lxml import etree
    for c in list(el.iter(etree.Comment)):                 # parsed without comments; signxml re-parses
        parent = c.getparent()
        if parent is not None:
            parent.remove(c)
    return ''.join(el.itertext()).strip()


def _time(value):
    if not value:
        return None
    value = re.sub(r'\.\d+', '', value.strip()).replace('Z', '+00:00')
    try:
        return datetime.datetime.fromisoformat(value).timestamp()
    except ValueError:
        raise SAMLError('invalid_token', f'bad SAML time {value!r}')


def signed_assertion(xml_bytes, certs):
    """The Assertion element covered by a valid IdP signature, or SAMLError."""
    root = _parse(xml_bytes)
    if root.tag != _tag('samlp:Response'):
        raise SAMLError('invalid_token', 'not a SAML Response')
    status = root.find('samlp:Status/samlp:StatusCode', NS)
    if status is None or status.get('Value') != SUCCESS:
        raise SAMLError('idp_error', f'the IdP refused the sign-in ({status.get("Value") if status is not None else "no status"})')
    if root.findall('.//saml:EncryptedAssertion', NS):
        raise SAMLError('invalid_token', 'encrypted assertions are not supported; turn off assertion encryption')
    every = root.findall('.//saml:Assertion', NS)
    children = root.findall('saml:Assertion', NS)
    if len(every) != 1 or len(children) != 1:
        raise SAMLError('invalid_token', f'expected exactly one Assertion, found {len(every)}')
    assertion = children[0]
    if assertion.find('ds:Signature', NS) is not None:
        signed = _verify(assertion, certs)
        if signed.tag != _tag('saml:Assertion'):
            raise SAMLError('invalid_token', 'the signature does not cover the Assertion')
        return signed
    if root.find('ds:Signature', NS) is not None:
        signed = _verify(root, certs)
        inner = signed.findall('saml:Assertion', NS) if signed.tag == _tag('samlp:Response') else []
        if len(inner) != 1 or len(signed.findall('.//saml:Assertion', NS)) != 1:
            raise SAMLError('invalid_token', 'the signature does not cover exactly one Assertion')
        return inner[0]
    raise SAMLError('invalid_token', 'the SAML response is not signed')


def _replay_file():
    return os.path.join(os.path.dirname(os.path.abspath(config_file())), 'saml_replay.json')


def _once(assertion_id, until, now):
    with _replay_lock:
        try:
            with open(_replay_file(), encoding='utf-8') as f:
                seen = json.load(f)
        except (OSError, ValueError):
            seen = {}
        seen = {k: v for k, v in seen.items() if v > now}
        if assertion_id in seen:
            raise SAMLError('invalid_token', 'this SAML assertion was already used (replay)')
        seen[assertion_id] = max(until, now + 600)
        tmp = _replay_file() + '.tmp'
        with open(tmp, 'w', encoding='utf-8') as f:
            json.dump(seen, f)
        os.replace(tmp, _replay_file())


def check_assertion(cfg, assertion, entity, acs, request_id, now=None):
    """The claims of a signed assertion after every condition is checked."""
    now = now or time.time()
    if _text(assertion.find('saml:Issuer', NS)) != cfg['idp_entity_id']:
        raise SAMLError('invalid_token', 'assertion issuer is not the configured IdP')
    cond = assertion.find('saml:Conditions', NS)
    if cond is None:
        raise SAMLError('invalid_token', 'assertion has no Conditions')
    nb, noa = _time(cond.get('NotBefore')), _time(cond.get('NotOnOrAfter'))
    if (nb and now + CLOCK_SKEW < nb) or not noa or now - CLOCK_SKEW >= noa:
        raise SAMLError('invalid_token', 'assertion is not valid at this time (check the clocks)')
    audiences = [_text(a) for a in cond.findall('saml:AudienceRestriction/saml:Audience', NS)]
    if entity not in audiences:
        raise SAMLError('invalid_token', f'assertion is for another service ({", ".join(audiences) or "no audience"})')
    subject = assertion.find('saml:Subject', NS)
    name_id = _text(subject.find('saml:NameID', NS)) if subject is not None else ''
    if not name_id:
        raise SAMLError('invalid_token', 'assertion has no NameID')
    ok = False
    for sc in subject.findall('saml:SubjectConfirmation', NS):
        data = sc.find('saml:SubjectConfirmationData', NS)
        if sc.get('Method') != BEARER or data is None:
            continue
        until = _time(data.get('NotOnOrAfter'))
        if data.get('Recipient') == acs and data.get('InResponseTo') == request_id and until \
                and now - CLOCK_SKEW < until:
            ok = True
            break
    if not ok:
        raise SAMLError('invalid_token', 'no bearer confirmation for this console and this sign-in '
                                         '(recipient, InResponseTo or expiry); unsolicited responses are refused')
    _once(assertion.get('ID') or hashlib.sha256(name_id.encode()).hexdigest(), noa, now)
    attrs = {}
    for a in assertion.findall('saml:AttributeStatement/saml:Attribute', NS):
        values = [_text(v) for v in a.findall('saml:AttributeValue', NS)]
        for key in (a.get('Name'), a.get('FriendlyName')):
            if key:
                attrs.setdefault(key, []).extend(values)
    contexts = {_text(c) for c in assertion.findall('saml:AuthnStatement/saml:AuthnContext/saml:AuthnContextClassRef', NS)}
    return {'name_id': name_id, 'attributes': attrs, 'authn_contexts': sorted(contexts)}


def role_for(cfg, claims):
    from core import auth
    groups = claims['attributes'].get(cfg['groups_attribute'] or 'groups', [])
    mapping = cfg['group_roles']
    roles = [mapping[g] for g in groups if g in mapping]
    if roles:
        return max(roles, key=auth.ROLE_RANK.get)
    if cfg.get('default_role'):
        return cfg['default_role']
    raise SAMLError('no_role', 'none of your groups is allowed to use this console')


def username_for(cfg, claims):
    raw = claims['name_id']
    if cfg.get('username_attribute'):
        raw = (claims['attributes'].get(cfg['username_attribute']) or [raw])[0]
    raw = raw.split('@')[0] if '@' in raw else raw
    name = re.sub(r'[^A-Za-z0-9_.-]', '.', raw).strip('.')[:32]
    if len(name) < 3:
        name = ('saml.' + hashlib.sha256(claims['name_id'].encode()).hexdigest())[:16]
    return name


def external_id(cfg, claims):
    return hashlib.sha256(f"saml|{cfg['idp_entity_id']}|{claims['name_id']}".encode()).hexdigest()[:32]


def check_mfa(cfg, claims, role):
    from core import auth
    if not auth.mfa_required_for(role) or cfg.get('trust_idp_mfa'):
        return
    if not MFA_CONTEXTS & set(claims['authn_contexts']):
        raise SAMLError('mfa_required', f'the {role} role needs multi-factor sign-in at the identity provider')


def complete(cfg, saml_response_b64, relay_state, cookie, secret, base_url, now=None):
    """(username, role, claims) for a finished sign-in, or SAMLError."""
    state = read_state(cookie, secret, now)
    if not relay_state or not hmac.compare_digest(str(relay_state), state['r']):
        raise SAMLError('state', 'RelayState mismatch (possible cross-site request)')
    if not saml_response_b64 or len(saml_response_b64) > MAX_RESPONSE * 4 // 3 + 4:
        raise SAMLError('invalid_token', 'missing or oversized SAMLResponse')
    try:
        xml = base64.b64decode(saml_response_b64, validate=False)
    except ValueError:
        raise SAMLError('invalid_token', 'SAMLResponse is not base64')
    entity, acs = endpoints(cfg, base_url)
    assertion = signed_assertion(xml, cfg['idp_certs'])
    claims = check_assertion(cfg, assertion, entity, acs, state['i'], now)
    role = role_for(cfg, claims)
    check_mfa(cfg, claims, role)
    return username_for(cfg, claims), role, claims
