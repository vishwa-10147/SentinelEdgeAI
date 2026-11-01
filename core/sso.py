"""Single sign-on with OpenID Connect (Phase 10): Microsoft Entra ID, Google, Okta, Keycloak, ...

Authorization-code flow with PKCE. The browser goes to the identity provider
(IdP) from GET /api/auth/oidc/login and comes back to
GET /api/auth/oidc/callback with a code, which the appliance exchanges for an
ID token directly with the IdP.

What is checked before anyone is signed in:
  * `state` and the PKCE verifier come from an HMAC-signed, 10-minute cookie
    bound to this browser; `nonce` must match the ID token;
  * the ID token's signature against the IdP's published keys (JWKS), only
    RS256 or ES256, never `none` or HMAC algorithms;
  * issuer exactly the configured one, audience containing the client id
    (and `azp` equal to it when there are several), not expired, not issued
    in the future;
  * the role comes from the IdP groups mapped in the configuration (highest
    wins), else `default_role`; with neither, sign-in is refused;
  * roles that require two-step sign-in (Operator, Admin by default) need the
    IdP to assert MFA in `amr`, unless `trust_idp_mfa` says the IdP always
    enforces it (e.g. Entra conditional access);
  * an SSO account is pinned to the IdP's (issuer, subject): it can never sign
    in as, or take over, a local account with the same name.

Configuration (Admin, GET/PUT /api/sso; data/sso.json, SENTINEL_SSO):
  enabled, label, issuer, client_id, client_secret, redirect_uri (optional,
  default https://<console>/api/auth/oidc/callback), scopes, username_claim
  (default email), groups_claim (default groups), group_roles {group: role},
  default_role, trust_idp_mfa, token_auth (client_secret_post | client_secret_basic).
"""
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
import time

import requests
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
STATE_TTL = 600
CLOCK_SKEW = 120
ALGORITHMS = ('RS256', 'ES256')
MFA_AMR = {'mfa', 'otp', 'hwk', 'swk', 'fido', 'sms', 'tel', 'phr', 'phrh', 'face', 'fpt', 'iris', 'retina',
           'sc', 'pop'}
SECRET_FIELDS = ('client_secret',)
DEFAULTS = {'enabled': False, 'label': 'Sign in with SSO', 'scopes': 'openid email profile',
            'username_claim': 'email', 'groups_claim': 'groups', 'group_roles': {}, 'default_role': None,
            'trust_idp_mfa': False, 'token_auth': 'client_secret_post'}
_cache = {}
_cache_lock = threading.Lock()


class SSOError(Exception):
    """Sign-in refused. `code` is shown to the user; `reason` goes to the audit log."""

    def __init__(self, code, reason):
        super().__init__(reason)
        self.code, self.reason = code, reason


# ---------------- configuration ----------------

def config_file():
    return os.environ.get('SENTINEL_SSO') or os.path.join(ROOT, 'data', 'sso.json')


def load_config():
    try:
        with open(config_file(), 'r', encoding='utf-8') as f:
            data = json.load(f)
    except (OSError, ValueError):
        data = {}
    return {**DEFAULTS, **(data if isinstance(data, dict) else {})}


def validate(cfg):
    from core import auth
    cfg = {**DEFAULTS, **cfg}
    if cfg['enabled']:
        for key in ('issuer', 'client_id', 'client_secret'):
            if not cfg.get(key):
                raise ValueError(f'SSO needs {key}')
        if not str(cfg['issuer']).startswith('https://') and not cfg.get('allow_http'):
            raise ValueError('the issuer must use https://')
        if 'openid' not in str(cfg['scopes']).split():
            raise ValueError('scopes must include openid')
    if not isinstance(cfg['group_roles'], dict):
        raise ValueError('group_roles must map group names or ids to roles')
    for group, role in cfg['group_roles'].items():
        auth.validate_role(role)
    if cfg['default_role'] not in (None, ''):
        auth.validate_role(cfg['default_role'])
    if cfg['token_auth'] not in ('client_secret_post', 'client_secret_basic'):
        raise ValueError('token_auth must be client_secret_post or client_secret_basic')
    return cfg


def save_config(cfg):
    current = load_config()
    for key in SECRET_FIELDS:                          # a redacted value sent back keeps the stored one
        if cfg.get(key) == '********':
            cfg[key] = current.get(key)
    cfg = validate(cfg)
    path = config_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2)
    os.replace(path + '.tmp', path)
    with _cache_lock:
        _cache.clear()
    return cfg


def redacted(cfg):
    return {**cfg, **{k: '********' for k in SECRET_FIELDS if cfg.get(k)}}


def enabled():
    return bool(load_config().get('enabled'))


# ---------------- IdP metadata ----------------

def _get_json(url):
    r = requests.get(url, timeout=10)
    r.raise_for_status()
    return r.json()


def discovery(cfg):
    key = ('discovery', cfg['issuer'])
    with _cache_lock:
        hit = _cache.get(key)
        if hit and hit[0] > time.time():
            return hit[1]
    doc = _get_json(cfg['issuer'].rstrip('/') + '/.well-known/openid-configuration')
    if doc.get('issuer') != cfg['issuer']:
        raise SSOError('idp_error', f"discovery issuer {doc.get('issuer')!r} differs from the configured issuer")
    with _cache_lock:
        _cache[key] = (time.time() + 3600, doc)
    return doc


def _jwks(cfg, refresh=False):
    key = ('jwks', cfg['issuer'])
    with _cache_lock:
        hit = _cache.get(key)
        if hit and not refresh and hit[0] > time.time():
            return hit[1]
        if refresh and hit and hit[2] > time.time() - 60:
            return hit[1]                              # refetch at most once a minute
    keys = _get_json(discovery(cfg)['jwks_uri']).get('keys', [])
    with _cache_lock:
        _cache[key] = (time.time() + 3600, keys, time.time())
    return keys


# ---------------- JWT verification ----------------

def _b64d(value):
    value = value.encode() if isinstance(value, str) else value
    return base64.urlsafe_b64decode(value + b'=' * (-len(value) % 4))


def _b64e(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def _int(value):
    return int.from_bytes(_b64d(value), 'big')


def _public_key(jwk):
    if jwk.get('kty') == 'RSA':
        return rsa.RSAPublicNumbers(_int(jwk['e']), _int(jwk['n'])).public_key()
    if jwk.get('kty') == 'EC' and jwk.get('crv') == 'P-256':
        return ec.EllipticCurvePublicNumbers(_int(jwk['x']), _int(jwk['y']), ec.SECP256R1()).public_key()
    raise SSOError('idp_error', f"unsupported key type {jwk.get('kty')}/{jwk.get('crv')}")


def _verify_signature(alg, key, signing_input, signature):
    if alg == 'RS256':
        key.verify(signature, signing_input, padding.PKCS1v15(), hashes.SHA256())
    elif alg == 'ES256':
        if len(signature) != 64:
            raise InvalidSignature()
        der = encode_dss_signature(int.from_bytes(signature[:32], 'big'), int.from_bytes(signature[32:], 'big'))
        key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    else:
        raise InvalidSignature()


def verify_id_token(cfg, token, nonce, now=None):
    """The ID token's claims after every check, or SSOError."""
    now = now or time.time()
    try:
        head_b64, body_b64, sig_b64 = token.split('.')
        header = json.loads(_b64d(head_b64))
        claims = json.loads(_b64d(body_b64))
        signature = _b64d(sig_b64)
    except (ValueError, AttributeError):
        raise SSOError('invalid_token', 'malformed ID token')
    alg = header.get('alg')
    if alg not in ALGORITHMS:
        raise SSOError('invalid_token', f'ID token algorithm {alg!r} is not accepted')
    kid = header.get('kid')
    for refresh in (False, True):
        candidates = [k for k in _jwks(cfg, refresh) if (kid is None or k.get('kid') == kid)
                      and k.get('use', 'sig') == 'sig' and k.get('alg', alg) == alg]
        if candidates:
            break
    else:
        raise SSOError('invalid_token', f'no signing key {kid!r} published by the IdP')
    signing_input = f'{head_b64}.{body_b64}'.encode()
    for jwk in candidates:
        try:
            _verify_signature(alg, _public_key(jwk), signing_input, signature)
            break
        except (InvalidSignature, ValueError):
            continue
    else:
        raise SSOError('invalid_token', 'ID token signature does not verify')
    if claims.get('iss') != cfg['issuer']:
        raise SSOError('invalid_token', f"issuer {claims.get('iss')!r} is not the configured issuer")
    aud = claims.get('aud')
    audiences = aud if isinstance(aud, list) else [aud]
    if cfg['client_id'] not in audiences:
        raise SSOError('invalid_token', 'ID token was not issued for this client')
    if len(audiences) > 1 and claims.get('azp') != cfg['client_id']:
        raise SSOError('invalid_token', 'authorised party is not this client')
    if not isinstance(claims.get('exp'), (int, float)) or claims['exp'] < now - CLOCK_SKEW:
        raise SSOError('invalid_token', 'ID token expired')
    if isinstance(claims.get('iat'), (int, float)) and claims['iat'] > now + CLOCK_SKEW:
        raise SSOError('invalid_token', 'ID token issued in the future')
    if not nonce or not hmac.compare_digest(str(claims.get('nonce') or ''), nonce):
        raise SSOError('invalid_token', 'nonce mismatch (possible replay)')
    if not claims.get('sub'):
        raise SSOError('invalid_token', 'ID token has no subject')
    return claims


# ---------------- flow ----------------

def _sign(secret, payload):
    return _b64e(hmac.new(secret, payload.encode(), hashlib.sha256).digest())


def start(cfg, redirect_uri, secret, now=None):
    """(authorization URL, signed state cookie value) for a new sign-in."""
    from urllib.parse import urlencode
    now = now or time.time()
    state, nonce, verifier = secrets.token_urlsafe(24), secrets.token_urlsafe(24), secrets.token_urlsafe(48)
    challenge = _b64e(hashlib.sha256(verifier.encode()).digest())
    params = {'response_type': 'code', 'client_id': cfg['client_id'], 'redirect_uri': redirect_uri,
              'scope': cfg['scopes'], 'state': state, 'nonce': nonce, 'code_challenge': challenge,
              'code_challenge_method': 'S256'}
    url = discovery(cfg)['authorization_endpoint'] + '?' + urlencode(params)
    payload = _b64e(json.dumps({'s': state, 'n': nonce, 'v': verifier, 'r': redirect_uri,
                                'e': int(now + STATE_TTL)}).encode())
    return url, f'{payload}.{_sign(secret, payload)}'


def read_state(cookie, secret, now=None):
    payload, _, mac = str(cookie or '').rpartition('.')
    if not payload or not hmac.compare_digest(mac, _sign(secret, payload)):
        raise SSOError('state', 'sign-in state cookie missing or altered; start again')
    data = json.loads(_b64d(payload))
    if data['e'] < (now or time.time()):
        raise SSOError('state', 'sign-in took more than 10 minutes; start again')
    return data


def exchange(cfg, code, state_data):
    token_endpoint = discovery(cfg)['token_endpoint']
    data = {'grant_type': 'authorization_code', 'code': code, 'redirect_uri': state_data['r'],
            'code_verifier': state_data['v'], 'client_id': cfg['client_id']}
    auth = None
    if cfg['token_auth'] == 'client_secret_basic':
        auth = (cfg['client_id'], cfg['client_secret'])
    else:
        data['client_secret'] = cfg['client_secret']
    r = requests.post(token_endpoint, data=data, auth=auth, timeout=10, headers={'Accept': 'application/json'})
    if r.status_code >= 400:
        raise SSOError('idp_error', f'token endpoint refused the code (HTTP {r.status_code})')
    token = r.json().get('id_token')
    if not token:
        raise SSOError('idp_error', 'the IdP returned no ID token')
    return token


def role_for(cfg, claims):
    from core import auth
    groups = claims.get(cfg['groups_claim']) or []
    if isinstance(groups, str):
        groups = [groups]
    roles = [cfg['group_roles'][g] for g in groups if isinstance(g, str) and g in cfg['group_roles']]
    if roles:
        return max(roles, key=auth.ROLE_RANK.get)
    if cfg.get('default_role'):
        return cfg['default_role']
    raise SSOError('no_role', 'none of your groups is allowed to use this console')


def username_for(cfg, claims):
    raw = str(claims.get(cfg['username_claim']) or claims.get('preferred_username') or claims.get('email') or '')
    name = re.sub(r'[^A-Za-z0-9_.-]', '.', raw.split('@')[0] if '@' in raw and len(raw) > 32 else raw)
    name = name.strip('.')[:32]
    if len(name) < 3:
        name = ('sso.' + hashlib.sha256(claims['sub'].encode()).hexdigest())[:16]
    return name


def external_id(cfg, claims):
    return hashlib.sha256(f"{cfg['issuer']}|{claims['sub']}".encode()).hexdigest()[:32]


def check_mfa(cfg, claims, role):
    from core import auth
    if not auth.mfa_required_for(role) or cfg.get('trust_idp_mfa'):
        return
    amr = claims.get('amr') or []
    if isinstance(amr, str):
        amr = [amr]
    if not MFA_AMR & {str(a).lower() for a in amr}:
        raise SSOError('mfa_required', f'the {role} role needs multi-factor sign-in at the identity provider')


def complete(cfg, code, state, cookie, secret, now=None):
    """(username, role, claims) for a finished sign-in, or SSOError."""
    data = read_state(cookie, secret, now)
    if not state or not hmac.compare_digest(state, data['s']):
        raise SSOError('state', 'state mismatch (possible cross-site request)')
    claims = verify_id_token(cfg, exchange(cfg, code, data), data['n'], now)
    role = role_for(cfg, claims)
    check_mfa(cfg, claims, role)
    return username_for(cfg, claims), role, claims
