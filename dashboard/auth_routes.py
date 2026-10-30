"""Authentication and authorisation for the dashboard API.

Every request resolves to a *principal* (who is calling and with which role):

1. ``Authorization: Bearer sat1....`` access token from a console login.
2. The legacy shared ``DASHBOARD_API_KEY`` (``X-API-Key`` or Bearer), kept for
   automation and device health checks. Its role is ``SENTINEL_API_KEY_ROLE``
   (default ``admin``); scoped API tokens replace it later in Phase 1.
3. Development mode: when no users exist and no API key is set, requests from
   localhost act as ``admin``; everything else is refused.

Endpoints declare the minimum role with ``Depends(require_role('operator'))``.
"""

import hmac
import logging
import os
from typing import Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, Response
from pydantic import BaseModel

from core import auth

logger = logging.getLogger('sentinel.auth')

REFRESH_COOKIE = 'sentinel_refresh'
CSRF_HEADER = 'X-Sentinel-CSRF'
LOCAL_HOSTS = ('127.0.0.1', '::1', 'localhost')

login_throttle = auth.LoginThrottle()
router = APIRouter()


def api_key():
    return os.environ.get('DASHBOARD_API_KEY') or None


def api_key_role():
    role = os.environ.get('SENTINEL_API_KEY_ROLE', 'admin').lower()
    return role if role in auth.ROLE_RANK else 'viewer'


def _client_host(request: Optional[Request]):
    try:
        return request.client.host
    except AttributeError:
        return None


def resolve_principal(token: Optional[str], client_host: Optional[str], key: Optional[str] = None):
    """Return the principal for a bearer token / API key, or None."""
    token = token or None
    if token and token.startswith(auth.ACCESS_TOKEN_PREFIX + '.'):
        return auth.get_store().verify_access_token(token)
    configured = api_key()
    if configured:
        for candidate in (key, token):
            if candidate and hmac.compare_digest(candidate.encode(), configured.encode()):
                return {'kind': 'api_key', 'username': 'api-key', 'role': api_key_role(),
                        'must_change_password': False}
        return None
    if not token and not key and client_host in LOCAL_HOSTS and auth.get_store().user_count() == 0:
        return {'kind': 'local', 'username': 'local', 'role': 'admin', 'must_change_password': False}
    return None


def _bearer(authorization: Optional[str]):
    value = authorization or ''
    return value[7:].strip() if value.lower().startswith('bearer ') else (value.strip() or None)


def get_principal(
    request: Request,
    x_api_key: Optional[str] = Header(default=None, alias='X-API-Key'),
    authorization: Optional[str] = Header(default=None),
):
    principal = resolve_principal(_bearer(authorization), _client_host(request), x_api_key)
    if principal is None:
        raise HTTPException(status_code=401, detail='authentication required',
                            headers={'WWW-Authenticate': 'Bearer'})
    return principal


def pending_setup(principal: dict):
    """What a signed-in user must finish before using the console, or None."""
    if principal.get('must_change_password'):
        return 'password change required'
    if principal.get('mfa_setup_required'):
        return 'two-step sign-in setup required'
    return None


def require_role(minimum: str, allow_pending_setup: bool = False):
    auth.validate_role(minimum)

    def dependency(principal: dict = Depends(get_principal)):
        pending = pending_setup(principal)
        if pending and not allow_pending_setup:
            raise HTTPException(status_code=403, detail=pending)
        if not auth.role_allows(principal.get('role'), minimum):
            raise HTTPException(status_code=403, detail=f'{minimum} role required')
        return principal

    return dependency


require_viewer = require_role('viewer')
require_analyst = require_role('analyst')
require_operator = require_role('operator')
require_admin = require_role('admin')
require_signed_in = require_role('viewer', allow_pending_setup=True)

USER_FIELDS = ('username', 'role', 'must_change_password', 'mfa_enabled', 'mfa_setup_required')


# ---------- auth endpoints ----------

class LoginRequest(BaseModel):
    username: str
    password: str
    # authenticator code or recovery code, for users with two-step sign-in
    otp: Optional[str] = None


class MfaCode(BaseModel):
    code: str


class PasswordChange(BaseModel):
    current_password: str
    new_password: str


class NewUser(BaseModel):
    username: str
    password: str
    role: str = 'viewer'
    must_change_password: bool = True


class UserUpdate(BaseModel):
    role: Optional[str] = None
    disabled: Optional[bool] = None
    password: Optional[str] = None
    reset_mfa: bool = False


def _cookie_secure(request: Request):
    if os.environ.get('SENTINEL_COOKIE_SECURE') == '1':
        return True
    return request.url.scheme == 'https' or request.headers.get('x-forwarded-proto') == 'https'


def _set_refresh_cookie(response: Response, request: Request, tokens: dict):
    response.set_cookie(
        REFRESH_COOKIE, tokens['refresh_token'],
        max_age=tokens['refresh_expires_in'], path='/api/auth',
        httponly=True, samesite='strict', secure=_cookie_secure(request),
    )


def _token_response(tokens: dict, user: dict):
    return {
        'access_token': tokens['access_token'],
        'token_type': 'bearer',
        'expires_in': tokens['expires_in'],
        'user': {k: user.get(k, False) for k in USER_FIELDS},
    }


def _require_csrf_header(request: Request):
    # a custom header cannot be sent cross-site without a CORS preflight,
    # which only the console's own origin passes
    if request.headers.get(CSRF_HEADER) != '1':
        raise HTTPException(status_code=403, detail=f'{CSRF_HEADER} header required')


@router.get('/api/auth/status')
def auth_status(request: Request):
    store = auth.get_store()
    users = store.user_count()
    return {
        'accounts_enabled': users > 0,
        'local_dev_mode': users == 0 and not api_key() and _client_host(request) in LOCAL_HOSTS,
        'password_min_length': auth.MIN_PASSWORD_LENGTH,
        'mfa_roles': sorted(auth.mfa_roles(), key=auth.ROLE_RANK.get),
    }


@router.post('/api/auth/login')
def login(payload: LoginRequest, request: Request, response: Response):
    client = _client_host(request) or 'unknown'
    if not login_throttle.allow(client):
        logger.warning('login throttled for %s', client)
        raise HTTPException(status_code=429, detail='too many login attempts; try again later')
    store = auth.get_store()
    try:
        user = store.authenticate(payload.username, payload.password, payload.otp)
    except auth.AuthError as exc:
        if exc.code == 'mfa_required':
            # correct password; the console now asks for the authenticator code
            raise HTTPException(status_code=401, detail='mfa_required')
        logger.warning('login failed for %r from %s: %s', payload.username[:64], client, exc.reason)
        if exc.status == 423:
            raise HTTPException(status_code=423, detail='account temporarily locked after repeated failures')
        if exc.code == 'mfa_invalid':
            raise HTTPException(status_code=401, detail='mfa_invalid')
        raise HTTPException(status_code=401, detail='invalid username or password')
    tokens = store.create_session(user['username'], client, request.headers.get('user-agent'))
    _set_refresh_cookie(response, request, tokens)
    logger.info('login %s (%s) from %s', user['username'], user['role'], client)
    return _token_response(tokens, user)


@router.post('/api/auth/refresh')
def refresh(request: Request, response: Response):
    _require_csrf_header(request)
    try:
        tokens = auth.get_store().refresh(request.cookies.get(REFRESH_COOKIE))
    except auth.AuthError as exc:
        logger.info('refresh refused: %s', exc.reason)
        response.delete_cookie(REFRESH_COOKIE, path='/api/auth')
        raise HTTPException(status_code=401, detail='session expired; sign in again')
    _set_refresh_cookie(response, request, tokens)
    return _token_response(tokens, tokens['user'])


@router.post('/api/auth/logout')
def logout(request: Request, response: Response):
    _require_csrf_header(request)
    store = auth.get_store()
    session_id = (request.cookies.get(REFRESH_COOKIE) or '').partition('.')[0]
    principal = resolve_principal(_bearer(request.headers.get('authorization')), _client_host(request))
    if principal and principal.get('session_id'):
        session_id = principal['session_id']
    if session_id:
        store.revoke_session(session_id)
    response.delete_cookie(REFRESH_COOKIE, path='/api/auth')
    return {'status': 'signed_out'}


@router.get('/api/auth/me')
def me(principal: dict = Depends(require_signed_in)):
    out = {k: bool(principal.get(k)) for k in USER_FIELDS[2:]}
    out.update({k: principal.get(k) for k in ('username', 'role', 'kind')})
    return out


def _console_user(principal: dict):
    if principal.get('kind') != 'user':
        raise HTTPException(status_code=400, detail='only console users can use two-step sign-in')
    return principal['username']


@router.get('/api/auth/mfa')
def mfa_status(principal: dict = Depends(require_signed_in)):
    username = _console_user(principal)
    store = auth.get_store()
    return {
        'enabled': bool(principal.get('mfa_enabled')),
        'required': auth.mfa_required_for(principal.get('role')),
        'recovery_codes_left': store.recovery_codes_left(username),
    }


@router.post('/api/auth/mfa/setup')
def mfa_setup(principal: dict = Depends(require_signed_in)):
    username = _console_user(principal)
    if principal.get('must_change_password'):
        raise HTTPException(status_code=403, detail='password change required')
    try:
        enrolment = auth.get_store().begin_mfa_enrolment(username)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    return enrolment


@router.post('/api/auth/mfa/enable')
def mfa_enable(payload: MfaCode, principal: dict = Depends(require_signed_in)):
    username = _console_user(principal)
    try:
        codes = auth.get_store().enable_mfa(username, payload.code)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    logger.info('two-step sign-in enabled for %s', username)
    return {'status': 'enabled', 'recovery_codes': codes}


@router.post('/api/auth/password')
def change_password(payload: PasswordChange, principal: dict = Depends(require_signed_in)):
    if principal.get('kind') != 'user':
        raise HTTPException(status_code=400, detail='only console users have a password')
    store = auth.get_store()
    if not store.verify_password(principal['username'], payload.current_password):
        raise HTTPException(status_code=400, detail='current password is incorrect')
    if payload.new_password == payload.current_password:
        raise HTTPException(status_code=400, detail='new password must be different')
    try:
        store.set_password(principal['username'], payload.new_password, keep_session=principal['session_id'])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    logger.info('password changed for %s', principal['username'])
    return {'status': 'password_changed'}


# ---------- user management (admin) ----------

@router.get('/api/users')
def list_users(principal: dict = Depends(require_admin)):
    return auth.get_store().list_users()


@router.post('/api/users', status_code=201)
def create_user(payload: NewUser, principal: dict = Depends(require_admin)):
    try:
        user = auth.get_store().create_user(
            payload.username, payload.password, payload.role, payload.must_change_password)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    logger.info('%s created user %s (%s)', principal['username'], user['username'], user['role'])
    return user


@router.patch('/api/users/{username}')
def update_user(username: str, payload: UserUpdate, principal: dict = Depends(require_admin)):
    store = auth.get_store()
    if principal.get('username', '').lower() == username.lower() and (
        payload.disabled or (payload.role and payload.role != principal.get('role'))
    ):
        raise HTTPException(status_code=400, detail='you cannot disable or change the role of your own account')
    try:
        if payload.password is not None:
            auth.validate_password(payload.password, username)
        user = store.update_user(username, role=payload.role, disabled=payload.disabled)
        if payload.password is not None:
            # admin reset: the user must choose a new password at next sign-in
            store.set_password(username, payload.password, must_change_password=True)
            user = store.get_user(username)
        if payload.reset_mfa:
            # lost phone: remove the authenticator; the user enrols again at next sign-in
            store.reset_mfa(username)
            user = store.get_user(username)
            logger.info('%s reset two-step sign-in for %s', principal['username'], username)
    except KeyError:
        raise HTTPException(status_code=404, detail='user not found')
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    logger.info('%s updated user %s', principal['username'], username)
    return user


@router.delete('/api/users/{username}')
def delete_user(username: str, principal: dict = Depends(require_admin)):
    if principal.get('username', '').lower() == username.lower():
        raise HTTPException(status_code=400, detail='you cannot delete your own account')
    try:
        auth.get_store().delete_user(username)
    except KeyError:
        raise HTTPException(status_code=404, detail='user not found')
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    logger.info('%s deleted user %s', principal['username'], username)
    return {'status': 'deleted'}
