"""Web Push (Phase 10): approval requests straight to an Operator's phone or browser.

An Operator or Admin turns push on in the console (Operations -> Notifications,
"Push on this device"). The browser subscribes with the appliance's VAPID key
and the subscription (push-service URL and the browser's encryption keys) is
stored in data/webpush.json (SENTINEL_WEBPUSH). When the playbook holds an
action for approval, every subscription of a current Operator or Admin gets a
notification that opens the phone approval page (#approve/<id>), where they
sign in as usual: the notification carries no credentials.

The protocol is the standard one, implemented with `cryptography`:
  * RFC 8291 message encryption (aes128gcm, ECDH P-256 + HKDF): the push
    service (Google, Mozilla, Apple, Microsoft) only relays ciphertext;
  * RFC 8292 VAPID: an ES256 JWT identifies the appliance to the push service.
The VAPID key pair is created on first use (data/webpush_vapid.pem, mode 600).

Subscriptions may only point at known push services (SENTINEL_WEBPUSH_HOSTS adds
more), so the feature cannot be used to make the appliance call arbitrary
hosts. A subscription the push service reports as gone (404/410) is removed.
Browsers allow push only on a trusted HTTPS origin: install a certificate the
phone trusts (sentinelctl tls import), and on iPhone add the console to the
home screen first.
"""
import base64
import json
import logging
import os
import queue
import secrets
import struct
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

from cryptography.hazmat.primitives import hashes, hmac, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logger = logging.getLogger('sentinel.webpush')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PUSH_HOSTS = ('fcm.googleapis.com', 'updates.push.services.mozilla.com', 'web.push.apple.com',
              '.push.apple.com', '.notify.windows.com', '.push.services.mozilla.com')
MAX_PER_USER = 10
MAX_TOTAL = 500
RECORD_SIZE = 4096
_lock = threading.Lock()


class PushError(ValueError):
    pass


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


def unb64url(text):
    text = str(text or '')
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def store_file():
    return os.environ.get('SENTINEL_WEBPUSH') or os.path.join(ROOT, 'data', 'webpush.json')


def _vapid_file():
    return os.path.join(os.path.dirname(os.path.abspath(store_file())), 'webpush_vapid.pem')


# ---------------- RFC 8291 encryption ----------------

def _hmac(key, data):
    h = hmac.HMAC(key, hashes.SHA256())
    h.update(data)
    return h.finalize()


def encrypt(plaintext, p256dh, auth, salt=None, private_key=None):
    """aes128gcm body for one push message (RFC 8291 section 3/4, single record)."""
    ua_public = unb64url(p256dh)
    auth_secret = unb64url(auth)
    if len(ua_public) != 65 or ua_public[0] != 4 or len(auth_secret) != 16:
        raise PushError('invalid subscription keys')
    if len(plaintext) > RECORD_SIZE - 17 - 86:
        raise PushError('push message too long')
    as_private = private_key or ec.generate_private_key(ec.SECP256R1())
    as_public = as_private.public_key().public_bytes(serialization.Encoding.X962,
                                                     serialization.PublicFormat.UncompressedPoint)
    try:
        ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    except ValueError as exc:
        raise PushError('invalid subscription key') from exc
    ecdh_secret = as_private.exchange(ec.ECDH(), ua_key)
    prk_key = _hmac(auth_secret, ecdh_secret)
    ikm = _hmac(prk_key, b'WebPush: info\x00' + ua_public + as_public + b'\x01')
    salt = salt or secrets.token_bytes(16)
    prk = _hmac(salt, ikm)
    cek = _hmac(prk, b'Content-Encoding: aes128gcm\x00\x01')[:16]
    nonce = _hmac(prk, b'Content-Encoding: nonce\x00\x01')[:12]
    ciphertext = AESGCM(cek).encrypt(nonce, plaintext + b'\x02', None)      # 0x02: last record, no padding
    return salt + struct.pack('!IB', RECORD_SIZE, len(as_public)) + as_public + ciphertext


# ---------------- VAPID (RFC 8292) ----------------

def _vapid_key():
    path = _vapid_file()
    with _lock:
        if not os.path.exists(path):
            os.makedirs(os.path.dirname(path), exist_ok=True)
            key = ec.generate_private_key(ec.SECP256R1())
            pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                    serialization.NoEncryption())
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as f:
                f.write(pem)
        with open(path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), None)


def public_key():
    """The VAPID public key (base64url, uncompressed point) the browser subscribes with."""
    return b64url(_vapid_key().public_key().public_bytes(serialization.Encoding.X962,
                                                         serialization.PublicFormat.UncompressedPoint))


def vapid_header(endpoint, subject, now=None):
    parts = urllib.parse.urlsplit(endpoint)
    claims = {'aud': f'{parts.scheme}://{parts.netloc}', 'exp': int((now or time.time()) + 12 * 3600),
              'sub': subject}
    signing_input = (b64url(json.dumps({'typ': 'JWT', 'alg': 'ES256'}, separators=(',', ':')).encode()) + '.'
                     + b64url(json.dumps(claims, separators=(',', ':')).encode()))
    r, s = decode_dss_signature(_vapid_key().sign(signing_input.encode('ascii'), ec.ECDSA(hashes.SHA256())))
    jwt = signing_input + '.' + b64url(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))
    return f'vapid t={jwt}, k={public_key()}'


# ---------------- subscriptions ----------------

def _allowed_host(host):
    extra = tuple(h.strip().lower() for h in os.environ.get('SENTINEL_WEBPUSH_HOSTS', '').split(',') if h.strip())
    host = (host or '').lower()
    for h in PUSH_HOSTS + extra:
        if host == h or (h.startswith('.') and host.endswith(h)):
            return True
    return False


def validate_subscription(sub):
    if not isinstance(sub, dict):
        raise PushError('subscription must be an object')
    endpoint = str(sub.get('endpoint') or '')
    keys = sub.get('keys') or {}
    parts = urllib.parse.urlsplit(endpoint)
    if parts.scheme != 'https' or not parts.hostname or len(endpoint) > 1024:
        raise PushError('push endpoint must be an https URL')
    if not _allowed_host(parts.hostname):
        raise PushError(f'{parts.hostname} is not a known push service (an Admin can add it with SENTINEL_WEBPUSH_HOSTS)')
    try:
        p256dh, auth = unb64url(keys.get('p256dh')), unb64url(keys.get('auth'))
    except (ValueError, TypeError) as exc:
        raise PushError('subscription keys are not base64url') from exc
    if len(p256dh) != 65 or p256dh[0] != 4 or len(auth) != 16:
        raise PushError('invalid subscription keys')
    return {'endpoint': endpoint, 'p256dh': b64url(p256dh), 'auth': b64url(auth)}


def _load():
    try:
        with open(store_file(), encoding='utf-8') as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _save(subs):
    path = store_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + '.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(subs, f, indent=2)
    os.replace(tmp, path)


def _public(s):
    return {k: s.get(k) for k in ('id', 'username', 'created', 'label', 'last_ok', 'failures')} | {
        'service': urllib.parse.urlsplit(s['endpoint']).hostname}


def subscribe(username, sub, label=None, now=None):
    clean = validate_subscription(sub)
    with _lock:
        subs = [s for s in _load() if s['endpoint'] != clean['endpoint']]
        mine = [s for s in subs if s['username'] == username]
        if len(mine) >= MAX_PER_USER:
            subs.remove(min(mine, key=lambda s: s['created']))
        if len(subs) >= MAX_TOTAL:
            raise PushError('too many push subscriptions on this appliance')
        entry = {'id': secrets.token_hex(8), 'username': username, 'created': int(now or time.time()),
                 'label': str(label or '')[:60], 'last_ok': None, 'failures': 0, **clean}
        subs.append(entry)
        _save(subs)
    return _public(entry)


def unsubscribe(sub_id=None, endpoint=None, username=None):
    """Remove by id or endpoint; `username` (when given) must own it. Returns the number removed."""
    with _lock:
        subs = _load()
        keep = [s for s in subs if not ((sub_id and s['id'] == sub_id) or (endpoint and s['endpoint'] == endpoint))
                or (username is not None and s['username'] != username)]
        _save(keep)
    return len(subs) - len(keep)


def list_subscriptions(username=None):
    return [_public(s) for s in _load() if username is None or s['username'] == username]


# ---------------- sending ----------------

def _subject():
    try:
        from integrations.notify import load_config
        url = load_config().get('console_url') or ''
        if url.startswith('https://'):
            return url
    except Exception:
        pass
    return 'mailto:sentineledgeai@localhost'


def _post(endpoint, body, headers, timeout=10):
    req = urllib.request.Request(endpoint, data=body, headers=headers, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:      # nosec B310: https push services only
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code


def send(sub, message, ttl=3600, urgency='high', poster=None):
    """Send one message (dict) to one stored subscription. Returns the HTTP status."""
    parts = urllib.parse.urlsplit(sub['endpoint'])
    if parts.scheme != 'https' or not _allowed_host(parts.hostname):
        raise PushError('subscription endpoint is not an allowed push service')
    body = encrypt(json.dumps(message, separators=(',', ':')).encode('utf-8'), sub['p256dh'], sub['auth'])
    headers = {'Authorization': vapid_header(sub['endpoint'], _subject()), 'TTL': str(int(ttl)),
               'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', 'Urgency': urgency}
    return (poster or _post)(sub['endpoint'], body, headers)


def _eligible(username):
    """Push only to accounts that exist, are enabled and can approve (Operator or Admin) right now."""
    try:
        from core import auth
        user = auth.get_store().get_user(username)
        return bool(user) and not user.get('disabled') and auth.role_allows(user.get('role'), 'operator')
    except Exception:
        return False


def deliver(message, username=None, poster=None, now=None):
    """Send to every eligible subscription (or one user's). Returns {sub_id: status or error}."""
    out = {}
    gone, outcome = set(), {}
    for s in _load():
        if username is not None and s['username'] != username:
            continue
        if not _eligible(s['username']):
            out[s['id']] = 'not an Operator or Admin'
            continue
        try:
            status = send(s, message, poster=poster)
        except Exception as exc:                        # one broken subscription must not stop the others
            out[s['id']] = str(exc)[:200] or exc.__class__.__name__
            outcome[s['id']] = False
            continue
        out[s['id']] = status
        if status in (404, 410):
            gone.add(s['id'])
        else:
            outcome[s['id']] = 200 <= status < 300
    if gone or outcome:
        with _lock:
            subs = []
            for s in _load():
                if s['id'] in gone:
                    continue
                if s['id'] in outcome:
                    if outcome[s['id']]:
                        s['last_ok'], s['failures'] = int(now or time.time()), 0
                    else:
                        s['failures'] = s.get('failures', 0) + 1
                subs.append(s)
            _save(subs)
    return out


_queue = queue.Queue(maxsize=200)
_worker = None


def _run():
    while True:
        message = _queue.get()
        try:
            deliver(message)
        except Exception:
            logger.exception('web push delivery failed')
        finally:
            _queue.task_done()


def enqueue(message):
    global _worker
    with _lock:
        if _worker is None or not _worker.is_alive():
            _worker = threading.Thread(target=_run, daemon=True, name='webpush')
            _worker.start()
    try:
        _queue.put_nowait(message)
    except queue.Full:
        logger.warning('web push queue full; dropped: %s', message.get('title'))


def approval_message(pending_id, ip, action, risk, reason):
    reason = ' '.join(str(reason or '').split())[:140]
    return {'title': f'Approval needed: {action} {ip}', 'body': f'Risk {int(risk)}. {reason}'.strip(),
            'url': f'/#approve/{int(pending_id)}', 'tag': f'approve-{int(pending_id)}', 'require': True}


def approval_requested(pending_id, ip, action, risk, reason):
    """Called with every new approval request. Never raises; does nothing without subscriptions."""
    try:
        if _load():
            enqueue(approval_message(pending_id, ip, action, risk, reason))
    except Exception:
        logger.exception('web push for approval failed')
