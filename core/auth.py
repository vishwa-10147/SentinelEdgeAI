"""User accounts, login sessions and roles for the management API.

Accounts live in their own SQLite file (``SENTINEL_AUTH_DB``, default
``data/auth.db``) so they survive upgrades and never mix with traffic data.

* Passwords are hashed with Argon2id (argon2-cffi defaults).
* A login creates a *session* (absolute lifetime ``SENTINEL_SESSION_TTL``,
  default 12 h) with a refresh token that is rotated on every use; presenting
  an old refresh token revokes the session (token theft detection).
* Short-lived *access tokens* (``SENTINEL_ACCESS_TOKEN_TTL``, default 15 min)
  are HMAC-signed and checked against the session and user on every request,
  so logout, disabling a user or changing a role take effect immediately.
* Repeated failed logins lock the account for ``LOCKOUT_SECONDS``.

Command line (run on the device as root or the service user)::

    python -m core.auth create-user --username alice --role operator
    python -m core.auth reset-password --username alice
    python -m core.auth list
    python -m core.auth bootstrap-admin --password-file /etc/sentinel/initial-admin-password
"""

import argparse
import base64
import getpass
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import sys
import threading
import time
from collections import deque

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

ROLES = ('viewer', 'analyst', 'operator', 'admin')
ROLE_RANK = {role: rank for rank, role in enumerate(ROLES)}

ACCESS_TOKEN_PREFIX = 'sat1'
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
MAX_FAILED_LOGINS = 5
LOCKOUT_SECONDS = 15 * 60
USERNAME_RE = re.compile(r'^[A-Za-z0-9_.-]{3,32}$')

_hasher = PasswordHasher()
# verified against when the username does not exist, so response time does
# not reveal which usernames are valid
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(16))


class AuthError(Exception):
    """Login or token problem. `reason` is safe to log, never shown to clients."""

    def __init__(self, reason, status=401):
        super().__init__(reason)
        self.reason = reason
        self.status = status


def _env_int(name, default):
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def access_token_ttl():
    return _env_int('SENTINEL_ACCESS_TOKEN_TTL', 900)


def session_ttl():
    return _env_int('SENTINEL_SESSION_TTL', 12 * 3600)


def default_db_path():
    return os.environ.get('SENTINEL_AUTH_DB') or os.path.join(ROOT, 'data', 'auth.db')


def validate_username(username):
    username = str(username or '').strip()
    if not USERNAME_RE.match(username):
        raise ValueError('username must be 3-32 characters: letters, digits, dot, dash or underscore')
    return username


def validate_role(role):
    role = str(role or '').strip().lower()
    if role not in ROLE_RANK:
        raise ValueError(f"role must be one of: {', '.join(ROLES)}")
    return role


def validate_password(password, username=None):
    if not isinstance(password, str):
        raise ValueError('password is required')
    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValueError(f'password must be at least {MIN_PASSWORD_LENGTH} characters')
    if len(password) > MAX_PASSWORD_LENGTH:
        raise ValueError(f'password must be at most {MAX_PASSWORD_LENGTH} characters')
    if username and password.lower() == str(username).lower():
        raise ValueError('password must not be the username')
    return password


def role_allows(role, minimum):
    return ROLE_RANK.get(role, -1) >= ROLE_RANK[minimum]


def _sha256(value):
    return hashlib.sha256(value.encode('utf-8')).hexdigest()


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('ascii')


class AuthStore:
    def __init__(self, path=None):
        self.path = path or default_db_path()
        self._lock = threading.Lock()
        self._conn = None
        self._secret = None

    # ---------- storage ----------

    def _db(self):
        if self._conn is None:
            if self.path != ':memory:':
                os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
                fresh = not os.path.exists(self.path)
            else:
                fresh = False
            conn = sqlite3.connect(self.path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            if fresh and os.name == 'posix':
                os.chmod(self.path, 0o600)
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    disabled INTEGER NOT NULL DEFAULT 0,
                    must_change_password INTEGER NOT NULL DEFAULT 0,
                    failed_logins INTEGER NOT NULL DEFAULT 0,
                    locked_until INTEGER NOT NULL DEFAULT 0,
                    created INTEGER NOT NULL,
                    updated INTEGER NOT NULL,
                    last_login INTEGER
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    refresh_hash TEXT NOT NULL,
                    created INTEGER NOT NULL,
                    expires INTEGER NOT NULL,
                    last_seen INTEGER NOT NULL,
                    revoked INTEGER NOT NULL DEFAULT 0,
                    client_ip TEXT,
                    user_agent TEXT
                );
                CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            conn.execute('PRAGMA foreign_keys=ON')
            conn.commit()
            self._conn = conn
        return self._conn

    def _execute(self, sql, params=()):
        with self._lock:
            db = self._db()
            cur = db.execute(sql, params)
            db.commit()
            return cur

    def _fetchone(self, sql, params=()):
        with self._lock:
            row = self._db().execute(sql, params).fetchone()
            return dict(row) if row else None

    def _fetchall(self, sql, params=()):
        with self._lock:
            return [dict(r) for r in self._db().execute(sql, params).fetchall()]

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _signing_secret(self):
        if self._secret is None:
            row = self._fetchone("SELECT value FROM settings WHERE key = 'token_secret'")
            if row:
                self._secret = base64.b64decode(row['value'])
            else:
                secret = secrets.token_bytes(32)
                self._execute(
                    "INSERT OR IGNORE INTO settings(key, value) VALUES ('token_secret', ?)",
                    (base64.b64encode(secret).decode('ascii'),),
                )
                row = self._fetchone("SELECT value FROM settings WHERE key = 'token_secret'")
                self._secret = base64.b64decode(row['value'])
        return self._secret

    # ---------- users ----------

    @staticmethod
    def _public(user):
        if not user:
            return None
        return {
            'username': user['username'],
            'role': user['role'],
            'disabled': bool(user['disabled']),
            'must_change_password': bool(user['must_change_password']),
            'locked': int(user.get('locked_until') or 0) > int(time.time()),
            'created': user['created'],
            'last_login': user.get('last_login'),
        }

    def user_count(self):
        return self._fetchone('SELECT COUNT(*) AS n FROM users')['n']

    def _get(self, username):
        return self._fetchone('SELECT * FROM users WHERE username = ?', (str(username),))

    def get_user(self, username):
        return self._public(self._get(username))

    def list_users(self):
        return [self._public(u) for u in self._fetchall('SELECT * FROM users ORDER BY username')]

    def _active_admins(self):
        return self._fetchone(
            "SELECT COUNT(*) AS n FROM users WHERE role = 'admin' AND disabled = 0"
        )['n']

    def create_user(self, username, password, role, must_change_password=False):
        username = validate_username(username)
        role = validate_role(role)
        validate_password(password, username)
        if self._get(username):
            raise ValueError(f'user already exists: {username}')
        now = int(time.time())
        self._execute(
            'INSERT INTO users(username, password_hash, role, must_change_password, created, updated) '
            'VALUES (?, ?, ?, ?, ?, ?)',
            (username, _hasher.hash(password), role, int(bool(must_change_password)), now, now),
        )
        return self.get_user(username)

    def update_user(self, username, role=None, disabled=None):
        user = self._get(username)
        if not user:
            raise KeyError(username)
        new_role = validate_role(role) if role is not None else user['role']
        new_disabled = bool(disabled) if disabled is not None else bool(user['disabled'])
        removes_admin = user['role'] == 'admin' and not user['disabled'] and (
            new_role != 'admin' or new_disabled
        )
        if removes_admin and self._active_admins() <= 1:
            raise ValueError('cannot remove the last active admin')
        self._execute(
            'UPDATE users SET role = ?, disabled = ?, updated = ? WHERE id = ?',
            (new_role, int(new_disabled), int(time.time()), user['id']),
        )
        if new_disabled:
            self.revoke_user_sessions(user['username'])
        return self.get_user(user['username'])

    def delete_user(self, username):
        user = self._get(username)
        if not user:
            raise KeyError(username)
        if user['role'] == 'admin' and not user['disabled'] and self._active_admins() <= 1:
            raise ValueError('cannot remove the last active admin')
        self._execute('DELETE FROM sessions WHERE user_id = ?', (user['id'],))
        self._execute('DELETE FROM users WHERE id = ?', (user['id'],))

    def set_password(self, username, password, must_change_password=False, keep_session=None):
        """Set a new password and sign out every session except `keep_session`."""
        user = self._get(username)
        if not user:
            raise KeyError(username)
        validate_password(password, user['username'])
        self._execute(
            'UPDATE users SET password_hash = ?, must_change_password = ?, failed_logins = 0, '
            'locked_until = 0, updated = ? WHERE id = ?',
            (_hasher.hash(password), int(bool(must_change_password)), int(time.time()), user['id']),
        )
        self._execute(
            'UPDATE sessions SET revoked = 1 WHERE user_id = ? AND id != ?',
            (user['id'], keep_session or ''),
        )

    def verify_password(self, username, password):
        user = self._get(username)
        if not user:
            return False
        try:
            return _hasher.verify(user['password_hash'], password)
        except (VerificationError, InvalidHashError):
            return False

    def authenticate(self, username, password):
        """Return the public user on success; raise AuthError otherwise."""
        now = int(time.time())
        user = self._get(str(username or ''))
        if not user:
            try:
                _hasher.verify(_DUMMY_HASH, str(password or ''))
            except (VerificationError, InvalidHashError):
                pass
            raise AuthError('unknown user')
        if int(user['locked_until'] or 0) > now:
            raise AuthError('account locked', status=423)
        try:
            _hasher.verify(user['password_hash'], str(password or ''))
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            failures = int(user['failed_logins'] or 0) + 1
            locked_until = now + LOCKOUT_SECONDS if failures >= MAX_FAILED_LOGINS else 0
            self._execute(
                'UPDATE users SET failed_logins = ?, locked_until = ? WHERE id = ?',
                (0 if locked_until else failures, locked_until, user['id']),
            )
            raise AuthError('bad password')
        if user['disabled']:
            raise AuthError('account disabled')
        if _hasher.check_needs_rehash(user['password_hash']):
            self._execute(
                'UPDATE users SET password_hash = ? WHERE id = ?',
                (_hasher.hash(password), user['id']),
            )
        self._execute(
            'UPDATE users SET failed_logins = 0, locked_until = 0, last_login = ? WHERE id = ?',
            (now, user['id']),
        )
        return self.get_user(user['username'])

    # ---------- sessions and tokens ----------

    def _sign(self, payload):
        return _b64(hmac.new(self._signing_secret(), payload.encode('ascii'), hashlib.sha256).digest())

    def issue_access_token(self, session_id):
        expires = int(time.time()) + access_token_ttl()
        payload = f'{ACCESS_TOKEN_PREFIX}.{session_id}.{expires}'
        return f'{payload}.{self._sign(payload)}', access_token_ttl()

    def create_session(self, username, client_ip=None, user_agent=None):
        user = self._get(username)
        if not user:
            raise KeyError(username)
        now = int(time.time())
        session_id = secrets.token_hex(16)
        refresh_secret = secrets.token_urlsafe(32)
        self._execute(
            'INSERT INTO sessions(id, user_id, refresh_hash, created, expires, last_seen, client_ip, user_agent) '
            'VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            (session_id, user['id'], _sha256(refresh_secret), now, now + session_ttl(), now,
             (client_ip or '')[:64], (user_agent or '')[:256]),
        )
        self._purge_expired(now)
        access_token, expires_in = self.issue_access_token(session_id)
        return {
            'session_id': session_id,
            'refresh_token': f'{session_id}.{refresh_secret}',
            'access_token': access_token,
            'expires_in': expires_in,
            'refresh_expires_in': session_ttl(),
        }

    def refresh(self, refresh_token):
        """Rotate the refresh token and issue a new access token."""
        session_id, _, secret = str(refresh_token or '').partition('.')
        if not session_id or not secret:
            raise AuthError('malformed refresh token')
        now = int(time.time())
        session = self._fetchone('SELECT * FROM sessions WHERE id = ?', (session_id,))
        if not session or session['revoked'] or session['expires'] <= now:
            raise AuthError('session ended')
        if not hmac.compare_digest(session['refresh_hash'], _sha256(secret)):
            # an old refresh token was replayed: assume it was stolen
            self.revoke_session(session_id)
            raise AuthError('refresh token reuse')
        user = self._fetchone('SELECT * FROM users WHERE id = ?', (session['user_id'],))
        if not user or user['disabled']:
            self.revoke_session(session_id)
            raise AuthError('account disabled')
        new_secret = secrets.token_urlsafe(32)
        self._execute(
            'UPDATE sessions SET refresh_hash = ?, last_seen = ? WHERE id = ?',
            (_sha256(new_secret), now, session_id),
        )
        access_token, expires_in = self.issue_access_token(session_id)
        return {
            'session_id': session_id,
            'refresh_token': f'{session_id}.{new_secret}',
            'access_token': access_token,
            'expires_in': expires_in,
            'refresh_expires_in': max(0, session['expires'] - now),
            'user': self._public(user),
        }

    def verify_access_token(self, token):
        """Return the principal for a valid access token, else None."""
        parts = str(token or '').split('.')
        if len(parts) != 4 or parts[0] != ACCESS_TOKEN_PREFIX:
            return None
        payload = '.'.join(parts[:3])
        if not hmac.compare_digest(parts[3], self._sign(payload)):
            return None
        try:
            expires = int(parts[2])
        except ValueError:
            return None
        now = int(time.time())
        if expires <= now:
            return None
        row = self._fetchone(
            'SELECT s.id AS session_id, s.expires, s.revoked, u.username, u.role, u.disabled, '
            'u.must_change_password FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id = ?',
            (parts[1],),
        )
        if not row or row['revoked'] or row['disabled'] or row['expires'] <= now:
            return None
        return {
            'kind': 'user',
            'username': row['username'],
            'role': row['role'],
            'must_change_password': bool(row['must_change_password']),
            'session_id': row['session_id'],
        }

    def revoke_session(self, session_id):
        self._execute('UPDATE sessions SET revoked = 1 WHERE id = ?', (str(session_id),))

    def revoke_user_sessions(self, username):
        self._execute(
            'UPDATE sessions SET revoked = 1 WHERE user_id = (SELECT id FROM users WHERE username = ?)',
            (str(username),),
        )

    def _purge_expired(self, now):
        # keep revoked sessions for a day so refresh-token reuse is still detected
        self._execute(
            'DELETE FROM sessions WHERE expires <= ? OR (revoked = 1 AND last_seen <= ?)',
            (now, now - 86400),
        )


class LoginThrottle:
    """Per-client sliding window limit on login attempts (in memory)."""

    def __init__(self, max_attempts=10, window_seconds=300):
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._attempts = {}
        self._lock = threading.Lock()

    def allow(self, key, now=None):
        now = now or time.monotonic()
        with self._lock:
            q = self._attempts.setdefault(key, deque())
            while q and q[0] <= now - self.window:
                q.popleft()
            if len(q) >= self.max_attempts:
                return False
            q.append(now)
            if len(self._attempts) > 10000:
                # drop idle clients so the table cannot grow without bound
                for k in [k for k, v in self._attempts.items() if not v]:
                    del self._attempts[k]
            return True

    def reset(self, key):
        with self._lock:
            self._attempts.pop(key, None)


_default_store = None
_default_lock = threading.Lock()


def get_store():
    global _default_store
    with _default_lock:
        if _default_store is None or _default_store.path != default_db_path():
            _default_store = AuthStore()
        return _default_store


# ---------- command line ----------

def _read_new_password(args, username):
    if getattr(args, 'password_file', None):
        with open(args.password_file, 'r', encoding='utf-8') as f:
            return f.read().strip()
    first = getpass.getpass(f'New password for {username}: ')
    if first != getpass.getpass('Repeat password: '):
        raise SystemExit('passwords do not match')
    return first


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m core.auth', description='Manage SentinelEdgeAI console users.')
    parser.add_argument('--db', help='auth database (default: $SENTINEL_AUTH_DB or data/auth.db)')
    sub = parser.add_subparsers(dest='command', required=True)

    p = sub.add_parser('create-user', help='create a user (prompts for the password)')
    p.add_argument('--username', required=True)
    p.add_argument('--role', required=True, choices=ROLES)
    p.add_argument('--password-file')
    p.add_argument('--must-change-password', action='store_true')

    p = sub.add_parser('reset-password', help='set a new password and sign the user out everywhere')
    p.add_argument('--username', required=True)
    p.add_argument('--password-file')
    p.add_argument('--must-change-password', action='store_true')

    p = sub.add_parser('set-role', help="change a user's role")
    p.add_argument('--username', required=True)
    p.add_argument('--role', required=True, choices=ROLES)

    p = sub.add_parser('unlock', help='clear a login lockout')
    p.add_argument('--username', required=True)

    sub.add_parser('list', help='list users')

    p = sub.add_parser(
        'bootstrap-admin',
        help="first install only: create user 'admin' with a random password written to --password-file",
    )
    p.add_argument('--password-file', required=True)

    args = parser.parse_args(argv)
    store = AuthStore(args.db) if args.db else AuthStore()
    try:
        if args.command == 'create-user':
            password = _read_new_password(args, args.username)
            user = store.create_user(args.username, password, args.role, args.must_change_password)
            print(f"created {user['username']} ({user['role']})")
        elif args.command == 'reset-password':
            password = _read_new_password(args, args.username)
            store.set_password(args.username, password, must_change_password=args.must_change_password)
            print(f'password reset for {args.username}; all of its sessions were signed out')
        elif args.command == 'set-role':
            user = store.update_user(args.username, role=args.role)
            print(f"{user['username']} is now {user['role']}")
        elif args.command == 'unlock':
            if not store.get_user(args.username):
                raise KeyError(args.username)
            store._execute('UPDATE users SET failed_logins = 0, locked_until = 0 WHERE username = ?', (args.username,))
            print(f'unlocked {args.username}')
        elif args.command == 'list':
            for u in store.list_users():
                flags = [f for f, on in (('disabled', u['disabled']), ('locked', u['locked']),
                                         ('must-change-password', u['must_change_password'])) if on]
                print(f"{u['username']:<32} {u['role']:<9} {' '.join(flags)}")
        elif args.command == 'bootstrap-admin':
            if store.user_count():
                print('users already exist; nothing to do')
                return 0
            password = secrets.token_urlsafe(18)
            fd = os.open(args.password_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(password + '\n')
            store.create_user('admin', password, 'admin', must_change_password=True)
            print(f"created user 'admin'; its one-time password is in {args.password_file}")
    except KeyError as exc:
        print(f'no such user: {exc.args[0]}', file=sys.stderr)
        return 1
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 1
    finally:
        store.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
