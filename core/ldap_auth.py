"""Direct sign-in against LDAP / Active Directory (Phase 10).

The console's normal sign-in form checks the password against the directory
when the username is not a local account (or is a directory account). The
role comes from the user's groups, mapped like SSO groups (highest wins), and
is refreshed at every sign-in. Two-step sign-in stays local: directory
accounts with Operator or Admin enrol an authenticator app on first sign-in,
exactly like local accounts, because a directory password alone is one factor.

What is enforced:
  * only encrypted connections: ldaps:// (636), or ldap:// with StartTLS; the
    server certificate is verified (system CAs or `ca_file`);
  * an empty password is refused before anything is sent (an LDAP "bind" with
    an empty password is an anonymous bind that succeeds);
  * the username is escaped in search filters (no filter injection), and the
    search must find exactly one entry;
  * the user's own bind decides the password; a service account (`bind_dn`)
    is only used to find the user's entry and groups;
  * a directory account is pinned to its directory identity (objectGUID /
    entryUUID, else the DN): it can never sign in as, or take over, a local
    account of the same name; repeated failures lock the account as usual.

Configuration (Admin, GET/PUT /api/ldap; data/ldap.json, SENTINEL_LDAP):
  enabled, url (ldaps://dc1.corp.example or ldap://...+ start_tls), ca_file,
  bind_dn + bind_password (service account; optional with user_dn_template),
  user_dn_template (e.g. "{username}@corp.example" for AD, or
  "uid={username},ou=people,dc=example,dc=org"), base_dn,
  user_filter (default AD: "(&(objectClass=user)(sAMAccountName={username}))"),
  group_filter (groups listing the user, default "(|(member={dn})(uniqueMember={dn}))",
  used besides memberOf, for OpenLDAP without the memberOf overlay),
  group_roles {group DN or CN: role}, default_role, nested_groups (AD: follow
  nested group membership), timeout.
"""
import hashlib
import json
import os
import re
import ssl

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SECRET_FIELDS = ('bind_password',)
DEFAULTS = {'enabled': False, 'url': '', 'start_tls': False, 'ca_file': '', 'bind_dn': '', 'bind_password': '',  # nosec B105: empty default, set by the Admin
            'user_dn_template': '', 'base_dn': '',
            'user_filter': '(&(objectClass=user)(sAMAccountName={username}))',
            'group_filter': '(|(member={dn})(uniqueMember={dn}))',
            'group_roles': {}, 'default_role': None, 'nested_groups': True, 'timeout': 8}
AD_IN_CHAIN = '1.2.840.113556.1.4.1941'          # LDAP_MATCHING_RULE_IN_CHAIN: nested membership
CLIENT_STRATEGY = None                           # ldap3 client strategy; tests use MOCK_SYNC (default: SYNC)
ATTRIBUTES = ['memberOf', 'objectGUID', 'entryUUID', 'sAMAccountName', 'uid', 'userPrincipalName', 'mail']


class LDAPError(Exception):
    """Sign-in refused. `code`: bad_password | no_role | unavailable | config; `reason` goes to the audit log."""

    def __init__(self, code, reason):
        super().__init__(reason)
        self.code, self.reason = code, reason


def config_file():
    return os.environ.get('SENTINEL_LDAP') or os.path.join(ROOT, 'data', 'ldap.json')


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
        url = str(cfg['url'] or '')
        if url.startswith('ldap://'):
            if not cfg['start_tls']:
                raise ValueError('ldap:// needs start_tls: passwords are never sent unencrypted (or use ldaps://)')
        elif not url.startswith('ldaps://'):
            raise ValueError('url must start with ldaps:// (or ldap:// with start_tls)')
        if not cfg['base_dn']:
            raise ValueError('base_dn is required')
        if not cfg['bind_dn'] and not cfg['user_dn_template']:
            raise ValueError('set bind_dn (a service account) or user_dn_template')
        if cfg['user_dn_template'] and '{username}' not in cfg['user_dn_template']:
            raise ValueError('user_dn_template must contain {username}')
        if '{username}' not in cfg['user_filter']:
            raise ValueError('user_filter must contain {username}')
        if cfg['ca_file'] and not os.path.isfile(cfg['ca_file']):
            raise ValueError(f'ca_file not found: {cfg["ca_file"]}')
    if not isinstance(cfg['group_roles'], dict):
        raise ValueError('group_roles must map group DNs or names to roles')
    for role in cfg['group_roles'].values():
        auth.validate_role(role)
    if cfg['default_role'] not in (None, ''):
        auth.validate_role(cfg['default_role'])
    cfg['timeout'] = max(2, min(30, int(cfg['timeout'] or 8)))
    return cfg


def save_config(cfg):
    current = load_config()
    for key in SECRET_FIELDS:
        if cfg.get(key) == '********':
            cfg[key] = current.get(key)
    cfg = validate(cfg)
    path = config_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2)
    os.replace(path + '.tmp', path)
    return cfg


def redacted(cfg):
    return {**cfg, **{k: '********' for k in SECRET_FIELDS if cfg.get(k)}}


def enabled():
    return bool(load_config().get('enabled'))


# ---------------- directory access ----------------

def _server(cfg):
    from ldap3 import Server, Tls
    tls = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLS_CLIENT,
              ca_certs_file=cfg['ca_file'] or None)
    return Server(cfg['url'], use_ssl=str(cfg['url']).startswith('ldaps://'), tls=tls,
                  connect_timeout=cfg['timeout'], get_info='NONE')


def _bind(cfg, server, user, password):
    """An open, bound connection, or None when the credentials are refused."""
    from ldap3 import SYNC, Connection
    from ldap3.core.exceptions import LDAPException
    conn = Connection(server, user=user, password=password, receive_timeout=cfg['timeout'], raise_exceptions=False,
                      auto_referrals=False, read_only=True, client_strategy=CLIENT_STRATEGY or SYNC)
    try:
        conn.open()
        if conn.closed:
            raise LDAPError('unavailable', f'cannot reach {cfg["url"]}')
        if cfg['start_tls'] and not str(cfg['url']).startswith('ldaps://') and not conn.start_tls():
            raise LDAPError('unavailable', 'StartTLS failed; refusing to send the password unencrypted')
        if conn.bind():
            return conn
        conn.unbind()
        return None
    except LDAPException as exc:
        raise LDAPError('unavailable', f'directory error: {exc.__class__.__name__}: {exc}'[:300])


def _escape(username):
    from ldap3.utils.conv import escape_filter_chars
    return escape_filter_chars(username)


def _find_user(cfg, conn, username):
    from ldap3 import SUBTREE
    flt = cfg['user_filter'].replace('{username}', _escape(username))
    conn.search(cfg['base_dn'], flt, SUBTREE, attributes=ATTRIBUTES, size_limit=2)
    entries = [e for e in conn.response or [] if e.get('type') == 'searchResEntry']
    if len(entries) != 1:
        raise LDAPError('bad_password', f'{len(entries)} directory entries match {username!r}')
    return entries[0]


def _groups(cfg, conn, entry):
    from ldap3 import SUBTREE
    from ldap3.utils.conv import escape_filter_chars
    groups = set()
    for dn in (entry.get('attributes') or {}).get('memberOf') or []:
        groups.add(str(dn))
    if cfg.get('group_filter'):
        try:
            conn.search(cfg['base_dn'], cfg['group_filter'].replace('{dn}', escape_filter_chars(entry['dn'])),
                        SUBTREE, attributes=['cn'], size_limit=500)
            groups |= {e['dn'] for e in conn.response or [] if e.get('type') == 'searchResEntry'}
        except Exception:
            pass
    if cfg.get('nested_groups'):
        flt = f'(member:{AD_IN_CHAIN}:={escape_filter_chars(entry["dn"])})'
        try:
            conn.search(cfg['base_dn'], flt, SUBTREE, attributes=['cn'], size_limit=500)
            groups |= {e['dn'] for e in conn.response or [] if e.get('type') == 'searchResEntry'}
        except Exception:
            pass                  # not Active Directory: direct memberOf only
    return groups


def _cn(dn):
    m = re.match(r'\s*cn=([^,]+)', dn, re.I)
    return m.group(1).strip() if m else dn


def role_for(cfg, groups):
    from core import auth
    mapping = {str(k).lower(): v for k, v in cfg['group_roles'].items()}
    roles = [mapping[key] for g in groups for key in (g.lower(), _cn(g).lower()) if key in mapping]
    if roles:
        return max(roles, key=auth.ROLE_RANK.get)
    if cfg.get('default_role'):
        return cfg['default_role']
    raise LDAPError('no_role', 'none of the directory groups is allowed to use this console')


def _external_id(cfg, entry):
    attrs = entry.get('attributes') or {}
    ident = attrs.get('objectGUID') or attrs.get('entryUUID') or entry['dn']
    if isinstance(ident, list):
        ident = ident[0] if ident else entry['dn']
    if isinstance(ident, bytes):
        ident = ident.hex()
    # the directory's own id for the entry (stable across renames and connection URLs); the DN otherwise
    return hashlib.sha256(f'ldap|{ident}'.lower().encode()).hexdigest()[:32]


def authenticate(username, password, cfg=None, server=None):
    """(username, role, external_id, dn) when the directory accepts the password; else LDAPError."""
    cfg = cfg or load_config()
    if not cfg.get('enabled'):
        raise LDAPError('config', 'directory sign-in is not enabled')
    username = str(username or '').strip()
    password = str(password or '')
    if not password:
        raise LDAPError('bad_password', 'empty password (would be an anonymous bind)')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,32}', username):
        # the account name (sAMAccountName / uid), as typed on the console; not user@domain
        raise LDAPError('bad_password', 'username has characters a directory account name cannot have')
    server = server or _server(cfg)
    if cfg.get('bind_dn'):
        lookup = _bind(cfg, server, cfg['bind_dn'], cfg.get('bind_password') or '')
        if lookup is None:
            raise LDAPError('config', 'the service account (bind_dn) was refused by the directory')
        try:
            entry = _find_user(cfg, lookup, username)
            groups = _groups(cfg, lookup, entry)
        finally:
            lookup.unbind()
        conn = _bind(cfg, server, entry['dn'], password)
        if conn is None:
            raise LDAPError('bad_password', 'the directory refused the password')
        conn.unbind()
    else:
        conn = _bind(cfg, server, cfg['user_dn_template'].replace('{username}', username), password)
        if conn is None:
            raise LDAPError('bad_password', 'the directory refused the password')
        try:
            entry = _find_user(cfg, conn, username)
            groups = _groups(cfg, conn, entry)
        finally:
            conn.unbind()
    return username, role_for(cfg, groups), _external_id(cfg, entry), entry['dn']


def lookup(username, cfg=None, server=None):
    """For the Admin's "test" button: find a user with the service account (no password is checked)."""
    cfg = cfg or load_config()
    if not cfg.get('enabled'):
        raise LDAPError('config', 'directory sign-in is not enabled')
    if not cfg.get('bind_dn'):
        raise LDAPError('config', 'a lookup needs the service account (bind_dn)')
    if not re.fullmatch(r'[A-Za-z0-9_.-]{3,32}', str(username or '')):
        raise LDAPError('config', 'not a valid account name')
    server = server or _server(cfg)
    conn = _bind(cfg, server, cfg['bind_dn'], cfg.get('bind_password') or '')
    if conn is None:
        raise LDAPError('config', 'the service account (bind_dn) was refused by the directory')
    try:
        entry = _find_user(cfg, conn, username)
        groups = sorted(_groups(cfg, conn, entry))
    except LDAPError as exc:
        return {'ok': False, 'error': exc.reason}
    finally:
        conn.unbind()
    try:
        role = role_for(cfg, groups)
    except LDAPError:
        role = None
    return {'ok': True, 'dn': entry['dn'], 'groups': groups[:50], 'role': role}
