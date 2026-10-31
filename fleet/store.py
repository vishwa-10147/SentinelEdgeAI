"""Fleet server state: enrolment codes, sites, their reports, templates and groups (data/fleet.db)."""
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CODE_TTL = 3600
HISTORY = 288                                             # reports kept per site (one day at 5-minute reports)


def default_path():
    return os.environ.get('SENTINEL_FLEET_DB') or os.path.join(ROOT, 'data', 'fleet.db')


def _hash(code):
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()


def template_version(text):
    return hashlib.sha256(text.encode()).hexdigest()[:16]


class FleetStore:
    def __init__(self, path=None):
        self.path = path or default_path()
        self._lock = threading.Lock()
        self._conn = None

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS codes (code_hash TEXT PRIMARY KEY, created INTEGER NOT NULL,
                    expires INTEGER NOT NULL, grp TEXT NOT NULL DEFAULT 'default', used_by TEXT);
                CREATE TABLE IF NOT EXISTS sites (id TEXT PRIMARY KEY, name TEXT NOT NULL, cert_fp TEXT NOT NULL,
                    grp TEXT NOT NULL DEFAULT 'default', enrolled INTEGER NOT NULL, last_seen INTEGER,
                    version TEXT, report TEXT, revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS reports (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL,
                    ts INTEGER NOT NULL, report TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS reports_site ON reports(site, ts);
                CREATE TABLE IF NOT EXISTS templates (name TEXT PRIMARY KEY, yaml TEXT NOT NULL, version TEXT NOT NULL,
                    updated INTEGER NOT NULL, updated_by TEXT);
                CREATE TABLE IF NOT EXISTS groups (name TEXT PRIMARY KEY, template TEXT, target_version TEXT,
                    stages TEXT NOT NULL DEFAULT '[]', started INTEGER, paused TEXT, updated_by TEXT);
                INSERT OR IGNORE INTO groups(name) VALUES ('default');
            """)
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _exec(self, sql, params=()):
        with self._lock:
            cur = self._db().execute(sql, params)
            self._conn.commit()
            return cur

    def _all(self, sql, params=()):
        with self._lock:
            return [dict(r) for r in self._db().execute(sql, params).fetchall()]

    def _one(self, sql, params=()):
        rows = self._all(sql, params)
        return rows[0] if rows else None

    # ---------- enrolment ----------

    def create_code(self, group='default', ttl=CODE_TTL):
        """A one-time enrolment code like 'K7QF-2M9P-XW4D'; the site joins `group`. Only the hash is kept."""
        if not self.get_group(group):
            raise ValueError(f'unknown group: {group}')
        alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        raw = ''.join(secrets.choice(alphabet) for _ in range(12))
        code = '-'.join(raw[i:i + 4] for i in range(0, 12, 4))
        now = int(time.time())
        self._exec('INSERT INTO codes(code_hash, created, expires, grp) VALUES (?,?,?,?)', (_hash(code), now, now + int(ttl), group))
        return code

    def redeem_code(self, code, site_id):
        """The group the code enrols into, or None if it is unknown, used or expired."""
        now = int(time.time())
        with self._lock:
            db = self._db()
            row = db.execute('SELECT grp FROM codes WHERE code_hash = ? AND used_by IS NULL AND expires > ?',
                             (_hash(str(code or '')), now)).fetchone()
            if not row:
                return None
            db.execute('UPDATE codes SET used_by = ? WHERE code_hash = ?', (site_id, _hash(str(code))))
            db.commit()
            return row['grp']

    def add_site(self, site_id, name, cert_fp, group):
        self._exec('INSERT INTO sites(id, name, cert_fp, grp, enrolled) VALUES (?,?,?,?,?)',
                   (site_id, name[:64], cert_fp, group, int(time.time())))

    # ---------- sites ----------

    def _site(self, row):
        if row is None:
            return None
        row['report'] = json.loads(row['report']) if row.get('report') else None
        row['revoked'] = bool(row['revoked'])
        return row

    def get_site(self, site_id):
        return self._site(self._one('SELECT * FROM sites WHERE id = ?', (site_id,)))

    def list_sites(self):
        return [self._site(r) for r in self._all('SELECT * FROM sites ORDER BY grp, name')]

    def revoke_site(self, site_id):
        return self._exec('UPDATE sites SET revoked = 1 WHERE id = ?', (site_id,)).rowcount == 1

    def set_site_group(self, site_id, group):
        if not self.get_group(group):
            raise ValueError(f'unknown group: {group}')
        return self._exec('UPDATE sites SET grp = ? WHERE id = ?', (group, site_id)).rowcount == 1

    def add_report(self, site_id, report):
        now = int(time.time())
        text = json.dumps(report, sort_keys=True, default=str)[:65536]
        with self._lock:
            db = self._db()
            db.execute('UPDATE sites SET last_seen = ?, version = ?, report = ? WHERE id = ?',
                       (now, str(report.get('version', ''))[:32], text, site_id))
            db.execute('INSERT INTO reports(site, ts, report) VALUES (?,?,?)', (site_id, now, text))
            db.execute('DELETE FROM reports WHERE site = ? AND id NOT IN '
                       '(SELECT id FROM reports WHERE site = ? ORDER BY id DESC LIMIT ?)', (site_id, site_id, HISTORY))
            db.commit()

    def history(self, site_id, limit=HISTORY):
        rows = self._all('SELECT ts, report FROM reports WHERE site = ? ORDER BY id DESC LIMIT ?', (site_id, int(limit)))
        return [{'ts': r['ts'], **json.loads(r['report'])} for r in rows]

    # ---------- templates and groups ----------

    def put_template(self, name, yaml_text, by):
        version = template_version(yaml_text)
        self._exec('INSERT INTO templates VALUES (?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET yaml = excluded.yaml, '
                   'version = excluded.version, updated = excluded.updated, updated_by = excluded.updated_by',
                   (name, yaml_text, version, int(time.time()), by))
        return version

    def get_template(self, name):
        return self._one('SELECT * FROM templates WHERE name = ?', (name,))

    def list_templates(self):
        return self._all('SELECT name, version, updated, updated_by FROM templates ORDER BY name')

    def _group(self, row):
        if row is None:
            return None
        row['stages'] = json.loads(row['stages'] or '[]')
        return row

    def get_group(self, name):
        return self._group(self._one('SELECT * FROM groups WHERE name = ?', (name,)))

    def list_groups(self):
        return [self._group(r) for r in self._all('SELECT * FROM groups ORDER BY name')]

    def put_group(self, name, template=None, target_version=None, stages=None, by='cli'):
        """Create or update a group. A new target version (re)starts its rollout."""
        old = self.get_group(name)
        restart = target_version and (not old or old['target_version'] != target_version)
        started = int(time.time()) if restart else (old or {}).get('started')
        paused = None if restart else (old or {}).get('paused')
        self._exec('INSERT INTO groups(name, template, target_version, stages, started, paused, updated_by) '
                   'VALUES (?,?,?,?,?,?,?) ON CONFLICT(name) DO UPDATE SET template = excluded.template, '
                   'target_version = excluded.target_version, stages = excluded.stages, started = excluded.started, '
                   'paused = excluded.paused, updated_by = excluded.updated_by',
                   (name, template, target_version, json.dumps(stages or []), started, paused, by))
        return self.get_group(name)

    def pause_group(self, name, reason):
        self._exec('UPDATE groups SET paused = ? WHERE name = ?', (str(reason)[:300], name))

    def resume_group(self, name):
        self._exec('UPDATE groups SET paused = NULL WHERE name = ?', (name,))
