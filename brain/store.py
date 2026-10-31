"""Brain-side state: enrolled sensors, enrolment codes, received flows, commands.

SQLite by default; PostgreSQL when SENTINEL_BRAIN_DATABASE_URL (or DATABASE_URL,
as for the engine) is set, for brains with many sensors. The flow table is append-only and
deduplicated on (sensor_id, rid) so a batch the sensor re-sends after a lost
acknowledgement is stored once.
"""
import hashlib
import json
import os
import secrets
import sqlite3
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
CODE_TTL = 3600


PG_SCHEMA = """
    CREATE TABLE IF NOT EXISTS sensors (
        id TEXT PRIMARY KEY, name TEXT, cert_fp TEXT NOT NULL, enrolled BIGINT NOT NULL,
        last_seen BIGINT, health TEXT, revoked INTEGER NOT NULL DEFAULT 0);
    CREATE TABLE IF NOT EXISTS enroll_codes (
        code_hash TEXT PRIMARY KEY, created BIGINT NOT NULL, expires BIGINT NOT NULL, used_by TEXT);
    CREATE TABLE IF NOT EXISTS flows (
        id BIGSERIAL PRIMARY KEY, sensor_id TEXT NOT NULL, rid BIGINT NOT NULL,
        received BIGINT NOT NULL, record TEXT NOT NULL, UNIQUE(sensor_id, rid));
    CREATE INDEX IF NOT EXISTS flows_sensor ON flows(sensor_id, id);
    CREATE TABLE IF NOT EXISTS commands (
        sensor_id TEXT NOT NULL, seq BIGINT NOT NULL, envelope TEXT NOT NULL,
        created BIGINT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', result TEXT,
        PRIMARY KEY (sensor_id, seq));
    CREATE TABLE IF NOT EXISTS lease (name TEXT PRIMARY KEY, holder TEXT NOT NULL, expires BIGINT NOT NULL);
    ALTER TABLE sensors ADD COLUMN IF NOT EXISTS segment TEXT;
"""


def database_url():
    """PostgreSQL URL for the brain, if one is configured (otherwise SQLite)."""
    return os.environ.get('SENTINEL_BRAIN_DATABASE_URL') or os.environ.get('DATABASE_URL') or None


class _PgConnection:
    """Just enough of sqlite3.Connection for BrainStore, on PostgreSQL (psycopg2)."""

    def __init__(self, url):
        import psycopg2
        import psycopg2.extras
        self._extras = psycopg2.extras
        self.conn = psycopg2.connect(url)
        self.conn.autocommit = True
        self.total_changes = 0

    @staticmethod
    def _sql(sql):
        if sql.strip().upper() == 'BEGIN IMMEDIATE':
            return 'BEGIN'
        if sql.lstrip().upper().startswith('INSERT OR IGNORE'):
            sql = sql.replace('INSERT OR IGNORE', 'INSERT', 1) + ' ON CONFLICT DO NOTHING'
        return sql.replace('?', '%s')

    def execute(self, sql, params=()):
        cur = self.conn.cursor(cursor_factory=self._extras.RealDictCursor)
        cur.execute(self._sql(sql), tuple(params))
        if cur.rowcount and cur.rowcount > 0 and not sql.lstrip().upper().startswith('SELECT'):
            self.total_changes += cur.rowcount
        return cur

    def executemany(self, sql, rows):
        for row in rows:
            self.execute(sql, row)

    def executescript(self, script):
        self.conn.cursor().execute(script)

    def close(self):
        self.conn.close()


def default_path():
    return os.environ.get('SENTINEL_BRAIN_DB') or os.path.join(ROOT, 'data', 'brain.db')


def _hash(code):
    return hashlib.sha256(code.strip().upper().encode()).hexdigest()


class BrainStore:
    def __init__(self, path=None, url=None):
        self.url = url or (None if path else database_url())
        # `path` identifies the store (brain.manage compares it); for PostgreSQL it is the URL
        self.path = self.url or path or default_path()
        self._lock = threading.Lock()
        self._conn = None

    def _db(self):
        if self._conn is None and self.url:
            conn = _PgConnection(self.url)
            conn.executescript(PG_SCHEMA)
            self._conn = conn
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            fresh = not os.path.exists(self.path)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10, isolation_level=None)
            conn.row_factory = sqlite3.Row
            if fresh and os.name == 'posix':
                os.chmod(self.path, 0o600)
            conn.execute('PRAGMA journal_mode=WAL')
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS sensors (
                    id TEXT PRIMARY KEY, name TEXT, cert_fp TEXT NOT NULL, enrolled INTEGER NOT NULL,
                    last_seen INTEGER, health TEXT, revoked INTEGER NOT NULL DEFAULT 0);
                CREATE TABLE IF NOT EXISTS enroll_codes (
                    code_hash TEXT PRIMARY KEY, created INTEGER NOT NULL, expires INTEGER NOT NULL,
                    used_by TEXT);
                CREATE TABLE IF NOT EXISTS flows (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, sensor_id TEXT NOT NULL, rid INTEGER NOT NULL,
                    received INTEGER NOT NULL, record TEXT NOT NULL, UNIQUE(sensor_id, rid));
                CREATE TABLE IF NOT EXISTS commands (
                    sensor_id TEXT NOT NULL, seq INTEGER NOT NULL, envelope TEXT NOT NULL,
                    created INTEGER NOT NULL, status TEXT NOT NULL DEFAULT 'pending', result TEXT,
                    PRIMARY KEY (sensor_id, seq));
                CREATE TABLE IF NOT EXISTS lease (name TEXT PRIMARY KEY, holder TEXT NOT NULL, expires INTEGER NOT NULL);
            """)
            if 'segment' not in {r[1] for r in conn.execute('PRAGMA table_info(sensors)')}:
                conn.execute('ALTER TABLE sensors ADD COLUMN segment TEXT')   # brains from before 2.8
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def _exec(self, sql, params=()):
        with self._lock:
            return self._db().execute(sql, params)

    def _one(self, sql, params=()):
        with self._lock:
            row = self._db().execute(sql, params).fetchone()
            return dict(row) if row else None

    def _all(self, sql, params=()):
        with self._lock:
            return [dict(r) for r in self._db().execute(sql, params).fetchall()]

    # ---------- enrolment ----------

    def create_code(self, ttl=CODE_TTL):
        """A one-time enrolment code, e.g. 'K7QF-2M9P-XW4D'. Only its hash is stored."""
        alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'
        raw = ''.join(secrets.choice(alphabet) for _ in range(12))
        code = '-'.join(raw[i:i + 4] for i in range(0, 12, 4))
        now = int(time.time())
        self._exec('INSERT INTO enroll_codes(code_hash, created, expires) VALUES (?, ?, ?)',
                   (_hash(code), now, now + int(ttl)))
        return code

    def redeem_code(self, code, sensor_id):
        """Mark a code used by `sensor_id`; False if unknown, used or expired."""
        now = int(time.time())
        with self._lock:
            cur = self._db().execute(
                'UPDATE enroll_codes SET used_by = ? WHERE code_hash = ? AND used_by IS NULL AND expires > ?',
                (sensor_id, _hash(str(code or '')), now))
            return cur.rowcount == 1

    def add_sensor(self, sensor_id, name, cert_fp):
        self._exec('INSERT INTO sensors(id, name, cert_fp, enrolled) VALUES (?, ?, ?, ?)',
                   (sensor_id, str(name)[:64], cert_fp, int(time.time())))

    def get_sensor(self, sensor_id):
        return self._one('SELECT * FROM sensors WHERE id = ?', (sensor_id,))

    def list_sensors(self):
        rows = self._all('SELECT s.*, (SELECT COUNT(*) FROM flows f WHERE f.sensor_id = s.id) AS flows '
                         'FROM sensors s ORDER BY enrolled')
        for r in rows:
            r['health'] = json.loads(r['health']) if r['health'] else None
            r['revoked'] = bool(r['revoked'])
        return rows

    def set_segment(self, sensor_id, segment):
        """Sensors sharing a segment back each other up for enforcement (see brain.manage)."""
        if not self.get_sensor(sensor_id):
            raise KeyError(sensor_id)
        self._exec('UPDATE sensors SET segment = ? WHERE id = ?', (segment or None, sensor_id))

    def segment_sensors(self, segment):
        return self._all('SELECT * FROM sensors WHERE segment = ? AND revoked = 0 ORDER BY last_seen DESC',
                         (segment,))

    # ---------- high availability ----------

    def acquire_lease(self, name, holder, ttl):
        """Take or renew lease `name` for `holder`; True if `holder` has it now."""
        now = int(time.time())
        with self._lock:
            db = self._db()
            db.execute('INSERT INTO lease(name, holder, expires) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET '
                       'holder = excluded.holder, expires = excluded.expires '
                       'WHERE lease.expires < ? OR lease.holder = excluded.holder', (name, holder, now + int(ttl), now))
            row = db.execute('SELECT holder FROM lease WHERE name = ?', (name,)).fetchone()
        return bool(row) and row['holder'] == holder

    def lease(self, name):
        return self._one('SELECT holder, expires FROM lease WHERE name = ?', (name,))

    def release_lease(self, name, holder):
        self._exec('DELETE FROM lease WHERE name = ? AND holder = ?', (name, holder))

    def revoke_sensor(self, sensor_id):
        if not self.get_sensor(sensor_id):
            raise KeyError(sensor_id)
        self._exec('UPDATE sensors SET revoked = 1 WHERE id = ?', (sensor_id,))

    def touch(self, sensor_id, health=None):
        if health is None:
            self._exec('UPDATE sensors SET last_seen = ? WHERE id = ?', (int(time.time()), sensor_id))
        else:
            self._exec('UPDATE sensors SET last_seen = ?, health = ? WHERE id = ?',
                       (int(time.time()), json.dumps(health)[:4096], sensor_id))

    # ---------- flows ----------

    def add_flows(self, sensor_id, items):
        """Store [(rid, record)]; returns how many were new."""
        now = int(time.time())
        rows = [(sensor_id, int(rid), now, json.dumps(rec, separators=(',', ':'))) for rid, rec in items]
        with self._lock:
            db = self._db()
            before = db.total_changes
            db.execute('BEGIN IMMEDIATE')
            db.executemany('INSERT OR IGNORE INTO flows(sensor_id, rid, received, record) VALUES (?, ?, ?, ?)', rows)
            db.execute('COMMIT')
            return db.total_changes - before

    def flow_count(self, sensor_id=None):
        if sensor_id:
            return self._one('SELECT COUNT(*) AS n FROM flows WHERE sensor_id = ?', (sensor_id,))['n']
        return self._one('SELECT COUNT(*) AS n FROM flows')['n']

    def recent_flows(self, limit=100, sensor_id=None):
        sql = 'SELECT sensor_id, rid, received, record FROM flows'
        params = []
        if sensor_id:
            sql += ' WHERE sensor_id = ?'
            params.append(sensor_id)
        sql += ' ORDER BY id DESC LIMIT ?'
        params.append(int(limit))
        out = []
        for r in self._all(sql, params):
            out.append({**json.loads(r['record']), 'sensor_id': r['sensor_id'], 'received': r['received']})
        return out

    # ---------- commands ----------

    def next_seq(self, sensor_id):
        row = self._one('SELECT MAX(seq) AS s FROM commands WHERE sensor_id = ?', (sensor_id,))
        return (row['s'] or 0) + 1

    def add_command(self, sensor_id, seq, envelope):
        self._exec('INSERT INTO commands(sensor_id, seq, envelope, created) VALUES (?, ?, ?, ?)',
                   (sensor_id, seq, json.dumps(envelope), int(time.time())))

    def pending_commands(self, sensor_id, after=0):
        rows = self._all("SELECT seq, envelope FROM commands WHERE sensor_id = ? AND seq > ? "
                         "AND status = 'pending' ORDER BY seq", (sensor_id, int(after)))
        return [json.loads(r['envelope']) for r in rows]

    def command_result(self, sensor_id, seq, status, result):
        self._exec('UPDATE commands SET status = ?, result = ? WHERE sensor_id = ? AND seq = ?',
                   (str(status)[:16], json.dumps(result)[:2048], sensor_id, int(seq)))

    def list_commands(self, sensor_id=None, limit=100):
        sql, params = 'SELECT * FROM commands', []
        if sensor_id:
            sql += ' WHERE sensor_id = ?'
            params.append(sensor_id)
        sql += ' ORDER BY created DESC, seq DESC LIMIT ?'
        params.append(int(limit))
        rows = self._all(sql, params)
        for r in rows:
            r['payload'] = json.loads(r.pop('envelope'))['payload']
            r['result'] = json.loads(r['result']) if r['result'] else None
        return rows
