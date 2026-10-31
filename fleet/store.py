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
ACTION_TTL = 3600                                         # an action not picked up within an hour expires
ALERT_RETENTION = 30 * 86400                              # shared alert summaries kept for 30 days
ALERTS_PER_SITE = 50000                                   # and at most this many per site


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
                CREATE TABLE IF NOT EXISTS fl_rounds (id INTEGER PRIMARY KEY AUTOINCREMENT, model TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open', created INTEGER NOT NULL, min_sites INTEGER NOT NULL,
                    base INTEGER, global TEXT, aggregated INTEGER, by TEXT);
                CREATE TABLE IF NOT EXISTS fl_updates (round INTEGER NOT NULL, site TEXT NOT NULL, ts INTEGER NOT NULL,
                    n_samples INTEGER NOT NULL, upd TEXT NOT NULL, PRIMARY KEY (round, site));
                CREATE TABLE IF NOT EXISTS actions (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL,
                    kind TEXT NOT NULL, ip TEXT NOT NULL, ttl INTEGER, reason TEXT, created INTEGER NOT NULL,
                    expires INTEGER NOT NULL, by TEXT, status TEXT NOT NULL DEFAULT 'queued', delivered INTEGER,
                    done INTEGER, result TEXT);
                CREATE INDEX IF NOT EXISTS actions_site ON actions(site, status);
                CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, site TEXT NOT NULL,
                    ts INTEGER NOT NULL, type TEXT, score REAL, severity TEXT, src_ip TEXT, dst_ip TEXT,
                    dst_port INTEGER, proto TEXT, mitre TEXT, summary TEXT);
                CREATE INDEX IF NOT EXISTS alerts_ts ON alerts(ts);
                CREATE INDEX IF NOT EXISTS alerts_site ON alerts(site, ts);
                CREATE INDEX IF NOT EXISTS alerts_src ON alerts(src_ip);
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

    # ---------- federated learning ----------

    def latest_global(self, model='autoencoder'):
        """The newest aggregated round as {'round', 'global'} or None."""
        row = self._one("SELECT id, global FROM fl_rounds WHERE model = ? AND status = 'aggregated' "
                        'ORDER BY id DESC LIMIT 1', (model,))
        return {'round': row['id'], 'global': json.loads(row['global'])} if row else None

    def open_round(self, model='autoencoder'):
        return self._one("SELECT * FROM fl_rounds WHERE model = ? AND status = 'open' ORDER BY id DESC LIMIT 1", (model,))

    def start_round(self, model, min_sites, by):
        if self.open_round(model):
            raise ValueError('a round is already open; wait for it or close it first')
        base = self.latest_global(model)
        cur = self._exec('INSERT INTO fl_rounds(model, created, min_sites, base, by) VALUES (?,?,?,?,?)',
                         (model, int(time.time()), int(min_sites), base['round'] if base else None, by))
        return self._one('SELECT * FROM fl_rounds WHERE id = ?', (cur.lastrowid,))

    def close_round(self, round_id):
        self._exec("UPDATE fl_rounds SET status = 'closed' WHERE id = ? AND status = 'open'", (round_id,))

    def add_update(self, round_id, site_id, update):
        self._exec('INSERT OR REPLACE INTO fl_updates VALUES (?,?,?,?,?)',
                   (round_id, site_id, int(time.time()), int(update['n_samples']), json.dumps(update)))
        return self._one('SELECT COUNT(*) AS n FROM fl_updates WHERE round = ?', (round_id,))['n']

    def updates(self, round_id):
        return [json.loads(r['upd']) for r in self._all('SELECT upd FROM fl_updates WHERE round = ? ORDER BY site',
                                                        (round_id,))]

    def submitted(self, round_id, site_id):
        return bool(self._one('SELECT 1 AS x FROM fl_updates WHERE round = ? AND site = ?', (round_id, site_id)))

    def finish_round(self, round_id, global_model):
        self._exec("UPDATE fl_rounds SET status = 'aggregated', global = ?, aggregated = ? WHERE id = ?",
                   (json.dumps(global_model), int(time.time()), round_id))

    def rounds(self, limit=20):
        rows = self._all('SELECT r.id, r.model, r.status, r.created, r.min_sites, r.base, r.aggregated, r.by, '
                         '(SELECT COUNT(*) FROM fl_updates u WHERE u.round = r.id) AS updates, '
                         '(SELECT SUM(n_samples) FROM fl_updates u WHERE u.round = r.id) AS samples '
                         'FROM fl_rounds r ORDER BY r.id DESC LIMIT ?', (int(limit),))
        return rows

    # ---------- remote actions ----------

    def queue_action(self, site_id, kind, ip, ttl, reason, by, ttl_queue=ACTION_TTL):
        now = int(time.time())
        cur = self._exec('INSERT INTO actions(site, kind, ip, ttl, reason, created, expires, by) VALUES (?,?,?,?,?,?,?,?)',
                         (site_id, kind, ip, ttl, (reason or '')[:200], now, now + int(ttl_queue), by))
        return self.get_action(cur.lastrowid)

    def get_action(self, action_id):
        row = self._one('SELECT * FROM actions WHERE id = ?', (int(action_id),))
        if row and row.get('result'):
            row['result'] = json.loads(row['result'])
        return row

    def _expire_actions(self, now):
        self._exec("UPDATE actions SET status = 'expired' WHERE status IN ('queued', 'delivered') AND expires <= ?",
                   (int(now),))

    def pending_actions(self, site_id, now=None):
        """Actions this site has not finished yet, oldest first; marks them delivered.
        Delivered but unanswered actions are handed out again (the site skips ids it already ran)."""
        now = int(now or time.time())
        self._expire_actions(now)
        rows = self._all("SELECT id, kind, ip, ttl, reason, created, expires, by FROM actions "
                         "WHERE site = ? AND status IN ('queued', 'delivered') ORDER BY id LIMIT 50", (site_id,))
        if rows:
            self._exec("UPDATE actions SET status = 'delivered', delivered = COALESCE(delivered, ?) "
                       "WHERE site = ? AND status = 'queued' AND id <= ?", (now, site_id, rows[-1]['id']))
        return rows

    def finish_action(self, site_id, action_id, ok, result):
        """Record a site's answer; only for its own, still open actions."""
        return self._exec("UPDATE actions SET status = ?, done = ?, result = ? WHERE id = ? AND site = ? "
                          "AND status IN ('queued', 'delivered')",
                          ('done' if ok else 'failed', int(time.time()), json.dumps(result, default=str)[:4000],
                           int(action_id), site_id)).rowcount == 1

    def cancel_action(self, action_id):
        return self._exec("UPDATE actions SET status = 'cancelled' WHERE id = ? AND status = 'queued'",
                          (int(action_id),)).rowcount == 1

    def list_actions(self, site_id=None, limit=100):
        self._expire_actions(time.time())
        sql, params = 'SELECT * FROM actions', []
        if site_id:
            sql, params = sql + ' WHERE site = ?', [site_id]
        rows = self._all(sql + ' ORDER BY id DESC LIMIT ?', (*params, int(limit)))
        for r in rows:
            r['result'] = json.loads(r['result']) if r.get('result') else None
        return rows

    # ---------- shared alert summaries ----------

    ALERT_FIELDS = ('ts', 'type', 'score', 'severity', 'src_ip', 'dst_ip', 'dst_port', 'proto', 'mitre', 'summary')

    def add_alerts(self, site_id, alerts, now=None):
        now = int(now or time.time())
        rows = []
        for a in (alerts or [])[:500]:
            if not isinstance(a, dict):
                continue
            try:
                ts = int(a.get('ts'))
                score = float(a['score']) if a.get('score') is not None else None
                port = int(a['dst_port']) if a.get('dst_port') not in (None, '') else None
            except (TypeError, ValueError):
                continue
            if ts < now - ALERT_RETENTION or ts > now + 3600:
                continue
            text = lambda k, n=64: str(a[k])[:n] if a.get(k) not in (None, '') else None  # noqa: E731
            rows.append((site_id, ts, text('type'), score, text('severity', 16), text('src_ip', 45), text('dst_ip', 45),
                         port, text('proto', 16), text('mitre', 32), text('summary', 300)))
        if not rows:
            return 0
        with self._lock:
            db = self._db()
            db.executemany('INSERT INTO alerts(site, ts, type, score, severity, src_ip, dst_ip, dst_port, proto, mitre, '
                           'summary) VALUES (?,?,?,?,?,?,?,?,?,?,?)', rows)
            db.execute('DELETE FROM alerts WHERE ts < ?', (now - ALERT_RETENTION,))
            db.execute('DELETE FROM alerts WHERE site = ? AND id NOT IN '
                       '(SELECT id FROM alerts WHERE site = ? ORDER BY ts DESC, id DESC LIMIT ?)',
                       (site_id, site_id, ALERTS_PER_SITE))
            db.commit()
        return len(rows)

    def search_alerts(self, q=None, ip=None, site=None, group=None, min_score=None, since=None, until=None,
                      limit=200):
        """Alert summaries from every site, newest first, with the site's name and group."""
        where, params = [], []
        if q:
            like = '%' + str(q).replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
            where.append("(a.type LIKE ? ESCAPE '\\' OR a.summary LIKE ? ESCAPE '\\' OR a.mitre LIKE ? ESCAPE '\\' "
                         "OR a.src_ip LIKE ? ESCAPE '\\' OR a.dst_ip LIKE ? ESCAPE '\\' OR s.name LIKE ? ESCAPE '\\')")
            params += [like] * 6
        if ip:
            where.append('(a.src_ip = ? OR a.dst_ip = ?)')
            params += [ip, ip]
        if site:
            where.append('a.site = ?')
            params.append(site)
        if group:
            where.append('s.grp = ?')
            params.append(group)
        if min_score is not None:
            where.append('a.score >= ?')
            params.append(float(min_score))
        if since is not None:
            where.append('a.ts >= ?')
            params.append(int(since))
        if until is not None:
            where.append('a.ts <= ?')
            params.append(int(until))
        sql = ('SELECT a.*, s.name AS site_name, s.grp AS site_group FROM alerts a LEFT JOIN sites s ON s.id = a.site'
               + (' WHERE ' + ' AND '.join(where) if where else '') + ' ORDER BY a.ts DESC, a.id DESC LIMIT ?')
        return self._all(sql, (*params, max(1, min(int(limit), 1000))))
