"""Graduated response: alert -> rate-limit -> (contain) -> block (TTL) -> quarantine.

A detection is mapped to the highest playbook step whose min_risk it
reaches; repeated detections of the same source within the window escalate
one step further. Steps at or above the approval threshold wait for an
Operator's approval while the approval period lasts (e.g. the first 30 days
of a new deployment), so automatic enforcement starts out supervised.

The configuration comes from the response policy (enforcement.policy).
Response tuning (enforcement.tuning) may pick a gentler action than the step,
never a stronger one, once evidence shows it resolves that kind of incident.
"""
import json
import os
import sqlite3
import threading
import time

import core.audit as audit
import core.firewall as firewall

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ACTIONS = ('alert', 'rate_limit', 'contain', 'block', 'quarantine')
DEFAULT_PLAYBOOK = {
    'steps': [
        {'action': 'alert', 'min_risk': 50},
        {'action': 'rate_limit', 'min_risk': 65, 'ttl': 600},
        {'action': 'block', 'min_risk': 75, 'ttl': 3600},
        {'action': 'quarantine', 'min_risk': 90, 'ttl': 86400},
    ],
    'escalate_after': 3,        # detections of one source within the window
    'window_seconds': 600,
    'approval': {'required_from_risk': 75, 'until': None},   # until: epoch seconds or None (always)
}


def default_path():
    return os.environ.get('SENTINEL_PLAYBOOK_DB') or os.path.join(ROOT, 'data', 'playbook.db')


class Playbook:
    def __init__(self, config=None, path=None, firewall_module=None, clock=time.time):
        self.config = config or DEFAULT_PLAYBOOK
        self.path = path or default_path()
        self.fw = firewall_module or firewall
        self.clock = clock
        self._lock = threading.Lock()
        self._conn = None
        self._tuner = None

    @property
    def tuner(self):
        if self._tuner is None:
            from enforcement.tuning import Tuner

            def false_positives():
                try:
                    from detection.feedback import get_store
                    return get_store().false_positive_kinds(since=self.clock() - 30 * 86400)
                except Exception:
                    return set()
            self._tuner = Tuner(self._db, self._lock, clock=self.clock, false_positives=false_positives)
        return self._tuner

    def _tuned(self, ip, kind, step):
        """(action to take, recommendation or None) within the bounds of `step` (see enforcement.tuning)."""
        from enforcement import tuning
        cfg = tuning.load_config()
        if cfg['mode'] == 'off' or step['action'] == 'alert':
            return step['action'], None
        try:
            from detection.peers import PeerStore, learned
            store = PeerStore()
            try:
                profile_ok = learned(store.profile(ip))
            finally:
                store.close()
        except Exception:
            profile_ok = False
        action, why = self.tuner.choose(ip, kind, step['action'], cfg, profile_learned=profile_ok)
        rec = {'action': action, 'why': why, 'mode': cfg['mode'], 'ceiling': step['action']}
        return (action if cfg['mode'] == 'apply' else step['action']), rec

    def _ttl(self, action, step):
        if action == step['action']:
            return step.get('ttl')
        for st in self.config['steps']:
            if st['action'] == action:
                return st.get('ttl')
        from enforcement.tuning import DEFAULT_TTL
        return DEFAULT_TTL.get(action)

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS detections (ip TEXT NOT NULL, ts REAL NOT NULL, risk INTEGER);
                CREATE INDEX IF NOT EXISTS detections_ip ON detections(ip, ts);
                CREATE TABLE IF NOT EXISTS pending (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, action TEXT NOT NULL,
                    ttl INTEGER, risk INTEGER, reason TEXT, created REAL NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending', decided_by TEXT, decided REAL, result TEXT);
            """)
            conn.commit()
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    # ---------- deciding ----------

    def _step_for(self, risk, recent):
        steps = sorted(self.config['steps'], key=lambda s: s['min_risk'])
        index = None
        for i, step in enumerate(steps):
            if risk >= step['min_risk']:
                index = i
        if index is None:
            return None
        if recent >= self.config.get('escalate_after', 3) and index + 1 < len(steps):
            index += 1  # a persistent source moves up one step
        return steps[index]

    def needs_approval(self, step, risk):
        gate = self.config.get('approval') or {}
        threshold = gate.get('required_from_risk')
        if threshold is None or step['action'] == 'alert' or risk < threshold:
            return False
        until = gate.get('until')
        return until is None or self.clock() < until

    def evaluate(self, ip, risk, reason=''):
        """Decide and act on one detection. Returns {'action', 'status', ...}."""
        now = self.clock()
        window = self.config.get('window_seconds', 600)
        with self._lock:
            db = self._db()
            db.execute('INSERT INTO detections(ip, ts, risk) VALUES (?, ?, ?)', (ip, now, int(risk)))
            db.execute('DELETE FROM detections WHERE ts < ?', (now - 86400,))
            recent = db.execute('SELECT COUNT(*) FROM detections WHERE ip = ? AND ts >= ?',
                                (ip, now - window)).fetchone()[0]
            db.commit()
        step = self._step_for(int(risk), recent)
        if step is None:
            return {'action': None, 'status': 'below_threshold'}
        kind = str(reason or 'anomaly')
        try:
            action, rec = self._tuned(ip, kind, step)
        except Exception:
            action, rec = step['action'], None
        extra = {'tuning': rec} if rec else {}
        if action == 'alert':
            if rec:
                self.tuner.record(ip, kind, 'alert', step['action'])
            return {'action': 'alert', 'status': 'alerted', **extra}
        step = {**step, 'action': action, 'ttl': self._ttl(action, step), 'ceiling': step['action']}
        if self.needs_approval(step, int(risk)):
            with self._lock:
                db = self._db()
                dup = db.execute("SELECT id FROM pending WHERE ip = ? AND action = ? AND status = 'pending'",
                                 (ip, step['action'])).fetchone()
                if dup:
                    return {'action': step['action'], 'status': 'awaiting_approval', 'pending_id': dup[0]}
                cur = db.execute('INSERT INTO pending(ip, action, ttl, risk, reason, created) VALUES (?,?,?,?,?,?)',
                                 (ip, step['action'], step.get('ttl'), int(risk), str(reason)[:200], now))
                db.commit()
                pid = cur.lastrowid
            audit.record('playbook', actor='engine', actor_kind='engine', target=ip, outcome='awaiting_approval',
                         details={'action': step['action'], 'risk': int(risk), 'pending_id': pid, 'reason': reason,
                                  **extra})
            return {'action': step['action'], 'status': 'awaiting_approval', 'pending_id': pid, **extra}
        result = self._execute(ip, step['action'], step.get('ttl'), reason)
        if result['status'] == 'refused' and step['action'] == 'contain':
            # no usable profile after all: fall back to what the playbook chose
            step = {**step, 'action': step['ceiling'], 'ttl': self._ttl(step['ceiling'], step)}
            result = self._execute(ip, step['action'], step.get('ttl'), reason)
        if result['status'] == 'applied' and rec:
            self.tuner.record(ip, kind, step['action'], step['ceiling'])
        audit.record('playbook', actor='engine', actor_kind='engine', target=ip,
                     outcome='success' if result['status'] == 'applied' else result['status'],
                     details={'action': step['action'], 'risk': int(risk), 'recent': recent, 'reason': reason,
                              'detail': result.get('detail'), **extra})
        return {'action': step['action'], **result, **extra}

    def _execute(self, ip, action, ttl, reason):
        reason = f'playbook:{reason}' if reason else 'playbook'
        try:
            if action == 'block':
                self.fw.add_block(ip, ttl=ttl, reason=reason)
            elif action == 'rate_limit':
                self.fw.add_restriction('ratelimit', ip, ttl=ttl, reason=reason)
            elif action == 'contain':
                self.fw.add_restriction('contain', ip, ttl=ttl, reason=reason)
            elif action == 'quarantine':
                mac = None
                try:
                    from enforcement.identity import get_registry
                    device = get_registry().by_ip(ip)
                    mac = device['mac'] if device else None
                except Exception:
                    pass
                self.fw.add_restriction('quarantine', ip, ttl=ttl, reason=reason, mac=mac)
            return {'status': 'applied'}
        except ValueError as exc:
            # protected or whitelisted host: never enforced
            return {'status': 'refused', 'detail': str(exc)}

    # ---------- approvals ----------

    def pending(self, status='pending', limit=200):
        with self._lock:
            rows = self._db().execute('SELECT * FROM pending WHERE status = ? ORDER BY created DESC LIMIT ?',
                                      (status, int(limit))).fetchall()
        return [dict(r) for r in rows]

    def decide(self, pending_id, approve, by):
        with self._lock:
            row = self._db().execute('SELECT * FROM pending WHERE id = ?', (int(pending_id),)).fetchone()
        if not row:
            raise KeyError(pending_id)
        if row['status'] != 'pending':
            raise ValueError(f"already {row['status']}")
        result = self._execute(row['ip'], row['action'], row['ttl'], row['reason']) if approve \
            else {'status': 'denied'}
        status = ('approved' if result['status'] == 'applied' else result['status']) if approve else 'denied'
        if result['status'] == 'applied':
            try:
                from enforcement import tuning
                if tuning.load_config()['mode'] != 'off':
                    self.tuner.record(row['ip'], str(row['reason'] or 'anomaly'), row['action'], row['action'])
            except Exception:
                pass
        with self._lock:
            db = self._db()
            db.execute('UPDATE pending SET status = ?, decided_by = ?, decided = ?, result = ? WHERE id = ?',
                       (status, str(by), self.clock(), json.dumps(result), int(pending_id)))
            db.commit()
        return {'id': int(pending_id), 'status': status, 'ip': row['ip'], 'action': row['action'],
                'detail': result.get('detail')}


_playbook = None


def get_playbook():
    """Playbook configured from the current response policy."""
    global _playbook
    from enforcement import policy
    config = policy.current().get('playbook') or DEFAULT_PLAYBOOK
    if _playbook is None or _playbook.path != default_path() or _playbook.config != config:
        if _playbook is not None:
            _playbook.close()
        _playbook = Playbook(config)
    return _playbook
