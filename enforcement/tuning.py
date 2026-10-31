"""Response tuning: learn which response resolves each kind of incident with the least disruption (Phase 7).

A contextual bandit, the practical form of reinforcement learning here:

  context   the kind of detection (port_scan, brute_force, ...)
  actions   alert < rate_limit < contain < block < quarantine (in order of disruption)
  outcome   resolved: no new detection of that source within `window` seconds after the
            action; an analyst's false-positive label counts as "an alert alone was enough"
  learner   Beta posterior of P(resolved) per (kind, action); Thompson sampling picks the
            least disruptive action whose sampled P(resolved) reaches `target`

Bounds a person set are never crossed:
  - the ceiling is what the response playbook chose for this risk: the tuner can only pick
    something gentler, never stronger
  - the floor (`min_action`, default rate_limit) is the gentlest it may pick
  - while an incident is ongoing (the same source is detected again), the next response is
    always stronger than the one that just failed
  - the playbook's approval gate applies to whatever is chosen
Gentler actions start from a pessimistic prior, so they are tried rarely until evidence
supports them. Modes: off, recommend (shadow: decisions unchanged, recommendation shown and
audited; the default) and apply.
"""
import json
import math
import os
import random
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
ORDER = ('alert', 'rate_limit', 'contain', 'block', 'quarantine')
DEFAULT_TTL = {'rate_limit': 600, 'contain': 3600, 'block': 3600, 'quarantine': 86400}
MODES = ('off', 'recommend', 'apply')
DEFAULTS = {'mode': 'recommend', 'target': 0.8, 'window_seconds': 3600, 'min_action': 'rate_limit'}
CEILING_PRIOR = (1, 1)
GENTLER_PRIOR = (1, 4)                                   # mean 0.2: little chance of being tried without evidence

SCHEMA = """
    CREATE TABLE IF NOT EXISTS tuning_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT NOT NULL, kind TEXT NOT NULL, action TEXT NOT NULL,
        ceiling TEXT NOT NULL, ts REAL NOT NULL, outcome INTEGER, settled REAL);
    CREATE INDEX IF NOT EXISTS tuning_events_ip ON tuning_events(ip, ts);
"""


def config_file():
    return os.environ.get('SENTINEL_TUNING') or os.path.join(ROOT, 'data', 'tuning.json')


def load_config():
    try:
        with open(config_file(), 'r', encoding='utf-8') as f:
            return {**DEFAULTS, **json.load(f)}
    except (OSError, ValueError):
        return dict(DEFAULTS)


def save_config(values, by='cli'):
    cfg = {**load_config(), **{k: v for k, v in (values or {}).items() if k in DEFAULTS}}
    if cfg['mode'] not in MODES:
        raise ValueError(f'mode must be one of {", ".join(MODES)}')
    if cfg['min_action'] not in ORDER[:-1]:
        raise ValueError(f'min_action must be one of {", ".join(ORDER[:-1])}')
    if not 0.5 <= float(cfg['target']) <= 0.99:
        raise ValueError('target must be between 0.5 and 0.99')
    if not 300 <= int(cfg['window_seconds']) <= 86400:
        raise ValueError('window_seconds must be between 300 and 86400')
    cfg['target'], cfg['window_seconds'] = float(cfg['target']), int(cfg['window_seconds'])
    path = config_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path + '.tmp', 'w', encoding='utf-8') as f:
        json.dump({**cfg, 'updated': int(time.time()), 'by': by}, f, indent=2)
    os.replace(path + '.tmp', path)
    import core.audit as audit
    audit.record('response_tuning', actor=by, details={k: cfg[k] for k in DEFAULTS})
    return cfg


class Tuner:
    """Lives inside the playbook's database (its detections table defines "the incident recurred")."""

    def __init__(self, db, lock, clock=time.time, rng=None, false_positives=None):
        self._db, self._lock, self.clock = db, lock, clock
        self.rng = rng or random.Random()  # nosec B311 - exploration, not security
        self._false_positives = false_positives
        with self._lock:
            self._db().executescript(SCHEMA)

    # ---------- outcomes ----------

    def record(self, ip, kind, action, ceiling, ts=None):
        with self._lock:
            db = self._db()
            db.execute('INSERT INTO tuning_events(ip, kind, action, ceiling, ts) VALUES (?,?,?,?,?)',
                       (ip, kind, action, ceiling, ts or self.clock()))
            db.commit()

    def settle(self, window, now=None):
        """Decide every event whose window has passed: resolved unless the source was detected again."""
        now = now or self.clock()
        with self._lock:
            db = self._db()
            due = db.execute('SELECT id, ip, ts FROM tuning_events WHERE outcome IS NULL AND ts <= ?',
                             (now - window,)).fetchall()
            for eid, ip, ts in due:
                again = db.execute('SELECT 1 FROM detections WHERE ip = ? AND ts > ? AND ts <= ? LIMIT 1',
                                   (ip, ts + 1, ts + window)).fetchone()
                db.execute('UPDATE tuning_events SET outcome = ?, settled = ? WHERE id = ?', (0 if again else 1, now, eid))
            db.commit()
        return len(due)

    def _ongoing(self, ip, window, now):
        """The latest unsettled response to this source within the window: it did not resolve the incident."""
        with self._lock:
            db = self._db()
            row = db.execute('SELECT id, action FROM tuning_events WHERE ip = ? AND outcome IS NULL AND ts > ? '
                             'ORDER BY ts DESC LIMIT 1', (ip, now - window)).fetchone()
            if row:
                db.execute('UPDATE tuning_events SET outcome = 0, settled = ? WHERE id = ?', (now, row[0]))
                db.commit()
        return row[1] if row else None

    def stats(self):
        """{kind: {action: [resolved, not resolved]}}, with analyst false positives as resolved alerts."""
        out = {}
        with self._lock:
            rows = self._db().execute('SELECT kind, action, outcome, COUNT(*) FROM tuning_events '
                                      'WHERE outcome IS NOT NULL GROUP BY kind, action, outcome').fetchall()
        for kind, action, outcome, n in rows:
            out.setdefault(kind, {}).setdefault(action, [0, 0])[0 if outcome else 1] += n
        for src, kind in (self._false_positives() if self._false_positives else ()):
            out.setdefault(kind, {}).setdefault('alert', [0, 0])[0] += 1
        return out

    # ---------- choosing ----------

    @staticmethod
    def _lower_bound(s, f, prior):
        a, b = prior[0] + s, prior[1] + f
        mean = a / (a + b)
        sd = math.sqrt(a * b / ((a + b) ** 2 * (a + b + 1)))
        return mean - 1.28 * sd                           # ~10th percentile: what "recommend" relies on

    def choose(self, ip, kind, ceiling, cfg, profile_learned=False, explore=True, now=None):
        """The action to take (never stronger than `ceiling`), and why."""
        now = now or self.clock()
        if ceiling not in ORDER:
            return ceiling, 'not tunable'
        self.settle(cfg['window_seconds'], now)
        top = ORDER.index(ceiling)
        floor = min(ORDER.index(cfg['min_action']), top)
        failed = self._ongoing(ip, cfg['window_seconds'], now)
        if failed in ORDER:
            floor = max(floor, min(ORDER.index(failed) + 1, top))
        stats = self.stats().get(kind, {})
        for i in range(floor, top + 1):
            action = ORDER[i]
            if action == 'contain' and not profile_learned:
                continue
            if i == top:
                return action, 'the playbook\'s choice'
            s, f = stats.get(action, [0, 0])
            p = (self.rng.betavariate(GENTLER_PRIOR[0] + s, GENTLER_PRIOR[1] + f) if explore
                 else self._lower_bound(s, f, GENTLER_PRIOR))
            if p >= cfg['target']:
                return action, f'{action} resolved {s} of {s + f} {kind} incidents'
        return ceiling, 'the playbook\'s choice'

    def summary(self, cfg):
        """Per kind: evidence per action and what the tuner would recommend under a 'block' ceiling."""
        out = []
        for kind, actions in sorted(self.stats().items()):
            rec = 'block'
            for action in ORDER[ORDER.index(cfg['min_action']):ORDER.index('block')]:
                s, f = actions.get(action, [0, 0])
                if self._lower_bound(s, f, GENTLER_PRIOR) >= cfg['target']:
                    rec = action
                    break
            out.append({'kind': kind, 'evidence': {a: {'resolved': v[0], 'not_resolved': v[1]} for a, v in actions.items()},
                        'recommended_instead_of_block': rec})
        return out
