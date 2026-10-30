"""Hash-chained audit log of sign-ins, account changes and response actions.

Every entry stores the SHA-256 of the previous entry, so editing, deleting or
reordering any entry breaks the chain and `verify()` reports the first bad
sequence number. Entries are also written to the 'sentinel.audit' logger
(journald on a device) with their hash, an independent copy that lets a
rewritten chain be detected too.

    python -m core.audit verify
    python -m core.audit tail -n 20
"""
import argparse
import hashlib
import json
import logging
import os
import sqlite3
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
GENESIS = '0' * 64
MAX_FIELD = 256

logger = logging.getLogger('sentinel.audit')


def default_db_path():
    return os.environ.get('SENTINEL_AUDIT_DB') or os.path.join(ROOT, 'data', 'audit.db')


def _clip(value, limit=MAX_FIELD):
    if value is None:
        return None
    return str(value)[:limit]


def entry_hash(entry):
    """SHA-256 over the entry's fields and the previous hash, in a fixed order."""
    fields = [entry['seq'], entry['ts'], entry['actor'], entry['actor_kind'], entry['role'],
              entry['client_ip'], entry['action'], entry['target'], entry['outcome'],
              entry['details'], entry['prev_hash']]
    data = json.dumps(fields, separators=(',', ':'), ensure_ascii=True)
    return hashlib.sha256(data.encode('ascii')).hexdigest()


class AuditLog:
    def __init__(self, path=None):
        self.path = path or default_db_path()
        self._lock = threading.Lock()
        self._conn = None

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            fresh = not os.path.exists(self.path)
            # autocommit mode: transactions are opened explicitly below
            conn = sqlite3.connect(self.path, check_same_thread=False, isolation_level=None, timeout=10)
            conn.row_factory = sqlite3.Row
            if fresh and os.name == 'posix':
                os.chmod(self.path, 0o600)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_log (
                    seq INTEGER PRIMARY KEY,
                    ts INTEGER NOT NULL,
                    actor TEXT NOT NULL,
                    actor_kind TEXT,
                    role TEXT,
                    client_ip TEXT,
                    action TEXT NOT NULL,
                    target TEXT,
                    outcome TEXT NOT NULL,
                    details TEXT,
                    prev_hash TEXT NOT NULL,
                    hash TEXT NOT NULL
                )
                """
            )
            conn.execute('CREATE INDEX IF NOT EXISTS audit_action ON audit_log(action)')
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def record(self, action, actor='system', actor_kind=None, role=None, client_ip=None,
               target=None, outcome='success', details=None):
        """Append one entry and return it. Safe across threads and processes."""
        entry = {
            'ts': int(time.time()),
            'actor': _clip(actor) or 'unknown',
            'actor_kind': _clip(actor_kind, 32),
            'role': _clip(role, 32),
            'client_ip': _clip(client_ip, 64),
            'action': _clip(action, 64),
            'target': _clip(target),
            'outcome': _clip(outcome, 32),
            'details': json.dumps(details, sort_keys=True, default=str)[:2048] if details else None,
        }
        with self._lock:
            db = self._db()
            # IMMEDIATE takes the write lock first, so two processes cannot
            # both chain onto the same previous entry
            db.execute('BEGIN IMMEDIATE')
            try:
                last = db.execute('SELECT seq, hash FROM audit_log ORDER BY seq DESC LIMIT 1').fetchone()
                entry['seq'] = (last['seq'] + 1) if last else 1
                entry['prev_hash'] = last['hash'] if last else GENESIS
                entry['hash'] = entry_hash(entry)
                db.execute(
                    'INSERT INTO audit_log(seq, ts, actor, actor_kind, role, client_ip, action, target, '
                    'outcome, details, prev_hash, hash) VALUES (:seq, :ts, :actor, :actor_kind, :role, '
                    ':client_ip, :action, :target, :outcome, :details, :prev_hash, :hash)',
                    entry,
                )
                db.execute('COMMIT')
            except Exception:
                db.execute('ROLLBACK')
                raise
        logger.info('audit %s', json.dumps(entry, sort_keys=True))
        return entry

    def entries(self, limit=100, before=None, action=None, actor=None):
        """Newest first. `before` pages backwards by sequence number."""
        clauses, params = [], []
        if before:
            clauses.append('seq < ?')
            params.append(int(before))
        if action:
            clauses.append('action = ?')
            params.append(str(action))
        if actor:
            clauses.append('actor = ?')
            params.append(str(actor))
        where = ('WHERE ' + ' AND '.join(clauses)) if clauses else ''
        params.append(max(1, min(int(limit), 1000)))
        with self._lock:
            rows = self._db().execute(
                f'SELECT * FROM audit_log {where} ORDER BY seq DESC LIMIT ?', params  # nosec B608 - fixed clauses; values are bound
            ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item['details'] = json.loads(item['details']) if item['details'] else None
            out.append(item)
        return out

    def verify(self):
        """Walk the whole chain. Returns {'ok', 'entries', 'head', 'first_bad_seq', 'reason'}."""
        with self._lock:
            rows = self._db().execute('SELECT * FROM audit_log ORDER BY seq').fetchall()
        prev, expected_seq = GENESIS, 1
        for row in rows:
            entry = dict(row)
            if entry['seq'] != expected_seq:
                return self._bad(len(rows), prev, expected_seq, 'entries missing before this sequence number')
            if entry['prev_hash'] != prev:
                return self._bad(len(rows), prev, entry['seq'], 'link to the previous entry is broken')
            if entry_hash(entry) != entry['hash']:
                return self._bad(len(rows), prev, entry['seq'], 'entry was modified')
            prev, expected_seq = entry['hash'], expected_seq + 1
        return {'ok': True, 'entries': len(rows), 'head': prev, 'first_bad_seq': None, 'reason': None}

    @staticmethod
    def _bad(count, head, seq, reason):
        return {'ok': False, 'entries': count, 'head': head, 'first_bad_seq': seq, 'reason': reason}


_default_log = None
_default_lock = threading.Lock()


def get_log():
    global _default_log
    with _default_lock:
        if _default_log is None or _default_log.path != default_db_path():
            _default_log = AuditLog()
        return _default_log


def record(action, **kwargs):
    """Record an entry; never raises, so an audit failure cannot block a response action."""
    try:
        return get_log().record(action, **kwargs)
    except Exception:
        logger.exception('audit record failed for %s', action)
        return None


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m core.audit', description='Inspect the SentinelEdgeAI audit log.')
    parser.add_argument('--db', help='audit database (default: $SENTINEL_AUDIT_DB or data/audit.db)')
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('verify', help='check the hash chain')
    p = sub.add_parser('tail', help='show the newest entries')
    p.add_argument('-n', type=int, default=20)
    args = parser.parse_args(argv)

    log = AuditLog(args.db) if args.db else AuditLog()
    try:
        if args.command == 'verify':
            result = log.verify()
            if result['ok']:
                print(f"audit log intact: {result['entries']} entries, head {result['head']}")
                return 0
            print(f"audit log BROKEN at entry {result['first_bad_seq']}: {result['reason']}", file=sys.stderr)
            return 1
        for e in reversed(log.entries(limit=args.n)):
            when = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(e['ts']))
            print(f"{e['seq']:>6} {when} {e['actor']:<20} {e['action']:<24} {e['target'] or '-':<20} {e['outcome']}")
        return 0
    finally:
        log.close()


if __name__ == '__main__':
    sys.exit(main())
