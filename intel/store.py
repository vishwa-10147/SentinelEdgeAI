"""Threat-intelligence indicators: import, store, update and match.

    python -m intel import feed.json --source abuse-ch --format stix
    python -m intel import blocklist.txt --source my-list
    python -m intel add-feed spamhaus-drop https://www.spamhaus.org/drop/drop.txt --format plain
    python -m intel update              # fetch every configured feed (sentineledgeai-intel.timer, daily)
    python -m intel list | check 203.0.113.9

Indicator types: ip, cidr, domain, url, ja3, ja4. STIX 2.1 indicators with
patterns on ipv4-addr, ipv6-addr, domain-name and url are understood, plus
the custom x-ja3 / x-ja4 objects; valid_until becomes the expiry.
"""
import argparse
import ipaddress
import json
import os
import re
import sqlite3
import sys
import threading
import time

import requests

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TYPES = ('ip', 'cidr', 'domain', 'url', 'ja3', 'ja4')
_PATTERN = re.compile(r"\[\s*(ipv4-addr|ipv6-addr|domain-name|url|x-ja3|x-ja4):value\s*=\s*'([^']+)'\s*\]")
_STIX_TYPE = {'ipv4-addr': 'ip', 'ipv6-addr': 'ip', 'domain-name': 'domain', 'url': 'url', 'x-ja3': 'ja3', 'x-ja4': 'ja4'}
_DOMAIN = re.compile(r'^(?=.{1,253}$)([a-z0-9-]{1,63}\.)+[a-z]{2,63}$')
_JA4 = re.compile(r'^[tq]\d{2}[di]\d{4}[0-9a-z]{2}_[0-9a-f]{12}_[0-9a-f]{12}$')


def default_path():
    return os.environ.get('SENTINEL_INTEL_DB') or os.path.join(ROOT, 'data', 'intel.db')


def classify(value):
    """(type, normalised value) for a plain indicator, or None."""
    v = value.strip().lower().strip('.')
    if not v:
        return None
    try:
        if '/' in v:
            net = ipaddress.ip_network(v, strict=False)
            return ('ip', str(net.network_address)) if net.num_addresses == 1 else ('cidr', str(net))
        return 'ip', str(ipaddress.ip_address(v))
    except ValueError:
        pass
    if re.fullmatch(r'[0-9a-f]{32}', v):
        return 'ja3', v
    if _JA4.match(v):
        return 'ja4', v
    if v.startswith(('http://', 'https://')):
        return 'url', v
    if _DOMAIN.match(v):
        return 'domain', v
    return None


def parse_plain(text):
    """One indicator per line; '#' or ';' comments; CSV/space-separated rows use the first field."""
    out = []
    for line in text.splitlines():
        line = re.split(r'[#;]', line, maxsplit=1)[0].strip()
        if not line:
            continue
        field = re.split(r'[\s,]', line, maxsplit=1)[0]
        hit = classify(field)
        if hit:
            out.append({'type': hit[0], 'value': hit[1], 'label': None, 'expires': None})
    return out


def _iso_to_epoch(value):
    if not value:
        return None
    try:
        from datetime import datetime
        return int(datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp())
    except ValueError:
        return None


def parse_stix(obj):
    """Indicators from a STIX 2.1 bundle (or a TAXII envelope with 'objects')."""
    if isinstance(obj, (str, bytes)):
        obj = json.loads(obj)
    out = []
    for o in obj.get('objects', []):
        if o.get('type') == 'indicator' and o.get('pattern_type', 'stix') == 'stix':
            if o.get('revoked'):
                continue
            label = o.get('name') or ', '.join(o.get('indicator_types', [])) or None
            for stype, value in _PATTERN.findall(o.get('pattern', '')):
                hit = classify(value) if _STIX_TYPE[stype] in ('ip', 'domain') else (_STIX_TYPE[stype], value.lower())
                if hit:
                    out.append({'type': hit[0], 'value': hit[1], 'label': label,
                                'expires': _iso_to_epoch(o.get('valid_until'))})
        elif o.get('type') in _STIX_TYPE and o.get('value'):
            hit = classify(o['value']) if o['type'] in ('ipv4-addr', 'ipv6-addr', 'domain-name') \
                else (_STIX_TYPE[o['type']], o['value'].lower())
            if hit:
                out.append({'type': hit[0], 'value': hit[1], 'label': None, 'expires': None})
    return out


class IntelStore:
    def __init__(self, path=None):
        self.path = path or default_path()
        self._lock = threading.Lock()
        self._conn = None
        self._cache = None
        self._cache_at = 0.0

    def _db(self):
        if self._conn is None:
            os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
            conn = sqlite3.connect(self.path, check_same_thread=False, timeout=10)
            conn.row_factory = sqlite3.Row
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS indicators (
                    type TEXT NOT NULL, value TEXT NOT NULL, source TEXT NOT NULL, label TEXT,
                    added INTEGER NOT NULL, expires INTEGER, PRIMARY KEY (type, value, source));
                CREATE TABLE IF NOT EXISTS feeds (
                    name TEXT PRIMARY KEY, url TEXT NOT NULL, format TEXT NOT NULL,
                    last_update INTEGER, last_count INTEGER, last_error TEXT);
            """)
            conn.commit()
            self._conn = conn
        return self._conn

    def close(self):
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None

    def replace_source(self, source, indicators):
        """Atomically replace everything from `source` (a feed update drops withdrawn entries)."""
        now = int(time.time())
        rows = {(i['type'], i['value']): i for i in indicators if i['type'] in TYPES}
        with self._lock:
            db = self._db()
            db.execute('BEGIN')
            db.execute('DELETE FROM indicators WHERE source = ?', (source,))
            db.executemany('INSERT INTO indicators(type, value, source, label, added, expires) VALUES (?,?,?,?,?,?)',
                           [(t, v, source, i.get('label'), now, i.get('expires')) for (t, v), i in rows.items()])
            db.commit()
        self._cache = None
        return len(rows)

    def counts(self):
        with self._lock:
            rows = self._db().execute('SELECT source, type, COUNT(*) AS n FROM indicators GROUP BY source, type').fetchall()
        out = {}
        for r in rows:
            out.setdefault(r['source'], {})[r['type']] = r['n']
        return out

    def add_feed(self, name, url, fmt):
        if fmt not in ('plain', 'stix', 'taxii'):
            raise ValueError('format must be plain, stix or taxii')
        if not url.startswith('https://') and not url.startswith('file://'):
            raise ValueError('feed URL must use https:// (or file:// for a local mirror)')
        with self._lock:
            self._db().execute('INSERT OR REPLACE INTO feeds(name, url, format) VALUES (?, ?, ?)', (name, url, fmt))
            self._db().commit()

    def feeds(self):
        with self._lock:
            return [dict(r) for r in self._db().execute('SELECT * FROM feeds ORDER BY name').fetchall()]

    def update_feeds(self, fetch=None):
        """Fetch every feed; a failing feed keeps its previous indicators."""
        results = {}
        for feed in self.feeds():
            try:
                text = (fetch or _fetch)(feed['url'], feed['format'])
                indicators = parse_plain(text) if feed['format'] == 'plain' else parse_stix(text)
                n = self.replace_source(feed['name'], indicators)
                err = None
            except Exception as exc:
                n, err = None, str(exc)[:300]
            with self._lock:
                self._db().execute('UPDATE feeds SET last_update = ?, last_count = COALESCE(?, last_count), '
                                   'last_error = ? WHERE name = ?', (int(time.time()), n, err, feed['name']))
                self._db().commit()
            results[feed['name']] = n if err is None else f'error: {err}'
        return results

    # ---------- matching ----------

    def _snapshot(self):
        now = time.time()
        if self._cache is not None and now - self._cache_at < 30:
            return self._cache
        with self._lock:
            rows = self._db().execute('SELECT type, value, source, label FROM indicators '
                                      'WHERE expires IS NULL OR expires > ?', (int(now),)).fetchall()
        exact, nets = {}, []
        for r in rows:
            meta = (r['source'], r['label'])
            if r['type'] == 'cidr':
                nets.append((ipaddress.ip_network(r['value']), meta))
            else:
                exact[(r['type'], r['value'])] = meta
        self._cache, self._cache_at = (exact, nets), now
        return self._cache

    def match_ip(self, ip):
        exact, nets = self._snapshot()
        hit = exact.get(('ip', str(ip)))
        if hit:
            return hit
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        for net, meta in nets:
            if addr.version == net.version and addr in net:
                return meta
        return None

    def match_domain(self, name):
        exact, _ = self._snapshot()
        labels = name.lower().rstrip('.').split('.')
        for i in range(len(labels) - 1):
            hit = exact.get(('domain', '.'.join(labels[i:])))
            if hit:
                return hit
        return None

    def match_fingerprint(self, fp):
        exact, _ = self._snapshot()
        return exact.get(('ja3', fp.lower())) or exact.get(('ja4', fp.lower()))


def _fetch(url, fmt):
    if url.startswith('file://'):
        with open(url[7:], 'r', encoding='utf-8') as f:
            return f.read()
    headers = {'Accept': 'application/taxii+json;version=2.1'} if fmt == 'taxii' else {}
    r = requests.get(url, headers=headers, timeout=30)
    r.raise_for_status()
    return r.text


_store = None


def get_store():
    global _store
    if _store is None or _store.path != default_path():
        _store = IntelStore()
    return _store


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m intel')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('import')
    p.add_argument('file')
    p.add_argument('--source', required=True)
    p.add_argument('--format', choices=['plain', 'stix'], default=None)
    p = sub.add_parser('add-feed')
    p.add_argument('name')
    p.add_argument('url')
    p.add_argument('--format', choices=['plain', 'stix', 'taxii'], default='plain')
    sub.add_parser('update')
    sub.add_parser('list')
    p = sub.add_parser('check')
    p.add_argument('value')
    args = parser.parse_args(argv)
    store = get_store()
    try:
        if args.command == 'import':
            with open(args.file, 'r', encoding='utf-8') as f:
                text = f.read()
            fmt = args.format or ('stix' if text.lstrip().startswith('{') else 'plain')
            n = store.replace_source(args.source, parse_plain(text) if fmt == 'plain' else parse_stix(text))
            print(f'imported {n} indicators as {args.source}')
        elif args.command == 'add-feed':
            store.add_feed(args.name, args.url, args.format)
            print(f'added feed {args.name}; fetch it with: python -m intel update')
        elif args.command == 'update':
            print(json.dumps(store.update_feeds(), indent=2))
        elif args.command == 'list':
            print(json.dumps({'indicators': store.counts(), 'feeds': store.feeds()}, indent=2))
        elif args.command == 'check':
            hit = store.match_ip(args.value) or store.match_domain(args.value) or store.match_fingerprint(args.value)
            print(json.dumps({'value': args.value, 'match': hit}))
            return 0 if hit else 1
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0
