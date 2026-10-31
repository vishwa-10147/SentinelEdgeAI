"""Event bus for the console's live stream (replaces per-connection file and table polling).

One task in the API process reads new alerts and live events by row id (a
real cursor, so nothing is skipped or repeated even when several arrive in
the same second) and new flows from the live statistics, numbers every event
and keeps the last RING of them. Each WebSocket subscribes with the cursor it
last saw and receives exactly what it missed, then everything new. If the
cursor is older than the ring or from an earlier API process (the epoch
changed), the client is told to resync over REST. Heartbeats carry the
current cursor so clients can tell a quiet stream from a dead one.
"""
import asyncio
import collections
import hashlib
import json
import logging
import os
import secrets
import time

logger = logging.getLogger('sentinel.events')

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
RING = 2000
POLL_SECONDS = 0.5
HEARTBEAT_SECONDS = 15
SUBSCRIBER_QUEUE = 1000


class EventBus:
    """`file_fallback`: also read live_stats.json and tail live_events.jsonl (ENABLE_FILE_FALLBACK, the
    engine's file outputs) when the database has no live statistics or events."""

    def __init__(self, storage_factory=None, ring=RING, poll=POLL_SECONDS, sanitize=None, file_fallback=None, root=ROOT):
        self.epoch = secrets.token_hex(4)
        self.seq = 0
        self.ring = collections.deque(maxlen=ring)
        self.subscribers = set()
        self.poll = poll
        self.sanitize = sanitize or (lambda x: x)
        self._storage_factory = storage_factory
        self._alert_id = None
        self._event_id = None
        self._stats = None
        self._flows_seen = collections.OrderedDict()
        self._task = None
        self.file_fallback = (os.environ.get('ENABLE_FILE_FALLBACK', '1') == '1') if file_fallback is None else file_fallback
        self.root = root
        self._events_pos = None

    # ---------- publishing ----------

    def publish(self, kind, payload):
        self.seq += 1
        event = {'type': kind, 'seq': self.seq, 'epoch': self.epoch, 'payload': payload}
        self.ring.append(event)
        for q in list(self.subscribers):
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                # a stalled client: drop it rather than slow everyone down; its loop sends a resync
                q.dropped = True
                self.subscribers.discard(q)
        return event

    # ---------- subscribing ----------

    def subscribe(self, epoch=None, cursor=None):
        """(queue, backlog). backlog is the missed events, or a single 'resync' event."""
        q = asyncio.Queue(maxsize=SUBSCRIBER_QUEUE)
        self.subscribers.add(q)
        if cursor is None:
            return q, []
        oldest = self.ring[0]['seq'] if self.ring else self.seq + 1
        if epoch != self.epoch or int(cursor) < oldest - 1 or int(cursor) > self.seq:
            return q, [{'type': 'resync', 'seq': self.seq, 'epoch': self.epoch,
                        'payload': {'reason': 'restarted' if epoch != self.epoch else 'too far behind'}}]
        return q, [e for e in self.ring if e['seq'] > int(cursor)]

    def unsubscribe(self, q):
        self.subscribers.discard(q)

    def heartbeat(self):
        return {'type': 'heartbeat', 'seq': self.seq, 'epoch': self.epoch, 'payload': {'ts': int(time.time())}}

    # ---------- reading the engine's output ----------

    def _storage(self):
        if self._storage_factory:
            return self._storage_factory()
        from core.storage import get_storage
        s = get_storage('data/sentinel.db')
        s.connect()
        return s

    def _flow_key(self, flow):
        return hashlib.sha1(json.dumps(flow, sort_keys=True, default=str).encode(), usedforsecurity=False).hexdigest()

    def poll_once(self):
        """Read everything new from storage and publish it; returns the number of events published."""
        s = self._storage()
        if self._alert_id is None:
            self._alert_id, self._event_id = s.last_ids()   # start at "now", not at the beginning of history
        n = 0
        for row in s.alerts_after(self._alert_id, 200):
            self._alert_id = row.pop('id')
            self.publish('alert', self.sanitize(row))
            n += 1
        for rid, payload in s.live_events_after(self._event_id, 200):
            self._event_id = rid
            try:
                obj = json.loads(payload)
            except (TypeError, ValueError):
                obj = payload
            self.publish(obj.get('type', 'event') if isinstance(obj, dict) else 'event', self.sanitize(obj))
            n += 1
        n += self._tail_events_file() if self.file_fallback else 0
        stats = s.get_live_stats()
        if not stats and self.file_fallback:
            try:
                with open(os.path.join(self.root, 'live_stats.json'), 'r', encoding='utf-8') as f:
                    stats = f.read()
            except OSError:
                stats = None
        text = stats if isinstance(stats, str) or stats is None else json.dumps(stats, sort_keys=True)
        if text and text != self._stats:
            self._stats = text
            try:
                data = json.loads(text)
            except ValueError:
                data = {}
            for flow in (data.get('flows') or [])[-50:] if isinstance(data, dict) else []:
                key = self._flow_key(flow)
                if key in self._flows_seen:
                    continue
                self._flows_seen[key] = True
                while len(self._flows_seen) > 5000:
                    self._flows_seen.popitem(last=False)
                self.publish('flow', self.sanitize(flow))
                n += 1
        return n

    def _tail_events_file(self):
        """New lines of live_events.jsonl since the last poll (starts at its end; survives truncation)."""
        path = os.path.join(self.root, 'live_events.jsonl')
        try:
            size = os.path.getsize(path)
        except OSError:
            return 0
        if self._events_pos is None or size < self._events_pos:
            self._events_pos = size if self._events_pos is None else 0
            if self._events_pos == size:
                return 0
        n = 0
        with open(path, 'r', encoding='utf-8') as f:
            f.seek(self._events_pos)
            for line in f:
                if not line.endswith('\n'):
                    break                                 # a line still being written
                self._events_pos += len(line.encode('utf-8'))
                try:
                    obj = json.loads(line)
                except ValueError:
                    continue
                self.publish(obj.get('type', 'event') if isinstance(obj, dict) else 'event', self.sanitize(obj))
                n += 1
        return n

    async def run(self):
        while True:
            try:
                await asyncio.to_thread(self.poll_once)
            except Exception:
                logger.debug('event bus poll failed', exc_info=True)
            await asyncio.sleep(self.poll)

    def start(self):
        if self._task is None:
            self._task = asyncio.get_event_loop().create_task(self.run())
        return self._task

    async def stop(self):
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
            self._task = None
