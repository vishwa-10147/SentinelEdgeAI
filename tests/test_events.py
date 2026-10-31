"""Event bus and the live WebSocket: cursors, replay, resync, heartbeats, slow clients."""
import asyncio
import json

import pytest

from core import events
from core.events import EventBus


class FakeStorage:
    def __init__(self):
        self.alerts, self.events, self.stats = [], [], None

    def last_ids(self):
        return (max([a['id'] for a in self.alerts] or [0]), max([e[0] for e in self.events] or [0]))

    def alerts_after(self, after, limit):
        return [dict(a) for a in self.alerts if a['id'] > after][:limit]

    def live_events_after(self, after, limit):
        return [e for e in self.events if e[0] > after][:limit]

    def get_live_stats(self):
        return self.stats


def alert(i, ts=1_800_000_000):
    return {'id': i, 'timestamp': ts, 'src_ip': '192.168.1.5', 'score': 80, 'details': '{}'}


def test_bus_starts_at_now_and_never_drops_alerts_in_the_same_second():
    s = FakeStorage()
    s.alerts = [alert(1), alert(2)]                       # history before the API started: not replayed
    bus = EventBus(storage_factory=lambda: s, file_fallback=False)
    assert bus.poll_once() == 0
    s.alerts += [alert(3), alert(4), alert(5)]            # three alerts within one second
    assert bus.poll_once() == 3
    assert [e['seq'] for e in bus.ring] == [1, 2, 3] and all(e['type'] == 'alert' for e in bus.ring)
    assert 'id' not in bus.ring[0]['payload']
    assert bus.poll_once() == 0                           # nothing twice


def test_live_events_past_the_first_200_still_arrive():
    s = FakeStorage()
    bus = EventBus(storage_factory=lambda: s, file_fallback=False)
    bus.poll_once()
    s.events = [(i, json.dumps({'type': 'firewall_event', 'n': i})) for i in range(1, 451)]
    while bus.poll_once():
        pass
    assert bus.seq == 450 and bus.ring[-1]['payload']['n'] == 450 and bus.ring[-1]['type'] == 'firewall_event'


def test_flows_from_live_stats_are_published_once():
    s = FakeStorage()
    bus = EventBus(storage_factory=lambda: s, file_fallback=False)
    s.stats = json.dumps({'flows': [{'src': 'a', 'ts': 1}, {'src': 'b', 'ts': 2}]})
    assert bus.poll_once() == 2
    s.stats = json.dumps({'flows': [{'src': 'a', 'ts': 1}, {'src': 'b', 'ts': 2}, {'src': 'c', 'ts': 3}]})
    assert bus.poll_once() == 1 and bus.ring[-1]['payload']['src'] == 'c'


def test_file_fallback_reads_live_stats_and_tails_live_events(tmp_path):
    s = FakeStorage()
    bus = EventBus(storage_factory=lambda: s, file_fallback=True, root=str(tmp_path))
    events_file = tmp_path / 'live_events.jsonl'
    events_file.write_text(json.dumps({'type': 'old'}) + '\n')          # history: not replayed
    (tmp_path / 'live_stats.json').write_text(json.dumps({'flows': [{'src': 'x', 'ts': 1}]}))
    assert bus.poll_once() == 1 and bus.ring[-1]['type'] == 'flow'
    with open(events_file, 'a') as f:
        f.write(json.dumps({'type': 'firewall_event', 'ip': '1.2.3.4'}) + '\n' + '{"type": "partial')
    assert bus.poll_once() == 1 and bus.ring[-1]['payload']['ip'] == '1.2.3.4'
    with open(events_file, 'a') as f:
        f.write('"}\n')                                                 # the partial line completes
    assert bus.poll_once() == 1 and bus.ring[-1]['type'] == 'partial'
    events_file.write_text(json.dumps({'type': 'after_rotation'}) + '\n')
    assert bus.poll_once() == 1 and bus.ring[-1]['type'] == 'after_rotation'


def test_resume_replays_exactly_what_was_missed():
    async def run():
        bus = EventBus(storage_factory=FakeStorage, file_fallback=False)
        for i in range(10):
            bus.publish('alert', {'n': i})
        q, backlog = bus.subscribe(bus.epoch, 7)
        assert [e['payload']['n'] for e in backlog] == [7, 8, 9]
        bus.publish('alert', {'n': 10})
        assert (await q.get())['payload']['n'] == 10
        _, none = bus.subscribe(bus.epoch, bus.seq)           # fully caught up
        assert none == []
    asyncio.run(run())


def test_resync_after_a_restart_or_when_too_far_behind():
    async def run():
        bus = EventBus(storage_factory=FakeStorage, ring=5, file_fallback=False)
        for i in range(20):
            bus.publish('alert', {'n': i})
        assert bus.subscribe('old-epoch', 19)[1][0]['payload']['reason'] == 'restarted'
        assert bus.subscribe(bus.epoch, 3)[1][0]['type'] == 'resync'
        assert bus.subscribe(bus.epoch, 999)[1][0]['type'] == 'resync'   # a cursor from the future
        assert [e['seq'] for e in bus.subscribe(bus.epoch, 15)[1]] == [16, 17, 18, 19, 20]
    asyncio.run(run())


def test_a_stalled_subscriber_is_dropped_not_waited_for(monkeypatch):
    monkeypatch.setattr(events, 'SUBSCRIBER_QUEUE', 3)

    async def run():
        bus = EventBus(storage_factory=FakeStorage, file_fallback=False)
        slow, _ = bus.subscribe()
        for i in range(10):
            bus.publish('alert', {'n': i})
        assert getattr(slow, 'dropped', False) and slow not in bus.subscribers
    asyncio.run(run())


# ---------- the WebSocket ----------

@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from core import auth
    from dashboard import auth_routes
    from dashboard import dashboard_api as api
    monkeypatch.setenv('SENTINEL_AUTH_DB', str(tmp_path / 'auth.db'))
    monkeypatch.setenv('SENTINEL_MFA_ROLES', '')
    monkeypatch.delenv('DASHBOARD_API_KEY', raising=False)
    monkeypatch.setattr(auth_routes, 'login_throttle', auth.LoginThrottle())
    auth.get_store().create_user('vera', 'correct horse battery 9', 'viewer')
    with TestClient(api.app) as c:
        token = c.post('/api/auth/login', json={'username': 'vera', 'password': 'correct horse battery 9'}).json()['access_token']
        yield c, token, api
    auth.get_store().close()


def test_websocket_replays_missed_events_on_resume(client):
    c, token, api = client
    bus = api.app.state.bus
    for i in range(5):
        bus.publish('firewall_event', {'n': i})
    epoch, cursor = bus.epoch, bus.seq - 2
    with c.websocket_connect('/ws/packets') as ws:
        ws.send_json({'type': 'auth', 'token': token, 'epoch': epoch, 'cursor': cursor})
        ok = ws.receive_json()
        assert ok['type'] == 'auth_ok' and ok['epoch'] == epoch
        assert [ws.receive_json()['payload']['n'] for _ in range(2)] == [3, 4]


def test_websocket_says_resync_for_a_stale_epoch(client):
    c, token, _ = client
    with c.websocket_connect('/ws/packets') as ws:
        ws.send_json({'type': 'auth', 'token': token, 'epoch': 'deadbeef', 'cursor': 12})
        assert ws.receive_json()['type'] == 'auth_ok'
        msg = ws.receive_json()
        assert msg['type'] == 'resync' and msg['payload']['reason'] == 'restarted'


def test_websocket_sends_heartbeats(client, monkeypatch):
    c, token, _ = client
    monkeypatch.setattr(events, 'HEARTBEAT_SECONDS', 0.2)
    with c.websocket_connect('/ws/packets') as ws:
        ws.send_json({'type': 'auth', 'token': token})
        assert ws.receive_json()['type'] == 'auth_ok'
        hb = ws.receive_json()
        assert hb['type'] == 'heartbeat' and 'seq' in hb
