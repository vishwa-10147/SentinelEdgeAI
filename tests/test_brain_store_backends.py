"""The brain store behaves the same on SQLite and PostgreSQL (Phase 2).

PostgreSQL runs when SENTINEL_TEST_POSTGRES_URL points at a throwaway database, e.g.
  docker run --rm -d -e POSTGRES_PASSWORD=t -p 127.0.0.1:55432:5432 postgres:16-alpine
  SENTINEL_TEST_POSTGRES_URL=postgresql://postgres:t@127.0.0.1:55432/postgres pytest tests/test_brain_store_backends.py
"""
import os
import time

import pytest

from brain.store import BrainStore

PG = os.environ.get('SENTINEL_TEST_POSTGRES_URL')


@pytest.fixture(params=['sqlite', 'postgres'])
def store(request, tmp_path):
    if request.param == 'sqlite':
        s = BrainStore(str(tmp_path / 'brain.db'))
    else:
        if not PG:
            pytest.skip('set SENTINEL_TEST_POSTGRES_URL to run against PostgreSQL')
        s = BrainStore(url=PG)
        db = s._db()
        for table in ('flows', 'commands', 'enroll_codes', 'sensors'):
            db.execute(f'DELETE FROM {table}')
    yield s
    s.close()


def test_codes_are_single_use(store):
    code = store.create_code()
    assert store.redeem_code(code, 'sensor-a')
    assert not store.redeem_code(code, 'sensor-b')
    assert not store.redeem_code('NOPE-NOPE-NOPE', 'sensor-c')
    expired = store.create_code(ttl=-1)
    assert not store.redeem_code(expired, 'sensor-d')


def test_flows_are_deduplicated_and_counted(store):
    store.add_sensor('sensor-a', 'pi-1', 'fp-a')
    store.add_sensor('sensor-b', 'pi-2', 'fp-b')
    assert store.add_flows('sensor-a', [(1, {'src': '10.0.0.1', 'n': 1}), (2, {'src': '10.0.0.1', 'n': 2})]) == 2
    assert store.add_flows('sensor-a', [(2, {'n': 2}), (3, {'n': 3})]) == 1          # rid 2 re-sent after a lost ack
    assert store.add_flows('sensor-b', [(1, {'n': 1})]) == 1                          # same rid, other sensor
    assert store.flow_count() == 4 and store.flow_count('sensor-a') == 3
    recent = store.recent_flows(limit=2, sensor_id='sensor-a')
    assert [r['n'] for r in recent] == [3, 2] and recent[0]['sensor_id'] == 'sensor-a'
    counts = {s['id']: s['flows'] for s in store.list_sensors()}
    assert counts == {'sensor-a': 3, 'sensor-b': 1}


def test_sensor_health_and_revocation(store):
    store.add_sensor('sensor-a', 'pi-1', 'fp-a')
    store.touch('sensor-a', {'buffered': 5, 'cpu': 12.5})
    s = store.get_sensor('sensor-a')
    assert s['last_seen'] >= int(time.time()) - 5
    assert store.list_sensors()[0]['health'] == {'buffered': 5, 'cpu': 12.5}
    store.revoke_sensor('sensor-a')
    assert store.list_sensors()[0]['revoked'] is True


def test_commands_are_sequenced_per_sensor(store):
    store.add_sensor('sensor-a', 'pi-1', 'fp-a')
    assert store.next_seq('sensor-a') == 1
    store.add_command('sensor-a', 1, {'payload': {'seq': 1}})
    store.add_command('sensor-a', 2, {'payload': {'seq': 2}})
    assert store.next_seq('sensor-a') == 3 and store.next_seq('sensor-b') == 1
    assert [c['payload']['seq'] for c in store.pending_commands('sensor-a', after=1)] == [2]
    store.command_result('sensor-a', 1, 'applied', {'ok': True})
    statuses = {c['seq']: c['status'] for c in store.list_commands('sensor-a')}
    assert statuses[1] == 'applied' and statuses[2] == 'pending'
