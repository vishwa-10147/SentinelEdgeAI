"""Brain management actions shared by the CLI and the console API."""
from brain import keys
from brain.store import BrainStore
from common import protocol, signing

_store = None


def store():
    global _store
    if _store is None or _store.path != BrainStore().path:
        _store = BrainStore()
    return _store


class StandbyError(ValueError):
    pass


def issue_command(sensor_id, action, ip=None, ttl=None, reason=''):
    """Sign a command for a sensor and queue it. Returns the envelope. Only the active brain issues commands."""
    s = store()
    from brain import ha
    if ha.role(s) != 'active':
        raise StandbyError('this brain is the standby; issue commands on the active brain')
    sensor = s.get_sensor(sensor_id)
    if not sensor:
        raise KeyError(sensor_id)
    if sensor['revoked']:
        raise ValueError('sensor is revoked')
    seq = s.next_seq(sensor_id)
    payload = protocol.make_command(sensor_id, seq, action, ip=ip, ttl=ttl, reason=reason)
    envelope = signing.sign(keys.read('signing.key'), payload, keys.read('signing.pub'))
    s.add_command(sensor_id, seq, envelope)
    return envelope


def enrolment_instructions(code, brain_url):
    return {
        'code': code,
        'ca_fingerprint': keys.ca_fingerprint(),
        'command': (f'sudo -u sentinel /opt/sentineledgeai/current/.venv/bin/python -m sensor enroll '
                    f'--brain {brain_url} --code {code} --ca-fingerprint {keys.ca_fingerprint()}'),
    }


def issue_segment_command(segment, action, ip=None, ttl=None, reason='', fresh=120):
    """Send a command to the healthiest sensor of a segment (dual sensors back each other up).

    The sensor heard from most recently within `fresh` seconds gets it; returns (sensor_id, envelope).
    """
    import time
    now = time.time()
    for sensor in store().segment_sensors(segment):
        if sensor['last_seen'] and now - sensor['last_seen'] <= fresh:
            return sensor['id'], issue_command(sensor['id'], action, ip, ttl, reason)
    raise ValueError(f'no sensor of segment {segment!r} was heard from in the last {fresh} seconds')
