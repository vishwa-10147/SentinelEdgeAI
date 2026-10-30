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


def issue_command(sensor_id, action, ip=None, ttl=None, reason=''):
    """Sign a command for a sensor and queue it. Returns the envelope."""
    s = store()
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
