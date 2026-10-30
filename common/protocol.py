"""Messages exchanged between sensor and brain (JSON over mutual-TLS HTTPS).

Flow records carry the 5-tuple, counters and the extracted features so the
brain can run its own models. Commands are signed by the brain (see
common.signing) and carry a per-sensor sequence number and an expiry.
"""
import ipaddress
import time

PROTOCOL_VERSION = 1
COMMAND_ACTIONS = ('block', 'unblock', 'rollback')
COMMAND_TTL_SECONDS = 300          # a command not executed within 5 minutes is void
MAX_BATCH = 1000


def flow_record(flow, result=None, features=None):
    """Build the wire record for a finished flow scored by the local engine."""
    result = result or {}
    record = {
        'v': PROTOCOL_VERSION,
        'ts': time.time(),
        'src': flow.initiator_ip,
        'dst': flow.responder_ip,
        'sport': int(flow.initiator_port or 0),
        'dport': int(flow.responder_port or 0),
        'proto': flow.protocol,
        'local_risk': result.get('final_risk'),
        'attack_type': result.get('attack_type'),
    }
    for attr in ('duration', 'forward_bytes', 'backward_bytes', 'forward_packets', 'backward_packets'):
        value = getattr(flow, attr, None)
        if isinstance(value, (int, float)):
            record[attr] = value
    start = getattr(flow, 'start_time', None)
    if hasattr(start, 'timestamp'):
        record['start'] = start.timestamp()
    if features:
        record['features'] = {k: v for k, v in features.items() if isinstance(v, (int, float))}
    return record


def validate_record(record):
    if not isinstance(record, dict):
        raise ValueError('record must be an object')
    for key in ('src', 'dst', 'proto', 'ts'):
        if key not in record:
            raise ValueError(f'record missing {key}')
    ipaddress.ip_address(record['src'])
    ipaddress.ip_address(record['dst'])
    return record


def make_command(sensor_id, seq, action, ip=None, ttl=None, reason='', now=None):
    if action not in COMMAND_ACTIONS:
        raise ValueError(f'action must be one of {COMMAND_ACTIONS}')
    if action in ('block', 'unblock'):
        if not ip:
            raise ValueError(f'{action} needs an ip')
        ip = str(ipaddress.ip_address(ip))
    now = int(now or time.time())
    return {
        'v': PROTOCOL_VERSION,
        'sensor_id': sensor_id,
        'seq': int(seq),
        'action': action,
        'ip': ip,
        'ttl': ttl,
        'reason': str(reason)[:200],
        'issued': now,
        'expires': now + COMMAND_TTL_SECONDS,
    }
