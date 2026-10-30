"""Sensor side of the link to the brain.

    python -m sensor enroll --brain https://brain:9443 --code K7QF-2M9P-XW4D --ca-fingerprint <sha256>
    python -m sensor run

Enrolment pins the brain's CA by the fingerprint shown next to the code, so
a machine in the middle cannot enrol the sensor to itself. After that every
request uses mutual TLS with the sensor's own certificate.

While the brain is unreachable the sensor is in degraded mode: the local
engine keeps detecting, flows pile up in the disk buffer, and nothing is
lost; the buffer is replayed oldest-first when the brain is back. The
sensor never auto-blocks on its own because the brain is down.
"""
import json
import logging
import os
import socket
import threading
import time
import warnings

import requests
import urllib3

from common import pki
from sensor.buffer import DiskBuffer
from sensor.enforcer import Enforcer

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
logger = logging.getLogger('sentinel.sensor')
BATCH = 500


def sensor_dir():
    return os.environ.get('SENTINEL_SENSOR_DIR') or os.path.join(ROOT, 'data', 'sensor')


def _path(name):
    return os.path.join(sensor_dir(), name)


def _write(name, text, private=False):
    fd = os.open(_path(name), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(text)


def load_identity():
    """The enrolment record, or None if this device is not an enrolled sensor."""
    try:
        with open(_path('sensor.json'), 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


class EnrolmentError(RuntimeError):
    pass


def enroll(brain_url, code, ca_fingerprint, name=None, timeout=10):
    """Enrol with the brain; stores key, certificate, CA and the brain's command key."""
    brain_url = brain_url.rstrip('/')
    os.makedirs(sensor_dir(), mode=0o700, exist_ok=True)
    # 1. fetch the CA without trusting it, then pin it by fingerprint
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
            ca = requests.get(f'{brain_url}/v1/ca', verify=False, timeout=timeout).json()['ca']  # nosec B501 - pinned below
    except (requests.RequestException, ValueError, KeyError) as exc:
        raise EnrolmentError(f'could not reach the brain: {exc}')
    if pki.fingerprint(ca) != ca_fingerprint.replace(':', '').lower():
        raise EnrolmentError('the brain CA fingerprint does not match; refusing to enrol')
    _write('ca.pem', ca)
    # 2. key stays here; only the certificate request goes to the brain
    key, csr = pki.make_csr(name or socket.gethostname())
    try:
        r = requests.post(f'{brain_url}/v1/enroll', json={'code': code, 'csr': csr, 'name': name or socket.gethostname()},
                          verify=_path('ca.pem'), timeout=timeout)
    except requests.RequestException as exc:
        raise EnrolmentError(f'enrolment request failed: {exc}')
    if r.status_code != 200:
        raise EnrolmentError(f"brain refused enrolment: {r.json().get('detail', r.text)}")
    body = r.json()
    _write('sensor.key', key, private=True)
    _write('sensor.pem', body['certificate'])
    _write('brain.pub', body['signing_public_key'])
    _write('sensor.json', json.dumps({'sensor_id': body['sensor_id'], 'brain_url': brain_url,
                                      'enrolled': int(time.time())}, indent=2))
    return body['sensor_id']


class Uplink:
    def __init__(self, identity=None, buffer=None, enforcer=None, timeout=5):
        self.identity = identity or load_identity()
        if not self.identity:
            raise EnrolmentError('this device is not enrolled; run: python -m sensor enroll ...')
        self.url = self.identity['brain_url']
        self.buffer = buffer or DiskBuffer()
        self.enforcer = enforcer or Enforcer(self.identity['sensor_id'], open(_path('brain.pub')).read(),
                                             _path('enforcer_state.json'))
        self.session = requests.Session()
        self.session.cert = (_path('sensor.pem'), _path('sensor.key'))
        self.session.verify = _path('ca.pem')
        self.timeout = timeout
        self.connected = False
        self.last_error = None
        self.sent = 0
        self._stop = threading.Event()

    def _post(self, path, payload):
        r = self.session.post(f'{self.url}{path}', json=payload, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def _set_connected(self, ok, error=None):
        if ok != self.connected:
            if ok:
                logger.warning('brain reachable again; replaying %d buffered flows', len(self.buffer))
            else:
                logger.warning('brain unreachable (%s); degraded mode, buffering flows locally', error)
        self.connected, self.last_error = ok, error

    def flush_once(self):
        """Send one batch from the buffer. Returns the number acknowledged (0 if empty or offline)."""
        batch = self.buffer.peek(BATCH)
        if not batch:
            return 0
        try:
            body = self._post('/v1/flows', {'records': [[rid, rec] for rid, rec in batch]})
        except requests.RequestException as exc:
            self._set_connected(False, str(exc)[:200])
            return 0
        self._set_connected(True)
        acked = body.get('acked') or []
        self.buffer.ack(acked)
        self.sent += len(acked)
        return len(acked)

    def poll_commands(self):
        try:
            r = self.session.get(f'{self.url}/v1/commands', params={'after': self.enforcer.last_seq()},
                                 timeout=self.timeout)
            r.raise_for_status()
        except requests.RequestException as exc:
            self._set_connected(False, str(exc)[:200])
            return []
        self._set_connected(True)
        results = []
        for envelope in r.json().get('commands', []):
            result = self.enforcer.apply(envelope)
            results.append(result)
            if result.get('seq') is not None:
                try:
                    self._post('/v1/commands/result', {'seq': int(result['seq']), 'status': result['status'],
                                                       'detail': result.get('detail')})
                except (requests.RequestException, ValueError, TypeError):
                    pass  # the brain sees it on the next poll; the sequence is already consumed
        return results

    def send_health(self, extra=None):
        health = {'buffered': len(self.buffer), 'dropped': self.buffer.dropped(), 'sent': self.sent,
                  'connected': self.connected, 'time': time.time(), **(extra or {})}
        try:
            self._post('/v1/health', health)
        except requests.RequestException as exc:
            self._set_connected(False, str(exc)[:200])

    def run(self, health_every=30, idle_sleep=1.0):
        backoff, last_health = 1.0, 0.0
        while not self._stop.is_set():
            sent = self.flush_once()
            self.poll_commands()
            if time.time() - last_health > health_every:
                self.send_health()
                last_health = time.time()
            if not self.connected:
                self._stop.wait(backoff)
                backoff = min(backoff * 2, 30.0)
                continue
            backoff = 1.0
            if sent < BATCH:
                self._stop.wait(idle_sleep)

    def stop(self):
        self._stop.set()
