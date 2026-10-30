"""Non-blocking alert fan-out to every configured sink.

The engine calls emit(alert); a worker thread delivers to each sink with
retries, so a slow or unreachable SIEM never delays detection. The sink
list lives in data/integrations.json (mode 600, it holds webhook secrets),
managed through the console API (Admin).
"""
import json
import logging
import os
import queue
import threading
import time

from integrations import sinks

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
logger = logging.getLogger('sentinel.integrations')
SEVERITY_RANK = {'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
SECRET_KEYS = ('secret', 'password', 'webhook_url')


def config_file():
    return os.environ.get('SENTINEL_INTEGRATIONS') or os.path.join(ROOT, 'data', 'integrations.json')


def load_config():
    try:
        with open(config_file(), 'r', encoding='utf-8') as f:
            cfg = json.load(f)
    except (OSError, ValueError):
        cfg = {}
    cfg.setdefault('sinks', [])
    return cfg


def save_config(cfg):
    for s in cfg.get('sinks', []):
        sinks.build(s)                         # validates; raises ValueError
    path = config_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(cfg, f, indent=2)
    os.replace(path + '.tmp', path)
    get_dispatcher().reload()


def redacted(cfg):
    out = json.loads(json.dumps(cfg))
    for s in out.get('sinks', []):
        for k in SECRET_KEYS:
            if s.get(k):
                s[k] = '********'
    return out


class Dispatcher:
    def __init__(self, max_queue=10000, retries=3):
        self.q = queue.Queue(max_queue)
        self.retries = retries
        self.sinks = []
        self.stats = {'queued': 0, 'sent': 0, 'failed': 0, 'dropped': 0, 'last_error': None, 'last_latency_ms': None}
        self._lock = threading.Lock()
        self._thread = None
        self._mtime = None
        self._checked = 0.0
        self.reload()

    def _maybe_reload(self):
        # the console (another process) edits the file; pick changes up within 5 s
        now = time.time()
        if now - self._checked < 5:
            return
        self._checked = now
        try:
            mtime = os.path.getmtime(config_file())
        except OSError:
            mtime = None
        if mtime != self._mtime:
            self.reload()

    def reload(self):
        try:
            self._mtime = os.path.getmtime(config_file())
        except OSError:
            self._mtime = None
        cfg = load_config()
        built = []
        for s in cfg['sinks']:
            if s.get('enabled', True) is False:
                continue
            try:
                sink = sinks.build(s)
                sink.min_severity = SEVERITY_RANK.get(str(s.get('min_severity', 'HIGH')).upper(), 3)
                built.append(sink)
            except ValueError as exc:
                logger.warning('integration %s disabled: %s', s.get('name') or s.get('type'), exc)
        with self._lock:
            for old in self.sinks:
                old.close()
            self.sinks = built

    def _ensure_worker(self):
        if self._thread is None or not self._thread.is_alive():
            self._thread = threading.Thread(target=self._run, daemon=True, name='sentinel-integrations')
            self._thread.start()

    def emit(self, alert):
        self._maybe_reload()
        if not self.sinks:
            return False
        try:
            self.q.put_nowait((time.time(), dict(alert)))
            self.stats['queued'] += 1
        except queue.Full:
            self.stats['dropped'] += 1
            return False
        self._ensure_worker()
        return True

    def _deliver(self, sink, alert):
        delay = 0.5
        for attempt in range(self.retries):
            try:
                sink.send(alert)
                return True
            except Exception as exc:
                self.stats['last_error'] = f'{sink.name}: {exc}'[:300]
                if attempt + 1 < self.retries:
                    time.sleep(delay)
                    delay *= 2
        return False

    def _run(self):
        while True:
            queued_at, alert = self.q.get()
            rank = SEVERITY_RANK.get(str(alert.get('severity', '')).upper(), 0)
            with self._lock:
                targets = [s for s in self.sinks if rank >= s.min_severity]
            for sink in targets:
                if self._deliver(sink, alert):
                    self.stats['sent'] += 1
                    self.stats['last_latency_ms'] = round((time.time() - queued_at) * 1000, 1)
                else:
                    self.stats['failed'] += 1
                    logger.warning('integration %s failed: %s', sink.name, self.stats['last_error'])
            self.q.task_done()

    def flush(self, timeout=10):
        deadline = time.time() + timeout
        while self.q.unfinished_tasks and time.time() < deadline:
            time.sleep(0.02)
        return self.q.unfinished_tasks == 0

    def test(self, sink_config):
        """Send a test alert to one sink synchronously; returns (ok, message, latency_ms)."""
        sink = sinks.build(sink_config)
        alert = {'severity': 'HIGH', 'attack_type': 'test_alert', 'initiator_ip': '192.0.2.1',
                 'responder_ip': '192.0.2.2', 'protocol': 'TCP', 'final_risk_score': 60,
                 'explanation': ['This is a test alert from SentinelEdgeAI'], 'test': True}
        t0 = time.time()
        try:
            sink.send(alert)
            return True, 'delivered', round((time.time() - t0) * 1000, 1)
        except Exception as exc:
            return False, str(exc)[:300], None
        finally:
            sink.close()


_dispatcher = None
_lock = threading.Lock()


def get_dispatcher():
    global _dispatcher
    with _lock:
        if _dispatcher is None:
            _dispatcher = Dispatcher()
        return _dispatcher


def status_file():
    return os.path.join(os.path.dirname(os.path.abspath(config_file())), 'integrations_status.json')


def write_status():
    """The engine publishes delivery counters for the console (a different process)."""
    try:
        d = get_dispatcher()
        with open(status_file() + '.tmp', 'w', encoding='utf-8') as f:
            json.dump({**d.stats, 'sinks': [s.name for s in d.sinks], 'updated': time.time()}, f)
        os.replace(status_file() + '.tmp', status_file())
    except OSError:
        pass


def read_status():
    try:
        with open(status_file(), 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def emit(alert):
    try:
        return get_dispatcher().emit(alert)
    except Exception:
        logger.exception('integration dispatch failed')
        return False
