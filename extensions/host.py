"""Runs enabled extensions in their sandboxes and turns their answers into checked findings.

The engine never waits for an extension: events are written to its stdin without blocking (when its pipe
is full the event is dropped and counted: load shedding), and findings are collected by a reader thread
and handed to the pipeline on the next event. Every finding is checked:

  * its device (src) must be one of the addresses in the event it answers;
  * kind becomes `ext:<extension>:<kind>`; severity is capped at 80, probability at 0.7, evidence at 300
    characters; at most 5 findings per event;
  * an extension finding never confirms an automatic response on its own (fusion needs a second signal,
    and its probability stays under the 0.9 precision bar).

An extension that crashes 3 times, or sends malformed output 20 times, is disabled and audited.
"""
import json
import logging
import os
import queue
import select
import subprocess
import sys
import tempfile
import threading
import time

from detection.detectors import Finding
from extensions import package

logger = logging.getLogger('sentinel.extensions')
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
MAX_SEVERITY, MAX_PROBABILITY = 80, 0.7
MAX_CRASHES, MAX_BAD = 3, 20
FLOW_FIELDS = ('src', 'dst', 'sport', 'dport', 'proto', 'duration', 'forward_bytes', 'backward_bytes',
               'forward_packets', 'backward_packets', 'ts')


def hidden_paths():
    """Directories an extension must never see."""
    paths = [os.path.join(ROOT, d) for d in ('data', 'logs', 'reports', 'model')] + \
            ['/etc/sentinel', '/var/lib/sentinel', '/var/log/sentinel', '/root', os.path.expanduser('~/.sentinel'),
             os.path.expanduser('~/.ssh')]
    for env in ('SENTINEL_AUTH_DB', 'SENTINEL_AUDIT_DB', 'SENTINEL_DEVICES_DB'):
        if os.environ.get(env):
            paths.append(os.path.dirname(os.path.abspath(os.environ[env])))
    # the extension's own directory is bind-mounted at /tmp/extension before these are covered,
    # and /tmp is a private tmpfs anyway
    out = []
    for p in paths:
        p = os.path.abspath(p)
        if os.path.isdir(p) and p not in out:
            out.append(p)
    return out


class ExtensionProcess:
    def __init__(self, name, manifest, on_disable=None):
        self.name, self.manifest = name, manifest
        self.on_disable = on_disable
        self.proc = None
        self.findings = queue.Queue(maxsize=1000)
        self.pending = {}                                  # event id -> addresses allowed in its findings
        self.next_id = 0
        self.crashes = self.bad = self.dropped = 0
        self.disabled = None
        self.ready = threading.Event()
        self._spec_file = None

    def _spec(self):
        spec = {'name': self.name, 'dir': package.installed_dir(self.name), 'entry': self.manifest['entry'],
                'python': sys.executable, 'sdk': os.path.join(ROOT, 'extensions', 'sdk'),
                'network': self.manifest.get('network', False), 'memory_mb': self.manifest['memory_mb'],
                'hide': hidden_paths()}
        fd, path = tempfile.mkstemp(prefix='ext-spec-', suffix='.json')
        with os.fdopen(fd, 'w') as f:
            json.dump(spec, f)
        return path

    def start(self):
        self._spec_file = self._spec()
        # the launcher uses the standard library only, so it runs isolated (-I) by file path
        self.proc = subprocess.Popen([sys.executable, '-I', '-B', os.path.join(ROOT, 'extensions', 'sandbox.py'),
                                      self._spec_file], cwd='/', stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, env={'PATH': '/usr/bin:/bin'}, close_fds=True)
        os.set_blocking(self.proc.stdin.fileno(), False)
        threading.Thread(target=self._read, daemon=True, name=f'ext-{self.name}').start()
        threading.Thread(target=self._read_err, daemon=True, name=f'ext-{self.name}-err').start()

    def _read_err(self):
        for line in self.proc.stderr:
            logger.info('extension %s: %s', self.name, line.decode('utf-8', 'replace').rstrip()[:300])

    def _read(self):
        proc = self.proc
        for line in proc.stdout:
            try:
                msg = json.loads(line)
            except ValueError:
                self._bad('not JSON')
                continue
            if 'ready' in msg:
                self.ready.set()
                continue
            if msg.get('error'):
                self._bad(f"handler error: {str(msg['error'])[:120]}")
                continue
            allowed = self.pending.pop(msg.get('id'), None)
            if allowed is None:
                self._bad('answer to an unknown event')
                continue
            for raw in (msg.get('findings') or [])[:5]:
                f = self._check(raw, allowed)
                if f is not None:
                    try:
                        self.findings.put_nowait(f)
                    except queue.Full:
                        self.dropped += 1
        code = proc.wait()
        if self._spec_file and os.path.exists(self._spec_file):
            os.unlink(self._spec_file)
        if self.disabled or self.proc is not proc:
            return
        self.crashes += 1
        reason = 'the sandbox could not be created on this system' if code == 97 else f'exited with status {code}'
        logger.warning('extension %s %s (%d/%d)', self.name, reason, self.crashes, MAX_CRASHES)
        if code == 97 or self.crashes >= MAX_CRASHES:
            self.disable(reason)
        else:
            time.sleep(min(30, 2 ** self.crashes))
            if not self.disabled:
                self.start()

    def _bad(self, why):
        self.bad += 1
        if self.bad >= MAX_BAD:
            self.disable(f'malformed output ({why})')

    def _check(self, raw, allowed):
        if not isinstance(raw, dict):
            self._bad('finding is not an object')
            return None
        src = str(raw.get('src', ''))
        if src not in allowed['ips']:
            self._bad(f'finding names {src[:45]}, which is not in the event')
            return None
        try:
            severity = max(0, min(MAX_SEVERITY, int(raw.get('severity', 50))))
            probability = max(0.0, min(MAX_PROBABILITY, float(raw.get('probability', 0.5))))
        except (TypeError, ValueError):
            self._bad('severity / probability not numbers')
            return None
        kind = ''.join(c for c in str(raw.get('kind', 'finding')) if c.isalnum() or c in '_-')[:40] or 'finding'
        details = raw.get('details') if isinstance(raw.get('details'), dict) else {}
        details = {str(k)[:40]: (v if isinstance(v, (int, float, bool)) else str(v)[:200])
                   for k, v in list(details.items())[:10]}
        return Finding(f'ext:{self.name}:{kind}', src, severity, probability, str(raw.get('technique') or '')[:16],
                       f"[{self.name}] {str(raw.get('evidence', ''))[:300]}", {**details, 'extension': self.name},
                       ts=allowed['ts'])

    def send(self, kind, event, ips, ts):
        if self.disabled or self.proc is None or self.proc.poll() is not None:
            return False
        self.next_id += 1
        line = (json.dumps({'id': self.next_id, 'type': kind, 'event': event}, default=str) + '\n').encode()
        try:
            _, w, _ = select.select([], [self.proc.stdin], [], 0)
            if not w:
                raise BlockingIOError
            os.write(self.proc.stdin.fileno(), line)
        except (BlockingIOError, BrokenPipeError, OSError):
            self.dropped += 1                              # the extension is behind: shed load, never wait
            return False
        self.pending[self.next_id] = {'ips': set(ips), 'ts': ts}
        if len(self.pending) > 5000:                       # events it never answered
            for k in list(self.pending)[:1000]:
                del self.pending[k]
        return True

    def take(self):
        out = []
        while True:
            try:
                out.append(self.findings.get_nowait())
            except queue.Empty:
                return out

    def disable(self, reason):
        self.disabled = reason
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.kill()
        except OSError:
            pass
        logger.warning('extension %s disabled: %s', self.name, reason)
        if self.on_disable:
            self.on_disable(self.name, reason)

    def stop(self):
        self.disabled = self.disabled or 'stopped'
        if self.proc and self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait(5)


class ExtensionHost:
    """All enabled extensions; the pipeline calls flow()/dns()/http() and the playbook action()."""

    def __init__(self, names=None):
        self.procs = {}
        state = package.load_state()
        for name, st in state.items():
            if names is not None and name not in names:
                continue
            if not st.get('enabled') and names is None:
                continue
            try:
                manifest, _ = package.verify(package.installed_dir(name))
            except package.ExtensionError as exc:
                self._disabled(name, f'verification failed: {exc}')
                continue
            p = ExtensionProcess(name, manifest, on_disable=self._disabled)
            p.start()
            self.procs[name] = p

    @staticmethod
    def _disabled(name, reason):
        try:
            package.set_enabled(name, False, reason=reason, by='extension host')
        except package.ExtensionError:
            pass

    def wait_ready(self, timeout=10):
        deadline = time.time() + timeout
        for p in self.procs.values():
            p.ready.wait(max(0, deadline - time.time()))
        return {n: p.ready.is_set() for n, p in self.procs.items()}

    def _dispatch(self, kind, event, ips, ts):
        out = []
        for p in self.procs.values():
            if kind in p.manifest['events']:
                p.send(kind, event, ips, ts)
            out += p.take()
        return out

    def flow(self, record):
        event = {k: record.get(k) for k in FLOW_FIELDS}
        return self._dispatch('flow', event, (record.get('src'), record.get('dst')), record.get('ts'))

    def dns(self, src, qname, nxdomain, ts):
        return self._dispatch('dns', {'src': src, 'qname': qname, 'nxdomain': bool(nxdomain), 'ts': ts}, (src,), ts)

    def http(self, src, dst, req, ts):
        event = {'src': src, 'dst': dst, 'ts': ts, **{k: req.get(k) for k in ('method', 'host', 'user_agent', 'ja4h')}}
        return self._dispatch('http', event, (src, dst), ts)

    def action(self, action, ip, reason, ts=None):
        """Notify response-action extensions (they act outside the appliance; their output is ignored)."""
        self._dispatch('action', {'action': action, 'ip': ip, 'reason': str(reason)[:200], 'ts': ts or time.time()},
                       (), ts)

    def status(self):
        return {n: {'running': p.proc is not None and p.proc.poll() is None, 'disabled': p.disabled,
                    'dropped': p.dropped, 'bad': p.bad, 'crashes': p.crashes} for n, p in self.procs.items()}

    def stop(self):
        for p in self.procs.values():
            p.stop()


_host = None


def get_host():
    """The engine's host, or None when no extension is enabled (nothing is started then)."""
    global _host
    if _host is None:
        if not any(st.get('enabled') for st in package.load_state().values()):
            return None
        _host = ExtensionHost()
    return _host
