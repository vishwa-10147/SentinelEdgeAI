"""Attack-specific detectors over finished flows (Phase 4).

Each detector keeps a sliding window per source and returns Finding objects.
A finding names the attack class, a severity (0-100), a calibrated
probability that it is a true positive, the MITRE ATT&CK technique and the
evidence in plain words, so every alert can be explained.

Flow records are dicts as produced by common.protocol.flow_record (src, dst,
sport, dport, proto, ts, duration, forward_bytes, backward_bytes, ...).
"""
import ipaddress
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

# services that authenticate per connection; Redis and HTTP-alternate ports are left out because
# applications reconnect to them constantly (seen live: a container hitting Redis every ~4 s)
AUTH_PORTS = {21, 22, 23, 110, 143, 389, 445, 993, 995, 1433, 3306, 3389, 5432, 5900}
# interactive logins: nothing legitimate reconnects every few seconds, so any fast cadence counts;
# on the other auth ports applications do reconnect on a timer, so only fast or irregular cadence counts
INTERACTIVE_PORTS = {21, 22, 23, 3389, 5900}


@dataclass
class Finding:
    kind: str               # e.g. 'port_scan'
    src: str
    severity: int           # 0-100
    probability: float      # calibrated chance this is a real attack
    technique: str          # MITRE ATT&CK id
    evidence: str
    details: dict = field(default_factory=dict)
    ts: float = field(default_factory=time.time)

    def as_dict(self):
        return {'kind': self.kind, 'src': self.src, 'severity': self.severity,
                'probability': round(self.probability, 3), 'technique': self.technique,
                'evidence': self.evidence, 'details': self.details, 'ts': self.ts}


def is_external(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast or a.is_reserved)


class _Window:
    """Per-key deque of (ts, value) trimmed to `seconds`."""

    def __init__(self, seconds, max_items=5000):
        self.seconds = seconds
        self.max_items = max_items
        self.data = defaultdict(deque)

    def add(self, key, ts, value):
        q = self.data[key]
        q.append((ts, value))
        while q and (q[0][0] < ts - self.seconds or len(q) > self.max_items):
            q.popleft()
        return q

    def prune(self, now):
        for key in [k for k, q in self.data.items() if not q or q[-1][0] < now - self.seconds]:
            del self.data[key]


class Cooldown:
    """Report the same (kind, src) at most once per `seconds`."""

    def __init__(self, seconds=300):
        self.seconds = seconds
        self.last = {}

    def ready(self, key, now):
        if now - self.last.get(key, -1e18) < self.seconds:
            return False
        self.last[key] = now
        return True


class PortScanDetector:
    """Many distinct destination ports on one host (vertical) or one port on many hosts (sweep)."""

    def __init__(self, window=60, ports=20, hosts=15):
        self.ports_w = _Window(window)
        self.hosts_w = _Window(window)
        self.port_threshold, self.host_threshold = ports, hosts
        self.cooldown = Cooldown()

    def observe(self, f):
        now, src = f['ts'], f['src']
        out = []
        q = self.ports_w.add((src, f['dst']), now, f.get('dport'))
        ports = {p for _, p in q}
        if len(ports) >= self.port_threshold and self.cooldown.ready(('port_scan', src, f['dst']), now):
            out.append(Finding('port_scan', src, min(95, 60 + len(ports)), 0.95, 'T1046',
                               f'{len(ports)} distinct ports probed on {f["dst"]} within {self.ports_w.seconds}s',
                               {'target': f['dst'], 'ports': len(ports)}, ts=now))
        if is_external(f['dst']):
            # many external hosts on one port is ordinary browsing (CDNs); sweeps are internal recon
            return out
        q = self.hosts_w.add((src, f.get('dport')), now, f['dst'])
        hosts = {h for _, h in q}
        if len(hosts) >= self.host_threshold and self.cooldown.ready(('host_sweep', src, f.get('dport')), now):
            out.append(Finding('host_sweep', src, min(90, 55 + len(hosts)), 0.9, 'T1018',
                               f'{len(hosts)} hosts contacted on port {f.get("dport")} within {self.hosts_w.seconds}s',
                               {'port': f.get('dport'), 'hosts': len(hosts)}, ts=now))
        return out


class BruteForceDetector:
    """Repeated short, small sessions to an authentication service."""

    def __init__(self, window=120, attempts=10, max_duration=5.0, max_bytes=5000, max_median_gap=5.0,
                 fast_gap=1.0, min_jitter=0.3):
        self.w = _Window(window)
        self.attempts, self.max_duration, self.max_bytes = attempts, max_duration, max_bytes
        # guessing is either very fast (< fast_gap s apart) or irregular; scheduled clients
        # (health checks, reconnecting apps) repeat on a near-fixed timer
        self.max_median_gap, self.fast_gap, self.min_jitter = max_median_gap, fast_gap, min_jitter
        self.cooldown = Cooldown()

    def observe(self, f):
        if f.get('dport') not in AUTH_PORTS or f.get('proto') != 'TCP':
            return []
        size = (f.get('forward_bytes') or 0) + (f.get('backward_bytes') or 0)
        if (f.get('duration') or 0) > self.max_duration or size > self.max_bytes:
            return []
        key = (f['src'], f['dst'], f['dport'])
        q = self.w.add(key, f['ts'], f.get('start') or f['ts'])
        if len(q) < self.attempts:
            return []
        starts = sorted(v for _, v in q)
        gaps = [b - a for a, b in zip(starts, starts[1:])]
        if not gaps:
            return []
        median = sorted(gaps)[len(gaps) // 2]
        mean = sum(gaps) / len(gaps)
        jitter = statistics.pstdev(gaps) / mean if mean > 0 else 0.0
        if f['dport'] in INTERACTIVE_PORTS:
            attack_like = median <= self.max_median_gap
        else:
            attack_like = median <= self.fast_gap or (median <= self.max_median_gap and jitter >= self.min_jitter)
        if attack_like and self.cooldown.ready(('brute_force',) + key, f['ts']):
            return [Finding('brute_force', f['src'], min(92, 65 + len(q)), 0.9, 'T1110',
                            f'{len(q)} short sessions to {f["dst"]}:{f["dport"]} within {self.w.seconds}s',
                            {'target': f['dst'], 'port': f['dport'], 'attempts': len(q)}, ts=f['ts'])]
        return []


class BeaconingDetector:
    """Connections to one destination at a near-constant interval (command and control)."""

    # NTP polls on a fixed interval by design
    IGNORE_PORTS = {123}

    def __init__(self, min_events=8, max_cv=0.15, min_period=5.0, window=3600):
        self.w = _Window(window, max_items=200)
        self.min_events, self.max_cv, self.min_period = min_events, max_cv, min_period
        self.cooldown = Cooldown(1800)

    def observe(self, f):
        if not is_external(f['dst']) or f.get('dport') in self.IGNORE_PORTS:
            return []
        key = (f['src'], f['dst'], f.get('dport'))
        start = f.get('start') or f['ts']
        q = self.w.add(key, f['ts'], start)
        if len(q) < self.min_events:
            return []
        starts = sorted(v for _, v in q)[-self.min_events * 2:]
        gaps = [b - a for a, b in zip(starts, starts[1:]) if b > a]
        if len(gaps) < self.min_events - 1:
            return []
        mean = statistics.mean(gaps)
        if mean < self.min_period:
            return []
        cv = statistics.pstdev(gaps) / mean
        if cv <= self.max_cv and self.cooldown.ready(('beaconing',) + key, f['ts']):
            return [Finding('beaconing', f['src'], 80, 0.8, 'T1071',
                            f'{len(gaps) + 1} connections to {f["dst"]}:{f.get("dport")} every '
                            f'{mean:.0f}s (jitter {cv * 100:.0f}%)',
                            {'target': f['dst'], 'period_s': round(mean, 1), 'jitter': round(cv, 3)}, ts=f['ts'])]
        return []


class ExfiltrationDetector:
    """Large, one-directional upload to an external destination the device has not used before."""

    def __init__(self, min_bytes=5_000_000, min_ratio=10.0, learning=3600):
        self.min_bytes, self.min_ratio, self.learning = min_bytes, min_ratio, learning
        self.seen = defaultdict(set)      # src -> destinations seen during normal use
        self.first = {}
        self.cooldown = Cooldown(1800)

    def observe(self, f):
        src, dst, now = f['src'], f['dst'], f['ts']
        self.first.setdefault(src, now)
        new_destination = dst not in self.seen[src]
        learning = now - self.first[src] < self.learning
        self.seen[src].add(dst)
        out_b, in_b = f.get('forward_bytes') or 0, f.get('backward_bytes') or 0
        if not is_external(dst) or out_b < self.min_bytes or out_b < self.min_ratio * max(in_b, 1):
            return []
        if not new_destination and learning:
            return []
        prob = 0.85 if new_destination else 0.6
        if self.cooldown.ready(('exfiltration', src, dst), now):
            return [Finding('exfiltration', src, 85 if new_destination else 70, prob, 'T1048',
                            f'{out_b / 1e6:.1f} MB sent to {"new " if new_destination else ""}external host {dst} '
                            f'({out_b / max(in_b, 1):.0f}x more than received)',
                            {'target': dst, 'bytes_out': out_b, 'bytes_in': in_b, 'new_destination': new_destination}, ts=now)]
        return []


class NewDeviceDetector:
    """A source address never seen before, after the learning period (possible rogue device)."""

    def __init__(self, learning=86400, clock=time.time):
        self.started = clock()
        self.learning = learning
        self.known = set()

    def observe(self, f):
        src = f['src']
        try:
            if not ipaddress.ip_address(src).is_private:
                return []
        except ValueError:
            return []
        if src in self.known:
            return []
        self.known.add(src)
        if f['ts'] - self.started < self.learning:
            return []
        return [Finding('new_device', src, 40, 0.5, 'T1200', f'first traffic from {src}, not seen before',
                        {'first_seen': f['ts']}, ts=f['ts'])]


def default_flow_detectors():
    return [PortScanDetector(), BruteForceDetector(), BeaconingDetector(), ExfiltrationDetector(),
            NewDeviceDetector(), IntelDetector()]


class IntelDetector:
    """Traffic to or from an address listed in the threat-intelligence store."""

    def __init__(self, store=None):
        self._store = store
        self.cooldown = Cooldown(900)

    def store(self):
        if self._store is None:
            from intel.store import get_store
            self._store = get_store()
        return self._store

    def observe(self, f):
        out = []
        for peer, local in ((f['dst'], f['src']), (f['src'], f['dst'])):
            hit = self.store().match_ip(peer)
            if hit and self.cooldown.ready(('threat_intel', local, peer), f['ts']):
                source, label = hit
                out.append(Finding('threat_intel', local, 85, 0.9, 'T1071',
                                   f'traffic with {peer}, listed by {source}' + (f' ({label})' if label else ''),
                                   {'indicator': peer, 'source': source, 'label': label, 'target': peer}, ts=f['ts']))
        return out
