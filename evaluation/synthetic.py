"""Labelled synthetic traffic for repeatable detection measurements.

Benign traffic deliberately includes the patterns that cause false alarms
in practice: NTP polling (periodic), nightly backups to a known server
(large uploads), software downloads, CDN-heavy browsing with many
destinations, a printer scanned by a management tool, and long legitimate
DNS names (CDNs, cloud services). Attacks cover every class the detectors
target. Every event carries its label and, for attacks, the attack id.

Deterministic for a given seed.
"""
import random
import string

BASE = 1_800_000_000.0     # a fixed epoch so results do not depend on the date
CLASSES = ('port_scan', 'host_sweep', 'brute_force', 'beaconing', 'exfiltration', 'dns_tunnel', 'dga')


def _flow(ts, src, dst, dport, proto='TCP', duration=1.0, out_b=2000, in_b=20000, label='benign', attack=None, sport=None):
    return {'type': 'flow', 'label': label, 'attack': attack,
            'record': {'ts': ts, 'start': ts - duration, 'src': src, 'dst': dst,
                       'sport': sport or random.randint(32768, 60999), 'dport': dport, 'proto': proto,
                       'duration': duration, 'forward_bytes': out_b, 'backward_bytes': in_b,
                       'forward_packets': max(1, out_b // 1200), 'backward_packets': max(1, in_b // 1200)}}


def _dns(ts, src, qname, nx=False, label='benign', attack=None):
    return {'type': 'dns', 'label': label, 'attack': attack, 'ts': ts, 'src': src, 'qname': qname, 'nx': nx}


def _ext(rng):
    while True:
        ip = f'{rng.choice([23, 34, 52, 104, 142, 151, 172, 185, 199])}.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}'
        if not ip.startswith('172.') or not (16 <= int(ip.split('.')[1]) <= 31):
            return ip


def benign(rng, hours=6, hosts=25):
    events = []
    clients = [f'192.168.10.{i}' for i in range(20, 20 + hosts)]
    servers = {'files': '192.168.10.5', 'printer': '192.168.10.9', 'backup': '203.0.113.200', 'mgmt': '192.168.10.2'}
    popular = [_ext(rng) for _ in range(400)]
    domains = ['google.com', 'microsoft.com', 'github.com', 'wikipedia.org', 'office.com', 'zoom.us', 'slack.com',
               'netflix.com', 'amazonaws.com', 'cloudfront.net', 'akamaiedge.net', 'apple.com', 'whatsapp.net']
    end = BASE + hours * 3600
    for c in clients:
        t = BASE + rng.uniform(0, 60)
        while t < end:                                   # browsing: bursts to many destinations
            for _ in range(rng.randint(3, 25)):
                events.append(_flow(t, c, rng.choice(popular), 443, duration=rng.uniform(0.2, 30),
                                    out_b=rng.randint(800, 40000), in_b=rng.randint(5000, 2_000_000)))
                q = f'{rng.choice(["www", "api", "cdn", "static", "img"])}.{rng.choice(domains)}'
                events.append(_dns(t, c, q, nx=rng.random() < 0.01))
                t += rng.uniform(0.1, 5)
            t += rng.expovariate(1 / 240)
        t = BASE + rng.uniform(0, 64)
        while t < end:                                   # NTP every 64 s
            events.append(_flow(t, c, '162.159.200.123', 123, 'UDP', 0.01, 90, 90))
            t += 64
        for _ in range(rng.randint(0, 3)):               # long but legitimate CDN / cloud names
            t = rng.uniform(BASE, end)
            sub = ''.join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(20, 30)))
            events.append(_dns(t, c, f'{sub}.cloudfront.net'))
        if rng.random() < 0.3:                           # software download
            t = rng.uniform(BASE, end)
            events.append(_flow(t, c, rng.choice(popular), 443, duration=120, out_b=200_000, in_b=800_000_000))
        t = BASE + rng.uniform(0, 300)
        while t < end:                                   # file share: many small SMB sessions
            events.append(_flow(t, c, servers['files'], 445, duration=rng.uniform(0.5, 20),
                                out_b=rng.randint(2000, 200000), in_b=rng.randint(2000, 500000)))
            t += rng.expovariate(1 / 120)
    for night in range(int(hours // 6) + 1):             # backup: large upload to a known server
        t = BASE + night * 6 * 3600 + 3000
        for c in clients[:5]:
            for k in range(3):
                events.append(_flow(t + k * 600 - 3000 + 60, c, servers['backup'], 443, duration=30,
                                    out_b=2_000_000, in_b=50_000))
            events.append(_flow(t + 1800, c, servers['backup'], 443, duration=600, out_b=900_000_000, in_b=400_000))
    t = BASE + 30
    while t < end:                                       # containerised app reconnecting to Redis/Postgres (seen live)
        events.append(_flow(t, '10.0.2.5', '10.0.2.2', 6379, duration=0.05, out_b=300, in_b=300))
        events.append(_flow(t + 1, '10.0.2.5', '10.0.2.3', 5432, duration=0.2, out_b=900, in_b=1200))
        t += rng.uniform(9, 11)
    t = BASE + 1800
    while t < end:                                       # monitoring tool polls the printer's services
        for port in (80, 161, 443, 515, 631, 9100):
            events.append(_flow(t, servers['mgmt'], servers['printer'], port, duration=0.2, out_b=300, in_b=900))
        t += 300
    return events


def attacks(rng, hours=6):
    events, truth = [], []
    end = BASE + hours * 3600

    def attack(kind, src, start, build):
        aid = f'{kind}-{len(truth)}'
        truth.append({'id': aid, 'kind': kind, 'src': src, 'start': start})
        events.extend(build(aid))

    for i in range(6):
        s = f'192.168.10.{100 + i}'
        st = rng.uniform(BASE + 3600, end - 600)
        target = f'192.168.10.{rng.randint(20, 44)}'
        attack('port_scan', s, st, lambda a, s=s, st=st, target=target: [
            _flow(st + k * rng.uniform(0.01, 0.5), s, target, p, duration=0.01, out_b=60, in_b=0,
                  label='port_scan', attack=a) for k, p in enumerate(rng.sample(range(1, 10000), rng.randint(30, 300)))])
    for i in range(6):
        s = f'192.168.10.{110 + i}'
        st = rng.uniform(BASE + 3600, end - 600)
        port = rng.choice([22, 445, 3389, 80])
        attack('host_sweep', s, st, lambda a, s=s, st=st, port=port: [
            _flow(st + k * rng.uniform(0.05, 1), s, f'192.168.10.{h}', port, duration=0.02, out_b=60, in_b=40,
                  label='host_sweep', attack=a) for k, h in enumerate(range(1, rng.randint(25, 120)))])
    for i in range(6):
        s = _ext(rng) if i % 2 else f'192.168.10.{120 + i}'
        st = rng.uniform(BASE + 3600, end - 1200)
        port = rng.choice([22, 3389, 21, 5432])
        attack('brute_force', s, st, lambda a, s=s, st=st, port=port: [
            _flow(st + k * rng.uniform(1, 6), s, '192.168.10.5', port, duration=rng.uniform(0.5, 3),
                  out_b=rng.randint(800, 2500), in_b=rng.randint(800, 2500), label='brute_force', attack=a)
            for k in range(rng.randint(15, 80))])
    for i in range(6):
        s = f'192.168.10.{20 + i}'                       # an infected ordinary workstation
        st = rng.uniform(BASE, BASE + 3600)
        period = rng.choice([30, 60, 120, 300])
        c2 = _ext(rng)
        def beacons(a, s=s, st=st, period=period, c2=c2):
            out, t = [], st
            while t < end:                               # each interval jitters independently (±5%)
                out.append(_flow(t, s, c2, 443, duration=0.3, out_b=400, in_b=600, label='beaconing', attack=a))
                t += period * rng.uniform(0.95, 1.05)
            return out
        attack('beaconing', s, st, beacons)
    for i in range(6):
        s = f'192.168.10.{30 + i}'
        st = rng.uniform(BASE + 7200, end - 600)
        attack('exfiltration', s, st, lambda a, s=s, st=st: [
            _flow(st, s, _ext(rng), rng.choice([443, 22, 8443]), duration=rng.uniform(60, 600),
                  out_b=rng.randint(20_000_000, 900_000_000), in_b=rng.randint(10_000, 200_000),
                  label='exfiltration', attack=a)])
    for i in range(6):
        s = f'192.168.10.{36 + i}'
        st = rng.uniform(BASE + 3600, end - 600)
        dom = rng.choice(['t1.evil-tunnel.com', 'ns.dnsexfil.net', 'x.data-chan.org'])
        attack('dns_tunnel', s, st, lambda a, s=s, st=st, dom=dom: [
            _dns(st + k * rng.uniform(0.05, 0.5), s,
                 ''.join(rng.choices('abcdefghijklmnopqrstuvwxyz234567', k=rng.randint(45, 63))) + '.' + dom,
                 label='dns_tunnel', attack=a) for k in range(rng.randint(60, 400))])
    for i in range(6):
        s = f'192.168.10.{42 + i}'
        st = rng.uniform(BASE + 3600, end - 600)
        attack('dga', s, st, lambda a, s=s, st=st: [
            _dns(st + k * rng.uniform(0.2, 3), s,
                 ''.join(rng.choices(string.ascii_lowercase + string.digits, k=rng.randint(10, 18))) +
                 rng.choice(['.com', '.net', '.info', '.biz']), nx=rng.random() < 0.9, label='dga', attack=a)
            for k in range(rng.randint(30, 120))])
    return events, truth


def dataset(seed=7, hours=6):
    rng = random.Random(seed)
    random.seed(seed)
    ev = benign(rng, hours)
    atk, truth = attacks(rng, hours)
    ev.extend(atk)
    ev.sort(key=lambda e: e['record']['ts'] if e['type'] == 'flow' else e['ts'])
    return ev, truth
