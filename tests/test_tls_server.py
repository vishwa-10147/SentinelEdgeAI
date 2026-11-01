"""Server-side TLS: JA4S and certificate anomalies, reassembled across segments (Phase 9)."""
import datetime
import struct

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from capture import afpacket
from detection.pipeline import DetectionPipeline
from detection.tls import ServerHandshakes, TLSDetector, certificate_anomalies, certificate_facts, parse_server_handshake

NOW = datetime.datetime(2026, 11, 1, tzinfo=datetime.timezone.utc)
CLIENT, SERVER = '192.168.1.20', '93.184.216.34'


def make_cert(cn='example.com', sans=('example.com',), self_signed=True, days=90, start=-1):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    issuer = subject if self_signed else x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'Test CA')])
    b = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
         .serial_number(1).not_valid_before(NOW + datetime.timedelta(days=start))
         .not_valid_after(NOW + datetime.timedelta(days=start + days)))
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
    return b.sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER)


def server_hello(version13=False, alpn=b'h2'):
    ext = b''
    if alpn:
        a = bytes([len(alpn)]) + alpn
        ext += struct.pack('>HH', 16, len(a) + 2) + struct.pack('>H', len(a)) + a
    if version13:
        ext += struct.pack('>HHH', 43, 2, 0x0304)
    body = struct.pack('>H', 0x0303) + b'\x11' * 32 + b'\x00' + struct.pack('>H', 0x1301) + b'\x00'
    body += struct.pack('>H', len(ext)) + ext
    return bytes([2]) + len(body).to_bytes(3, 'big') + body


def certificate_msg(*ders):
    chain = b''.join(len(d).to_bytes(3, 'big') + d for d in ders)
    body = len(chain).to_bytes(3, 'big') + chain
    return bytes([11]) + len(body).to_bytes(3, 'big') + body


def record(hs):
    return b'\x16\x03\x03' + struct.pack('>H', len(hs)) + hs


def test_ja4s_and_tls13_stops_early():
    hello, certs, complete = parse_server_handshake(record(server_hello(version13=True)))
    assert complete and certs == [] and hello['version'] == '13'
    a, cipher, c = hello['ja4s'].split('_')
    assert a == 't1302h2' and cipher == '1301' and len(c) == 12
    hello12, _, complete = parse_server_handshake(record(server_hello(alpn=b'')))
    assert hello12['ja4s'].startswith('t120000_1301_') and not complete      # certificate still to come


def test_reassembly_across_segments():
    data = record(server_hello() + certificate_msg(make_cert()))
    hs = ServerHandshakes()
    key = (SERVER, 443, CLIENT, 50000)
    assert hs.feed(key, data[:200]) is None and key in hs.pending
    assert hs.feed(key, data[200:260]) is None
    hello, certs = hs.feed(key, data[260:])
    assert hello['cipher'] == 0x1301 and len(certs) == 1 and key not in hs.pending
    assert hs.feed(key, b'\x17\x03\x03\x00\x10' + b'\x00' * 16) is None       # application data, not followed


def test_certificate_anomalies():
    ts = NOW.timestamp()
    facts = certificate_facts(make_cert())
    assert facts['self_signed'] and facts['names'] == ['example.com']
    assert certificate_anomalies(facts, 'example.com', ts) == ['self-signed']
    ok = certificate_facts(make_cert(cn='x', sans=('*.example.com',), self_signed=False))
    assert certificate_anomalies(ok, 'www.example.com', ts) == []
    assert certificate_anomalies(ok, 'a.b.example.com', ts)[0].startswith('issued for *.example.com')
    short = certificate_facts(make_cert(self_signed=False, days=1, start=0))
    assert certificate_anomalies(short, None, ts) == ['valid for only 24 hours']
    old = certificate_facts(make_cert(self_signed=False, start=-200))
    assert certificate_anomalies(old, 'example.com', ts) == ['expired']


def test_detector_reports_external_certificate_problems_only():
    det = TLSDetector(blocklist={}, clock=lambda: NOW.timestamp())
    det.sni[(CLIENT, SERVER)] = 'bank.example'
    hello, certs, _ = parse_server_handshake(record(server_hello() + certificate_msg(make_cert())))
    [f] = det.observe_server(SERVER, CLIENT, hello, certs)
    assert f.kind == 'tls_cert_anomaly' and f.src == CLIENT and 'self-signed' in f.details['reasons']
    assert any('not bank.example' in r for r in f.details['reasons'])
    assert det.observe_server(SERVER, CLIENT, hello, certs) == []                # cooldown
    assert det.observe_server('192.168.1.1', CLIENT, hello, certs) == []         # internal: not reported
    bad = TLSDetector(blocklist={hello['ja4s']: 'test C2'}, clock=lambda: NOW.timestamp())
    assert [f.kind for f in bad.observe_server('192.168.1.1', CLIENT, hello, [])] == ['tls_known_bad']


def test_pipeline_and_fast_path_follow_the_server_handshake():
    from scapy.all import IP, TCP, Ether, Raw
    data = record(server_hello() + certificate_msg(make_cert(sans=('evil.test',))))
    first, rest = data[:300], data[300:]
    E = dict(src='02:00:00:00:00:01', dst='02:00:00:00:00:02')
    f1 = bytes(Ether(**E) / IP(src=SERVER, dst=CLIENT) / TCP(sport=443, dport=50001) / Raw(first))
    f2 = bytes(Ether(**E) / IP(src=SERVER, dst=CLIENT) / TCP(sport=443, dport=50001) / Raw(rest))
    assert afpacket.parse(f1)[6] is True and afpacket.parse(f2)[6] is True    # continuation followed
    pipe = DetectionPipeline(models=False, clock=lambda: NOW.timestamp())
    assert pipe.observe_tls_server(SERVER, 443, CLIENT, 50001, first) == (None, [])
    hello, findings = pipe.observe_tls_server(SERVER, 443, CLIENT, 50001, rest)
    assert hello['ja4s'] and [f.kind for f in findings] == ['tls_cert_anomaly']
