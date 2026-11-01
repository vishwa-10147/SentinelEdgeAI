"""Plain-HTTP metadata, JA4H, and the encrypted session-rhythm detector (Phase 9)."""
import hashlib
import random

from scapy.all import IP, TCP, Ether, Raw

from capture import afpacket
from detection.detectors import BeaconingDetector, SessionRhythmDetector
from detection.http import HTTPDetector, is_http_request, parse_http_request
from detection.pipeline import DetectionPipeline
from integrations.zeek import ZeekFeeder
from intel import store as intel_store

T0 = 1_700_000_000.0
DAY = 86400
WS, WEB = '10.0.0.20', '93.184.216.34'

BROWSER = (b'GET /index.html?q=secret HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n'
           b'Accept: */*\r\nAccept-Language: en-US,en;q=0.9\r\nReferer: http://example.com/\r\n'
           b'Cookie: sid=abc123; theme=dark\r\nConnection: keep-alive\r\n\r\n')
POWERSHELL = (b'GET /payload.ps1 HTTP/1.1\r\nUser-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) '
              b'WindowsPowerShell/5.1.19041.1\r\nHost: 93.184.216.34\r\nConnection: Keep-Alive\r\n\r\n')
BASIC = b'GET /admin HTTP/1.0\r\nHost: printer.local\r\nAuthorization: Basic YWRtaW46YWRtaW4=\r\n\r\n'


def h12(text):
    return hashlib.sha256(text.encode()).hexdigest()[:12]


# ---------- JA4H ----------

def test_ja4h_layout():
    req = parse_http_request(BROWSER)
    a, b, c, d = req['ja4h'].split('_')
    assert a == 'ge11cr05enus'                       # GET, 1.1, cookie, referer, 5 headers, en-US
    assert b == h12('Host,User-Agent,Accept,Accept-Language,Connection')
    assert c == h12('sid,theme') and d == h12('sid=abc123,theme=dark')
    assert req['ja4h_ab'] == f'{a}_{b}'
    assert req['host'] == 'example.com' and req['user_agent'] == 'Mozilla/5.0'
    assert 'secret' not in repr(req) and 'abc123' not in repr(req)     # path and cookie values are not kept


def test_ja4h_without_cookies_or_language():
    req = parse_http_request(BASIC)
    assert req['ja4h'].startswith('ge10nn020000_') and req['ja4h'].endswith('_000000000000_000000000000')
    assert req['auth_scheme'] == 'basic' and 'YWRt' not in repr(req)


def test_not_http():
    assert parse_http_request(b'\x16\x03\x01\x00') is None
    assert parse_http_request(b'GETTING THINGS DONE') is None
    assert parse_http_request(b'GET / FTP/1.0\r\n\r\n') is None
    assert is_http_request(b'POST /x HTTP/1.1\r\n') and not is_http_request(b'HTTP/1.1 200 OK\r\n')
    many = b'GET / HTTP/1.1\r\n' + b''.join(b'X-H%d: v\r\n' % i for i in range(200)) + b'\r\n'
    assert parse_http_request(many)['ja4h'][6:8] == '64'      # header list is bounded


# ---------- HTTP findings ----------

def test_lolbin_basic_auth_and_blocklist():
    det = HTTPDetector(blocklist={}, clock=lambda: T0)
    [f] = det.observe(WS, WEB, parse_http_request(POWERSHELL), ts=T0)
    assert f.kind == 'http_lolbin' and f.technique == 'T1105' and f.details['tool'] == 'PowerShell'
    assert det.observe(WS, '10.0.0.5', parse_http_request(POWERSHELL), ts=T0) == []   # internal server
    [f] = det.observe(WS, '10.0.0.9', parse_http_request(BASIC), ts=T0)
    assert f.kind == 'http_basic_auth' and f.probability < 0.5
    req = parse_http_request(BROWSER)
    det = HTTPDetector(blocklist={req['ja4h_ab']: 'test malware'}, clock=lambda: T0)
    [f] = det.observe(WS, WEB, req, ts=T0)
    assert f.kind == 'http_known_bad' and 'test malware' in f.evidence
    assert det.observe('8.8.8.8', WS, req, ts=T0) == []      # requests from the internet are not judged


def test_new_client_after_learning():
    det = HTTPDetector(blocklist={}, clock=lambda: T0)
    assert det.observe(WS, WEB, parse_http_request(BROWSER), ts=T0) == []
    assert det.observe(WS, '10.0.0.9', parse_http_request(BASIC), ts=T0 + 10)[0].kind == 'http_basic_auth'
    other = BROWSER.replace(b'Connection: keep-alive\r\n', b'X-Tool: 1\r\nConnection: close\r\n')
    [f] = det.observe(WS, WEB, parse_http_request(other), ts=T0 + DAY + 1)
    assert f.kind == 'http_new_client'


def test_intel_ja4h_indicator(tmp_path):
    req = parse_http_request(BROWSER)
    assert intel_store.classify(req['ja4h']) == ('ja4h', req['ja4h'])
    assert intel_store.classify(req['ja4h_ab']) == ('ja4h', req['ja4h_ab'])


def test_pipeline_and_capture_route_http():
    pipe = DetectionPipeline(models=False, clock=lambda: T0)
    req, findings = pipe.observe_http(WS, WEB, POWERSHELL, ts=T0)
    assert req['method'] == 'GET' and [f.kind for f in findings] == ['http_lolbin']
    assert pipe.observe_http(WS, WEB, b'not http') == (None, [])
    request = bytes(Ether() / IP(src=WS, dst=WEB) / TCP(sport=50000, dport=8080, flags='PA') / Raw(BROWSER))
    reply = bytes(Ether() / IP(src=WEB, dst=WS) / TCP(sport=8080, dport=50000, flags='PA') /
                  Raw(b'HTTP/1.1 200 OK\r\n\r\n' + b'x' * 500))
    assert afpacket.parse(request)[6] is True and afpacket.parse(reply)[6] is False


def test_zeek_http_log():
    pipe = DetectionPipeline(models=False, clock=lambda: T0)
    feeder = ZeekFeeder(pipe)
    ids = {'id.orig_h': WS, 'id.resp_h': WEB, 'id.orig_p': 50000, 'id.resp_p': 80, 'ts': T0}
    found = feeder.feed('http', {**ids, 'method': 'GET', 'host': WEB, 'user_agent': 'CertUtil URL Agent'})
    assert [f.kind for f in found] == ['http_lolbin']
    found = feeder.feed('http', {**ids, 'method': 'GET', 'host': 'cam', 'username': 'admin',
                                 'ja4h': 'ge11nn020000_aaaaaaaaaaaa_000000000000_000000000000'})
    assert [f.kind for f in found] == ['http_basic_auth']


# ---------- session rhythm ----------

def flows(n, gap, jitter, out_b, in_b, size_noise=0, seed=1, dport=443):
    rnd = random.Random(seed)
    t = T0
    for _ in range(n):
        t += gap * (1 + rnd.uniform(-jitter, jitter))
        yield {'src': WS, 'dst': WEB, 'dport': dport, 'start': t, 'ts': t + 1,
               'forward_bytes': out_b + rnd.randint(-size_noise, size_noise),
               'backward_bytes': in_b + rnd.randint(-size_noise, size_noise)}


def run(det, records):
    out = []
    for f in records:
        out += det.observe(f)
    return out


def test_jittered_beacon_with_constant_sizes():
    records = list(flows(14, 60, 0.5, 1480, 3120, size_noise=10))
    [f] = run(SessionRhythmDetector(), records)
    assert f.kind == 'session_rhythm' and f.details['timing_cv'] > 0.15 and f.details['size_cv'] < 0.05
    assert run(BeaconingDetector(), records) == []          # the interval test alone misses it


def test_regular_beacons_left_to_the_beaconing_detector():
    records = list(flows(14, 60, 0.02, 1480, 3120))
    assert run(SessionRhythmDetector(), records) == []
    assert run(BeaconingDetector(), records)


def test_browsing_and_bulk_are_not_rhythm():
    assert run(SessionRhythmDetector(), flows(30, 60, 0.6, 3000, 9000, size_noise=2500)) == []   # varied sizes
    assert run(SessionRhythmDetector(), flows(30, 60, 0.6, 500_000, 9000)) == []                 # large sessions
    assert run(SessionRhythmDetector(), flows(30, 2, 0.6, 1480, 3120)) == []                     # rapid bursts
    assert run(SessionRhythmDetector(), flows(30, 60, 0.6, 1480, 3120, dport=8080)) == []        # not a TLS port
