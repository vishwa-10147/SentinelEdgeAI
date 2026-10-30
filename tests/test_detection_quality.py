import os
import random
import time

import pytest

from detection import autoencoder, feedback, registry
from detection.detectors import (BeaconingDetector, BruteForceDetector, ExfiltrationDetector, Finding,
                                 NewDeviceDetector, PortScanDetector)
from detection.dns_analysis import DNSDetector, dga_score, entropy, split_name
from detection.fusion import Fusion
from detection.pipeline import DetectionPipeline
from detection.tls import TLSDetector, parse_client_hello
from evaluation import harness, synthetic

FIXTURE = os.path.join(os.path.dirname(__file__), 'fixtures', 'clienthello_example_com.hex')
T0 = 1_800_000_000.0


def flow(ts, src='192.168.1.50', dst='192.168.1.10', dport=80, proto='TCP', duration=1.0, out_b=1000, in_b=1000,
         start=None):
    return {'ts': ts, 'start': start or ts - duration, 'src': src, 'dst': dst, 'dport': dport, 'proto': proto,
            'duration': duration, 'forward_bytes': out_b, 'backward_bytes': in_b}


# ---------- flow detectors ----------

def test_port_scan_and_sweep():
    d = PortScanDetector()
    found = [f for i, p in enumerate(range(1, 40)) for f in d.observe(flow(T0 + i * 0.1, dport=p))]
    assert [f.kind for f in found] == ['port_scan'] and found[0].technique == 'T1046'
    found = [f for h in range(1, 30) for f in d.observe(flow(T0 + h, src='192.168.1.60', dst=f'192.168.1.{h}', dport=22))]
    assert [f.kind for f in found] == ['host_sweep']


def test_normal_browsing_is_not_a_scan():
    d = PortScanDetector()
    assert not [f for i in range(200) for f in d.observe(flow(T0 + i, dst=f'52.1.{i % 50}.1', dport=443))]


def test_brute_force_only_on_auth_ports_and_short_sessions():
    d = BruteForceDetector()
    hits = [f for i in range(15) for f in d.observe(flow(T0 + i * 3, dport=22, duration=1, out_b=1500, in_b=1500))]
    assert [f.kind for f in hits] == ['brute_force']
    d = BruteForceDetector()
    assert not [f for i in range(30) for f in d.observe(flow(T0 + i * 3, dport=443, duration=1))]
    assert not [f for i in range(30) for f in d.observe(flow(T0 + i * 3, dport=22, duration=60))]


def test_beaconing_regular_vs_irregular():
    d = BeaconingDetector()
    t, hits = T0, []
    for _ in range(12):
        hits += d.observe(flow(t, dst='185.10.10.10', dport=443))
        t += 60 * random.Random(int(t)).uniform(0.97, 1.03)
    assert [f.kind for f in hits] == ['beaconing'] and 55 < hits[0].details['period_s'] < 65
    rng = random.Random(1)
    d, t = BeaconingDetector(), T0
    for _ in range(30):
        assert not d.observe(flow(t, dst='185.10.10.11', dport=443))
        t += rng.expovariate(1 / 60)
    d = BeaconingDetector()
    assert not [f for k in range(20) for f in d.observe(flow(T0 + k * 64, dst='162.159.200.1', dport=123, proto='UDP'))]


def test_exfiltration_new_destination_vs_known_backup():
    d = ExfiltrationDetector(learning=600)
    d.observe(flow(T0, dst='203.0.113.5', dport=443))                       # backup server seen in learning
    assert not d.observe(flow(T0 + 100, dst='203.0.113.5', dport=443, out_b=900_000_000, in_b=100_000))
    hit = d.observe(flow(T0 + 4000, dst='45.33.1.2', dport=443, out_b=50_000_000, in_b=10_000))
    assert [f.kind for f in hit] == ['exfiltration'] and hit[0].details['new_destination']
    assert not d.observe(flow(T0 + 5000, dst='45.33.1.9', dport=443, out_b=50_000_000, in_b=40_000_000))  # symmetric


def test_new_device_after_learning():
    d = NewDeviceDetector(learning=100, clock=lambda: T0)
    assert d.observe(flow(T0 + 10, src='192.168.1.70')) == []
    assert [f.kind for f in d.observe(flow(T0 + 200, src='192.168.1.71'))] == ['new_device']
    assert d.observe(flow(T0 + 300, src='192.168.1.71')) == []


# ---------- DNS ----------

def test_dns_helpers():
    assert split_name('a.b.example.co.uk') == ('a.b', 'example.co.uk', 'example')
    assert split_name('www.google.com')[1] == 'google.com'
    assert entropy('aaaa') == 0 and entropy('abcd') == 2
    assert dga_score('google') == 0 and dga_score('wikipedia') < 0.5
    assert dga_score('xkq7vz2mfw9pj3') > 0.6


def test_dns_tunnel_and_dga():
    rng = random.Random(3)
    d = DNSDetector()
    hits = [f for i in range(80) for f in d.observe('192.168.1.80', ''.join(rng.choices('abcdefghijklmnopqrstuvwxyz234567', k=55)) + '.t.evil.com', ts=T0 + i * 0.2)]
    assert [f.kind for f in hits] == ['dns_tunnel'] and hits[0].details['domain'] == 'evil.com'
    d = DNSDetector()
    hits = [f for i in range(40) for f in d.observe('192.168.1.81', ''.join(rng.choices('qwrtypsdfghjklzxcvbnm0123456789', k=14)) + '.com', nxdomain=True, ts=T0 + i)]
    assert [f.kind for f in hits] == ['dga']


def test_dns_normal_names_do_not_alert():
    d = DNSDetector()
    names = ['www.google.com', 'outlook.office365.com', 'api.github.com', 'd3kx9z.cloudfront.net', 'fonts.gstatic.com']
    assert not [f for i in range(500) for f in d.observe('192.168.1.82', names[i % 5], nxdomain=i % 50 == 0, ts=T0 + i)]


# ---------- TLS ----------

def test_ja3_ja4_from_a_real_client_hello():
    payload = bytes.fromhex(open(FIXTURE).read().strip())
    h = parse_client_hello(payload)
    assert h['sni'] == 'example.com' and h['version'] == '13'
    assert h['ja3'] == '446fb8bd613d17e5d44bd3b288ac94ca'
    assert h['ja4'] == 't13d3012h2_1d37bd780c83_882d495ac381'
    assert h['alpn'] == ['h2', 'http/1.1']
    assert parse_client_hello(b'GET / HTTP/1.1\r\n') is None
    assert parse_client_hello(payload[:60]) is not None or True   # truncated input never raises


def test_tls_blocklist_and_missing_sni():
    payload = bytes.fromhex(open(FIXTURE).read().strip())
    h = parse_client_hello(payload)
    det = TLSDetector(blocklist={h['ja3']: 'test-malware'})
    kinds = {f.kind for f in det.observe('192.168.1.90', '93.184.216.34', h, ts=T0)}
    assert kinds == {'tls_known_bad'}
    det = TLSDetector(blocklist={})
    assert {f.kind for f in det.observe('192.168.1.90', '93.184.216.34', dict(h, sni=None), ts=T0)} == {'tls_no_sni'}


# ---------- fusion ----------

def F(kind, prob, sev=70, ts=T0, src='192.168.1.95'):
    return Finding(kind, src, sev, prob, 'T0000', f'{kind} evidence', ts=ts)


def test_fusion_confirmation_rules():
    fu = Fusion(clock=lambda: T0)
    fu.add_findings([F('beaconing', 0.8)])
    r = fu.fuse('192.168.1.95', now=T0)
    assert r['risk'] == 70 and r['confirmed'] is False          # one moderate signal is not enough
    fu.add_findings([F('dga', 0.85, 80, T0 + 1)])
    r = fu.fuse('192.168.1.95', now=T0 + 1)
    assert r['confirmed'] is True and r['risk'] == 85 and r['attack_type'] == 'dga'
    assert r['confidence'] > 0.95 and len(r['explanation']) == 2
    fu2 = Fusion(clock=lambda: T0)
    fu2.add_findings([F('port_scan', 0.95, 90)])
    assert fu2.fuse('192.168.1.95', now=T0)['confirmed'] is True   # one high-precision finding


def test_fusion_feedback_lowers_confidence():
    fu = Fusion(clock=lambda: T0, calibrate=lambda kind, prior: 0.2 if kind == 'port_scan' else prior)
    fu.add_findings([F('port_scan', 0.95, 90)])
    assert fu.fuse('192.168.1.95', now=T0)['confirmed'] is False


def test_fusion_explains_with_baseline_zscores():
    fu = Fusion(clock=lambda: T0)
    for i in range(100):
        fu.fuse('192.168.1.96', proto='TCP', features={'bytes': 1000 + i % 10}, now=T0)
    r = fu.fuse('192.168.1.96', engine_risk=40, engine_confidence=0.5, proto='TCP', features={'bytes': 90000}, now=T0)
    assert r['top_features'][0]['feature'] == 'bytes' and r['top_features'][0]['zscore'] > 10
    assert any('standard deviations above' in e for e in r['explanation'])


# ---------- feedback ----------

def test_feedback_calibration(tmp_path):
    s = feedback.FeedbackStore(str(tmp_path / 'fb.db'))
    for _ in range(18):
        s.add('beaconing', 'fp')
    s.add('beaconing', 'tp')
    s.add('beaconing', 'tp')
    assert s.calibrated('beaconing', 0.8) == pytest.approx((2 + 8) / 30)
    assert s.calibrated('dga', 0.85) == 0.85
    assert s.summary()[0] == {'kind': 'beaconing', 'true_positives': 2, 'false_positives': 18, 'precision': 0.1}
    with pytest.raises(ValueError):
        s.add('beaconing', 'maybe')


# ---------- autoencoder + registry ----------

def normal_rows(n, rng):
    return [{'bytes': rng.gauss(5000, 500), 'packets': rng.gauss(40, 4), 'duration': rng.gauss(2, 0.2)} for _ in range(n)]


@pytest.fixture(scope='module')
def trained():
    rng = random.Random(5)
    return autoencoder.FlowAutoencoder(['bytes', 'packets', 'duration']).fit(normal_rows(600, rng))


def test_autoencoder_scores_anomalies_higher(trained):
    rng = random.Random(6)
    normal = [trained.score(r) for r in normal_rows(200, rng)]
    weird = trained.score({'bytes': 5_000_000, 'packets': 2, 'duration': 0.01})
    assert sorted(normal)[int(0.95 * len(normal))] < 1.5 and weird > 5
    f = autoencoder.finding_for({'src': '192.168.1.97', 'features': {'bytes': 5_000_000, 'packets': 2, 'duration': 0.01}}, trained)
    assert f.kind == 'autoencoder_anomaly'


def test_registry_signing_stages_rollback(trained):
    v1 = registry.register('autoencoder', trained, {'auc': 0.9}, trained.features)
    v2 = registry.register('autoencoder', trained, {'auc': 0.95}, trained.features)
    assert registry.index()['autoencoder']['versions'][str(v2)]['stage'] == 'shadow'
    registry.set_stage('autoencoder', v1, 'active')
    registry.set_stage('autoencoder', v2, 'canary', percent=20)
    entry = registry.set_stage('autoencoder', v2, 'active')
    assert entry['active'] == str(v2) and entry['previous_active'] == str(v1)
    assert registry.rollback('autoencoder')['active'] == str(v1)
    with pytest.raises(ValueError):
        registry.set_stage('autoencoder', v1, 'retired')     # cannot demote the active version


def test_registry_refuses_tampered_models(trained):
    v = registry.register('autoencoder', trained)
    path = os.path.join(registry.registry_dir(), 'autoencoder', str(v), 'model.joblib')
    with open(path, 'ab') as f:
        f.write(b'tampered')
    with pytest.raises(registry.RegistryError, match='signed hash'):
        registry.load('autoencoder', v)
    with pytest.raises(registry.RegistryError):
        registry.set_stage('autoencoder', v, 'active')


def test_model_handle_hot_reload_and_canary(trained):
    v1 = registry.register('autoencoder', trained)
    registry.set_stage('autoencoder', v1, 'active')
    h = registry.ModelHandle('autoencoder', check_every=0)
    assert h.for_source('192.168.1.5')[:2] == ('active', str(v1))
    v2 = registry.register('autoencoder', trained)
    registry.set_stage('autoencoder', v2, 'canary', percent=50)
    time.sleep(0.01)
    os.utime(os.path.join(registry.registry_dir(), 'index.json'))
    stages = {h.for_source(f'192.168.1.{i}')[0] for i in range(100)}
    assert stages == {'active', 'canary'}
    assert h.shadow() is None or h.shadow()[0] == 'shadow'


def test_pipeline_uses_the_active_model(trained):
    v = registry.register('autoencoder', trained)
    registry.set_stage('autoencoder', v, 'active')
    pipe = DetectionPipeline(flow_detectors=[], calibrate=None)
    r = pipe.observe_flow({'src': '192.168.1.98', 'dst': '8.8.8.8', 'proto': 'TCP', 'ts': T0,
                           'features': {'bytes': 9_000_000, 'packets': 1, 'duration': 0.01}})
    assert r['attack_type'] == 'autoencoder_anomaly'


# ---------- evaluation gate ----------

def test_evaluation_meets_phase4_targets_on_synthetic_data():
    events, truth = synthetic.dataset(seed=21, hours=3)
    r = harness.evaluate(events, truth)
    assert r['detection_rate'] >= 0.9, r['classes']
    assert r['false_positive_rate'] <= 0.01
    assert r['latency_ms']['p99'] < 1000


def test_health_check_reconnects_are_not_brute_force():
    # live false positive: a container reconnecting to Redis every ~10 s
    d = BruteForceDetector()
    hits = [f for i in range(40) for f in d.observe(flow(T0 + i * 10, src='10.0.2.5', dst='10.0.2.2', dport=6379,
                                                          duration=0.05, out_b=300, in_b=300))]
    assert hits == []
    d = BruteForceDetector()                    # every ~4 s, 30 per 2 minutes, on a database port: still a client
    hits = [f for i in range(60) for f in d.observe(flow(T0 + i * 4 + (i % 3) * 0.05, src='10.0.2.5', dst='10.0.2.3',
                                                          dport=5432, duration=0.05, out_b=300, in_b=300))]
    assert hits == []
    d = BruteForceDetector()                    # sub-second guessing is caught even when regular
    hits = [f for i in range(12) for f in d.observe(flow(T0 + i * 0.5, src='10.0.2.6', dst='10.0.2.2', dport=22,
                                                          duration=0.05, out_b=300, in_b=300))]
    assert [f.kind for f in hits] == ['brute_force']
    rng = random.Random(9)                      # and slower, irregular guessing too
    d, t, hits = BruteForceDetector(), T0, []
    for _ in range(15):
        hits += d.observe(flow(t, src='10.0.2.7', dst='10.0.2.2', dport=3389, duration=1, out_b=1500, in_b=1500))
        t += rng.uniform(0.5, 5)
    assert [f.kind for f in hits] == ['brute_force']


def test_long_internal_sessions_are_not_suspicious():
    from types import SimpleNamespace
    from detection.attack_classifier import AttackClassifier
    c = AttackClassifier()
    base = dict(forward_bytes=1000, backward_bytes=1000, forward_packets=10, backward_packets=10, responder_port=6379)
    assert c.classify(SimpleNamespace(duration=600, responder_ip='10.0.2.2', **base), 3) != 'LONG_SUSPICIOUS_SESSION'
    assert c.classify(SimpleNamespace(duration=600, responder_ip='185.10.10.10', **base), 3) == 'LONG_SUSPICIOUS_SESSION'


def test_alert_explanation_labels_only_earlier_findings():
    from detection.fusion import alert_explanation as _alert_explanation
    old = {'kind': 'dga', 'evidence': 'random domains'}
    fused = {'findings': [old], 'new_findings': [],
             'explanation': ['random domains', 'bytes is 9.0 standard deviations above the TCP baseline for this hour']}
    assert _alert_explanation(fused) == ['bytes is 9.0 standard deviations above the TCP baseline for this hour',
                                         'earlier finding for this source: random domains']
    fused['new_findings'] = [old]
    assert _alert_explanation(fused)[0] == 'random domains'
