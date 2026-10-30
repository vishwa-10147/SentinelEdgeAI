import hashlib
import http.server
import io
import json
import os
import socket
import socketserver
import sqlite3
import tarfile
import threading
import time

import pytest

import core.audit as audit
import core.auth as auth
from detection.detectors import IntelDetector
from integrations import dispatcher, formats, sinks, suricata
from intel import store as intel_store
from ops import backup
from reporting import pdf, summary
from utils import metrics

ALERT = {'severity': 'CRITICAL', 'attack_type': 'port_scan', 'initiator_ip': '192.168.1.66',
         'responder_ip': '192.168.1.10', 'protocol': 'TCP', 'final_risk_score': 92, 'confidence': 0.97,
         'mitre_technique_id': 'T1046', 'explanation': ['42 distinct ports probed on 192.168.1.10 within 60s']}


# ---------- formats ----------

def test_rfc5424_shape():
    msg = formats.rfc5424(dict(ALERT, attack_type='a"b]c'), hostname='pi')
    assert msg.startswith('<34>1 ') and ' pi sentineledgeai - alert [sentinel@32473 ' in msg
    assert 'type="a\\"b\\]c"' in msg and 'risk="92"' in msg
    assert msg.endswith('42 distinct ports probed on 192.168.1.10 within 60s')


def test_cef_escaping():
    msg = formats.cef(dict(ALERT, attack_type='x|y', explanation=['a=b\\c']))
    assert msg.startswith('CEF:0|SentinelEdgeAI|NDR|')
    assert '|x\\|y|x\\|y detected|9|' in msg
    assert 'msg=a\\=b\\\\c' in msg and 'src=192.168.1.66' in msg and 'cs1=T1046' in msg


# ---------- delivery (exit criterion: a SIEM receives alerts within 5 s) ----------

class _Collector:
    def __init__(self, kind):
        self.kind, self.received = kind, []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM if kind == 'udp' else socket.SOCK_STREAM)
        self.sock.bind(('127.0.0.1', 0))
        self.port = self.sock.getsockname()[1]
        if kind == 'tcp':
            self.sock.listen(1)
        threading.Thread(target=self._run, daemon=True).start()

    def _run(self):
        if self.kind == 'udp':
            while True:
                data, _ = self.sock.recvfrom(65535)
                self.received.append((time.time(), data.decode()))
        conn, _ = self.sock.accept()
        buf = b''
        while True:
            chunk = conn.recv(65535)
            if not chunk:
                return
            buf += chunk
            while b' ' in buf:
                length, _, rest = buf.partition(b' ')
                n = int(length)
                if len(rest) < n:
                    break
                self.received.append((time.time(), rest[:n].decode()))
                buf = rest[n:]


def _wait(pred, timeout=5):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if pred():
            return True
        time.sleep(0.01)
    return False


@pytest.mark.parametrize('transport, fmt', [('udp', 'rfc5424'), ('tcp', 'cef')])
def test_alert_reaches_syslog_collector_within_5_seconds(transport, fmt):
    col = _Collector(transport)
    dispatcher.save_config({'sinks': [{'type': 'syslog', 'name': 'siem', 'host': '127.0.0.1', 'port': col.port,
                                       'transport': transport, 'format': fmt, 'min_severity': 'HIGH'}]})
    d = dispatcher.get_dispatcher()
    sent_at = time.time()
    assert d.emit(ALERT)
    assert _wait(lambda: col.received), 'alert did not arrive'
    latency = col.received[0][0] - sent_at
    assert latency < 5
    body = col.received[0][1]
    assert ('CEF:0|SentinelEdgeAI' in body) if fmt == 'cef' else ('[sentinel@32473' in body)
    # below the sink's minimum severity: not sent
    d.emit(dict(ALERT, severity='LOW'))
    d.flush()
    assert len(col.received) == 1 and d.stats['sent'] >= 1


class _Hook(http.server.BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers['Content-Length']))
        _Hook.received.append((self.headers.get('X-Sentinel-Signature'), body))
        self.send_response(204)
        self.end_headers()

    def log_message(self, *a):
        pass


def test_signed_webhook():
    server = socketserver.TCPServer(('127.0.0.1', 0), _Hook)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f'http://127.0.0.1:{server.server_address[1]}/hook'
    try:
        with pytest.raises(ValueError, match='https'):
            sinks.build({'type': 'webhook', 'url': url})
        sink = sinks.build({'type': 'webhook', 'url': url, 'secret': 's3cret', 'allow_http': True})
        sink.send(ALERT)
        header, body = _Hook.received[-1]
        assert sinks.verify_webhook('s3cret', body, header)
        assert not sinks.verify_webhook('wrong', body, header)
        assert not sinks.verify_webhook('s3cret', body + b' ', header)
        assert json.loads(body)['attack_type'] == 'port_scan'
    finally:
        server.shutdown()


def test_jsonl_sink_rotates(tmp_path):
    path = str(tmp_path / 'alerts.jsonl')
    sink = sinks.build({'type': 'jsonl', 'path': path, 'max_bytes': 300})
    for _ in range(5):
        sink.send(ALERT)
    assert os.path.exists(path + '.1')
    assert json.loads(open(path).readline())['source'] == 'sentineledgeai'


def test_failed_delivery_is_counted_not_raised():
    d = dispatcher.Dispatcher(retries=1)
    d.sinks = [sinks.build({'type': 'syslog', 'host': '127.0.0.1', 'port': 1, 'transport': 'tcp'})]
    d.sinks[0].min_severity = 1
    d.emit(ALERT)
    d.flush()
    assert d.stats['failed'] == 1 and 'siem' not in (d.stats['last_error'] or '') and d.stats['last_error']


def test_config_validation_and_redaction():
    for bad in ({'type': 'pager'}, {'type': 'syslog'}, {'type': 'syslog', 'host': 'h', 'transport': 'carrier-pigeon'},
                {'type': 'slack', 'webhook_url': 'http://x'}):
        with pytest.raises(ValueError):
            dispatcher.save_config({'sinks': [bad]})
    cfg = {'sinks': [{'type': 'webhook', 'name': 'w', 'url': 'https://example.invalid/h', 'secret': 'top'}]}
    dispatcher.save_config(cfg)
    assert oct(os.stat(dispatcher.config_file()).st_mode & 0o777) == '0o600'
    assert dispatcher.redacted(dispatcher.load_config())['sinks'][0]['secret'] == '********'


def test_dispatcher_test_send():
    col = _Collector('udp')
    ok, msg, latency = dispatcher.get_dispatcher().test({'type': 'syslog', 'host': '127.0.0.1', 'port': col.port})
    assert ok and latency is not None
    assert _wait(lambda: col.received) and 'test_alert' in col.received[0][1]


# ---------- threat intelligence ----------

STIX = {'type': 'bundle', 'id': 'bundle--1', 'objects': [
    {'type': 'indicator', 'id': 'indicator--1', 'name': 'C2 server', 'pattern_type': 'stix',
     'pattern': "[ipv4-addr:value = '198.51.100.23']", 'valid_from': '2026-01-01T00:00:00Z'},
    {'type': 'indicator', 'id': 'indicator--2', 'pattern_type': 'stix', 'indicator_types': ['malicious-activity'],
     'pattern': "[domain-name:value = 'bad.example'] OR [ipv4-addr:value = '203.0.113.0/24']"},
    {'type': 'indicator', 'id': 'indicator--3', 'pattern_type': 'stix', 'revoked': True,
     'pattern': "[ipv4-addr:value = '192.0.2.200']"},
    {'type': 'indicator', 'id': 'indicator--4', 'pattern_type': 'stix', 'valid_until': '2001-01-01T00:00:00Z',
     'pattern': "[ipv4-addr:value = '192.0.2.201']"},
    {'type': 'indicator', 'id': 'indicator--5', 'pattern_type': 'sigma', 'pattern': 'title: x'},
]}


def test_stix_and_plain_parsing():
    got = {(i['type'], i['value']) for i in intel_store.parse_stix(STIX)}
    assert got == {('ip', '198.51.100.23'), ('domain', 'bad.example'), ('cidr', '203.0.113.0/24'), ('ip', '192.0.2.201')}
    plain = intel_store.parse_plain('# list\n198.51.100.7 ; c2\n10.0.0.0/8,internal\nEVIL.example.\n'
                                    '446fb8bd613d17e5d44bd3b288ac94ca\nnot an indicator\n')
    assert {(i['type'], i['value']) for i in plain} == {('ip', '198.51.100.7'), ('cidr', '10.0.0.0/8'),
                                                        ('domain', 'evil.example'), ('ja3', '446fb8bd613d17e5d44bd3b288ac94ca')}


def test_intel_matching_and_expiry():
    s = intel_store.get_store()
    s.replace_source('stix-feed', intel_store.parse_stix(STIX))
    assert s.match_ip('198.51.100.23') == ('stix-feed', 'C2 server')
    assert s.match_ip('203.0.113.77')[0] == 'stix-feed'
    assert s.match_ip('192.0.2.201') is None           # expired
    assert s.match_domain('www.bad.example.')[0] == 'stix-feed'
    assert s.match_domain('notbad.example') is None
    f = IntelDetector(s).observe({'src': '192.168.1.40', 'dst': '198.51.100.23', 'ts': time.time()})
    assert [x.kind for x in f] == ['threat_intel'] and f[0].src == '192.168.1.40'


def test_feed_update_keeps_old_data_on_failure(tmp_path):
    s = intel_store.get_store()
    feed = tmp_path / 'feed.txt'
    feed.write_text('198.51.100.90\n')
    s.add_feed('local', f'file://{feed}', 'plain')
    assert s.update_feeds() == {'local': 1}
    feed.unlink()
    assert s.update_feeds()['local'].startswith('error')
    assert s.match_ip('198.51.100.90')[0] == 'local'
    with pytest.raises(ValueError):
        s.add_feed('x', 'http://insecure.example/list', 'plain')


# ---------- Suricata ----------

def test_suricata_eve_tailing_with_rotation(tmp_path):
    eve = tmp_path / 'eve.json'
    eve.write_text(json.dumps({'event_type': 'flow', 'src_ip': '192.168.1.5'}) + '\n')
    got = []
    t = suricata.EveTailer(str(eve), got.append, poll=0.05)
    threading.Thread(target=t.run, kwargs={'from_start': True}, daemon=True).start()
    alert = {'event_type': 'alert', 'src_ip': '192.168.1.50', 'dest_ip': '198.51.100.1', 'dest_port': 4444,
             'alert': {'signature': 'ET MALWARE test', 'signature_id': 2000001, 'severity': 1,
                       'metadata': {'mitre_technique_id': ['T1071']}}}
    with open(eve, 'a') as f:
        f.write(json.dumps(alert) + '\n')
    assert _wait(lambda: got)
    assert got[0].kind == 'suricata' and got[0].severity == 85 and got[0].technique == 'T1071'
    os.rename(eve, str(eve) + '.1')                      # logrotate
    eve.write_text(json.dumps(dict(alert, src_ip='192.168.1.51')) + '\n')
    assert _wait(lambda: len(got) == 2)
    t.stop()
    assert got[1].src == '192.168.1.51'


# ---------- reports ----------

def test_summary_pdf_and_exports():
    now = time.time()
    alerts = [dict(ALERT, logged_at=time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(now - 3600))),
              dict(ALERT, initiator_ip='192.168.1.67', severity='HIGH', final_risk_score=60, attack_type='dga',
                   logged_at=time.strftime('%Y-%m-%dT%H:%M:%S+00:00', time.gmtime(now - 7200))),
              dict(ALERT, logged_at='2001-01-01T00:00:00+00:00')]
    audit.record('firewall_block', actor='otto', target='192.168.1.66')
    r = summary.build('daily', now=now, alerts=alerts)
    assert r['alerts'] == 2 and r['by_severity'] == {'CRITICAL': 1, 'HIGH': 1}
    assert r['top_sources'][0]['ip'] in ('192.168.1.66', '192.168.1.67') and r['enforcement'] == {'firewall_block': 1}
    assert r['audit_chain']['ok']
    data = summary.to_pdf(r)
    assert data.startswith(b'%PDF-1.4') and data.rstrip().endswith(b'%%EOF') and b'/Count 1' in data
    csv_text = summary.device_history_csv('192.168.1.66', alerts)
    assert csv_text.splitlines()[0].startswith('time,direction') and len(csv_text.splitlines()) == 3
    exp = summary.compliance_export(now - 86400, now + 1, alerts)
    assert len(exp['alerts']) == 2 and exp['audit'][0]['action'] == 'firewall_block'


def test_pdf_writer_multi_page():
    p = pdf.PDF()
    p.text(50, 50, 'héllo (world) \\ ✓')
    p.add_page()
    p.rect(10, 10, 100, 20, rgb=(1, 0, 0))
    out = p.output()
    assert b'/Count 2' in out and out.count(b' obj\n') >= 6


# ---------- metrics ----------

def test_engine_metrics_are_registered_and_exported():
    from prometheus_client import generate_latest
    metrics.init_metrics()
    metrics.FINDINGS.labels('port_scan').inc()
    metrics.DECISION_LATENCY.observe(0.002)
    metrics.collect_system()
    text = generate_latest(metrics.REGISTRY).decode()
    assert 'sentinel_findings_total{kind="port_scan"} 1.0' in text
    assert 'sentinel_decision_latency_seconds_bucket' in text and 'sentinel_system{resource="cpu_percent"}' in text


# ---------- backup / restore (exit criterion: full restore onto a fresh device) ----------

def _device(root):
    etc, state = root / 'etc', root / 'state'
    (etc / 'tls').mkdir(parents=True)
    (state / 'data' / 'brain').mkdir(parents=True)
    (etc / 'sentinel.env').write_text('DASHBOARD_API_KEY=abc\n')
    (etc / 'model_signing.key').write_text('signing-key\n')
    os.chmod(etc / 'model_signing.key', 0o640)
    (etc / 'tls' / 'key.pem').write_text('tls-key\n')
    (state / 'firewall_policy.json').write_text('{"response_mode": "alert"}')
    (state / 'data' / 'brain' / 'ca.key').write_text('ca\n')
    (state / 'data' / 'initial-admin-password').write_text('must not be backed up')
    store = auth.AuthStore(str(state / 'data' / 'auth.db'))
    store.create_user('admin', 'correct horse battery', 'admin')
    store.close()
    log = audit.AuditLog(str(state / 'data' / 'audit.db'))
    for i in range(5):
        log.record('firewall_block', actor='otto', target=f'198.51.100.{i}')
    head = log.verify()['head']
    log.close()
    return etc, state, head


def test_backup_restores_onto_a_fresh_device(tmp_path):
    etc, state, head = _device(tmp_path / 'old')
    archive = str(tmp_path / 'device.seab')
    manifest = backup.create(archive, 'a long passphrase', str(etc), str(state), '1.3.0')
    assert 'state/data/auth.db' in manifest['files'] and 'etc/tls/key.pem' in manifest['files']
    assert not any('initial-admin-password' in f for f in manifest['files'])
    assert b'signing-key' not in open(archive, 'rb').read()             # encrypted at rest
    new_etc, new_state = tmp_path / 'new' / 'etc', tmp_path / 'new' / 'state'
    restored = backup.restore(archive, 'a long passphrase', str(new_etc), str(new_state))
    assert len(restored) == len(manifest['files'])
    assert (new_etc / 'model_signing.key').read_text() == 'signing-key\n'
    assert oct(os.stat(new_etc / 'model_signing.key').st_mode & 0o777) == '0o640'
    assert sqlite3.connect(new_state / 'data' / 'auth.db').execute('PRAGMA integrity_check').fetchone()[0] == 'ok'
    store = auth.AuthStore(str(new_state / 'data' / 'auth.db'))
    assert store.verify_password('admin', 'correct horse battery')
    store.close()
    log = audit.AuditLog(str(new_state / 'data' / 'audit.db'))
    result = log.verify()
    log.close()
    assert result['ok'] and result['entries'] == 5 and result['head'] == head


def test_backup_rejects_wrong_passphrase_and_tampering(tmp_path):
    etc, state, _ = _device(tmp_path / 'old')
    archive = tmp_path / 'device.seab'
    backup.create(str(archive), 'a long passphrase', str(etc), str(state))
    with pytest.raises(backup.BackupError, match='wrong passphrase'):
        backup.restore(str(archive), 'another passphrase', str(tmp_path / 'e'), str(tmp_path / 's'))
    blob = bytearray(archive.read_bytes())
    blob[-5] ^= 0xFF
    archive.write_bytes(bytes(blob))
    with pytest.raises(backup.BackupError):
        backup.restore(str(archive), 'a long passphrase', str(tmp_path / 'e'), str(tmp_path / 's'))
    assert not (tmp_path / 'e').exists()
    with pytest.raises(backup.BackupError, match='12 characters'):
        backup.create(str(tmp_path / 'x.seab'), 'short', str(etc), str(state))


def test_backup_refuses_path_traversal(tmp_path):
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    buf = io.BytesIO()
    payload = b'pwned'
    with tarfile.open(fileobj=buf, mode='w:gz') as tar:
        info = tarfile.TarInfo('etc/../../escape.txt')
        info.size = len(payload)
        tar.addfile(info, io.BytesIO(payload))
        manifest = json.dumps({'format': 1, 'files': {'etc/../../escape.txt': {
            'sha256': hashlib.sha256(payload).hexdigest(), 'mode': 0o644, 'size': 5}}}).encode()
        info = tarfile.TarInfo('manifest.json')
        info.size = len(manifest)
        tar.addfile(info, io.BytesIO(manifest))
    salt, nonce = os.urandom(16), os.urandom(12)
    sealed = AESGCM(backup._key('a long passphrase', salt)).encrypt(nonce, buf.getvalue(), backup.MAGIC)
    evil = tmp_path / 'evil.seab'
    evil.write_bytes(backup.MAGIC + salt + nonce + sealed)
    with pytest.raises(backup.BackupError, match='unsafe path'):
        backup.restore(str(evil), 'a long passphrase', str(tmp_path / 'etc'), str(tmp_path / 'state'))
    assert not (tmp_path / 'escape.txt').exists()
