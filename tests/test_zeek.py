"""Zeek as a sensor engine: its JSON logs feed the detectors (Phase 9)."""
import json

from detection.lateral import LateralDetector
from detection.pipeline import DetectionPipeline
from integrations.zeek import ZeekFeeder, ZeekFollower, conn_record

T0 = 1_700_000_000.0
WEEK = 7 * 86400


def pipe(**kw):
    return DetectionPipeline(models=False, clock=lambda: T0, **kw)


def conn(src, dst, dport, ts, **kw):
    rec = {'ts': ts, 'uid': 'C1', 'id.orig_h': src, 'id.orig_p': 50000, 'id.resp_h': dst, 'id.resp_p': dport,
           'proto': 'tcp', 'duration': 0.01, 'orig_bytes': 0, 'resp_bytes': 0, 'orig_pkts': 1, 'resp_pkts': 1,
           'conn_state': 'REJ'}
    rec.update(kw)
    return rec


def test_conn_record_mapping():
    r = conn_record(conn('10.0.0.5', '10.0.0.9', 22, T0, duration=2.5, orig_bytes=100, resp_bytes=900, service='ssh'))
    assert r['src'] == '10.0.0.5' and r['dport'] == 22 and r['proto'] == 'TCP'
    assert r['ts'] == T0 + 2.5 and r['start'] == T0 and r['backward_bytes'] == 900 and r['service'] == 'ssh'
    assert conn_record({'ts': T0}) is None


def test_conn_log_drives_flow_detectors():
    feeder = ZeekFeeder(pipe())
    found = []
    for port in range(1, 30):
        found += feeder.feed('conn', conn('10.0.0.66', '10.0.0.9', port, T0 + port * 0.1))
    assert 'port_scan' in {f.kind for f in found}


def test_dns_notice_and_cert_status():
    p = pipe()
    feeder = ZeekFeeder(p)
    nx = [feeder.feed('dns', {'ts': T0 + i, 'id.orig_h': '10.0.0.7', 'query': f'x{i}q8z3k1v0p.example.com',
                              'rcode_name': 'NXDOMAIN'}) for i in range(60)]
    assert any(nx)
    [n] = feeder.feed('notice', {'ts': T0, 'note': 'Scan::Port_Scan', 'msg': '10.0.0.66 scanned 30 ports',
                                 'src': '10.0.0.66'})
    assert n.kind == 'zeek_notice' and n.technique == 'T1046'
    ssl = {'ts': T0, 'id.orig_h': '10.0.0.7', 'id.resp_h': '93.184.216.34', 'server_name': 'shop.example',
           'validation_status': 'self signed certificate'}
    [c] = feeder.feed('ssl', ssl)
    assert c.kind == 'tls_cert_anomaly' and c.details['reasons'] == ['self-signed']
    assert feeder.feed('ssl', dict(ssl, **{'id.resp_h': '10.0.0.1'})) == []          # internal server
    assert p.fusion.fuse('10.0.0.66', 0, 0, 'TCP', None, now=T0 + 1)['attack_type'] == 'zeek_notice'


def test_windows_logs_feed_lateral_movement():
    feeder = ZeekFeeder(pipe(lateral=LateralDetector(clock=lambda: T0 - WEEK - 1, ntlm_hosts=3)))
    ws = '10.0.0.20'
    [share] = feeder.feed('smb_mapping', {'ts': T0, 'id.orig_h': ws, 'id.resp_h': '10.0.0.5',
                                          'path': '\\\\FS01\\ADMIN$', 'share_type': 'DISK'})
    assert share.kind == 'admin_share'
    [svc] = feeder.feed('dce_rpc', {'ts': T0, 'id.orig_h': ws, 'id.resp_h': '10.0.0.5', 'endpoint': 'svcctl',
                                    'operation': 'CreateServiceW'})
    assert svc.kind == 'remote_service'
    out = [feeder.feed('ntlm', {'ts': T0 + i, 'id.orig_h': ws, 'id.resp_h': f'10.0.0.{30 + i}'}) for i in range(3)]
    assert out[-1][0].kind == 'ntlm_fanout'
    assert feeder.feed('kerberos', {'ts': T0, 'id.orig_h': ws, 'id.resp_h': '10.0.0.2', 'request_type': 'TGS'}) == []


def test_ot_logs_feed_ot_detector():
    feeder = ZeekFeeder(pipe())
    [stop] = feeder.feed('dnp3', {'ts': T0, 'id.orig_h': '10.1.0.5', 'id.resp_h': '10.1.0.9',
                                  'fc_request': 'COLD_RESTART'})
    assert stop.kind == 'ot_device_stop'
    assert feeder.feed('modbus', {'ts': T0, 'id.orig_h': '10.1.0.5', 'id.resp_h': '10.1.0.10',
                                  'func': 'READ_HOLDING_REGISTERS'}) == []
    plc = next(a for a in feeder.pipe.ot.assets() if a['ip'] == '10.1.0.10')
    assert plc['masters'][0]['functions'] == ['read holding registers']
    assert feeder.feed('modbus', {'func': 'NOT_A_FUNCTION'}) == [] and feeder.feed('nope', {}) == []


def test_follower_reads_new_lines_and_survives_rotation(tmp_path):
    got = []
    follower = ZeekFollower(str(tmp_path), pipeline=pipe(), on_finding=got.append, poll=0.01, from_start=True)
    notice = tmp_path / 'notice.log'
    notice.write_text(json.dumps({'ts': T0, 'note': 'Scan::Address_Scan', 'msg': 'm', 'src': '10.0.0.1'}) + '\n'
                      + '{"ts": 1, "note": "partial')                                  # unfinished line
    follower.step()
    assert [f.details['note'] for f in got] == ['Scan::Address_Scan']
    notice.rename(tmp_path / 'notice.old.log')                                         # Zeek rotates
    notice.write_text(json.dumps({'ts': T0, 'note': 'SSH::Password_Guessing', 'msg': 'm', 'src': '10.0.0.2'}) + '\n')
    follower.step()
    assert [f.details['note'] for f in got] == ['Scan::Address_Scan', 'SSH::Password_Guessing']
    assert follower.feeder.counts['notice'] == 2
