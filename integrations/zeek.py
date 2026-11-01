"""Zeek as a sensor engine (Phase 9): its JSON logs feed SentinelEdgeAI's detectors.

On a busy link, Zeek (C++, multi-worker) can do the capture and protocol
parsing instead of the Python capture path. The engine follows Zeek's logs
in SENTINEL_ZEEK_LOGS (default /opt/zeek/logs/current; Zeek must write JSON:
`redef LogAscii::use_json = T;`) and feeds each log to the matching detector,
so findings are fused and explained exactly like the engine's own:

    conn.log                  finished connections  -> flow detectors (scan, brute force, beaconing,
                                                       exfiltration, new device, intel, admin fan-out)
    dns.log                   queries               -> DNS tunnelling / DGA / intel
    ssl.log                   SNI, JA3/JA4/JA4S (when the JA4 package is loaded), certificate
                              validation status    -> TLS detector, certificate anomalies
    smb_mapping.log, ntlm.log, dce_rpc.log, kerberos.log  -> lateral movement detector
    modbus.log, dnp3.log      OT requests           -> OT detector (per-controller baselines)
    notice.log                Zeek's own notices    -> findings (like Suricata alerts)

SENTINEL_CAPTURE=zeek makes Zeek the only engine (the Python capture is not
started); otherwise the logs are followed alongside it when the directory exists.
Only the first start reads from the end of each log: nothing old is replayed.
"""
import logging
import os
import threading
import time

from detection.detectors import Cooldown, Finding, is_external
from detection.ot import DNP3_FUNCTIONS, DNP3_STOPS, DNP3_WRITES, MODBUS_FUNCTIONS, MODBUS_WRITES, _msg
from integrations.suricata import EveTailer

logger = logging.getLogger('sentinel.zeek')
DEFAULT_DIR = '/opt/zeek/logs/current'
LOGS = ('conn', 'dns', 'ssl', 'notice', 'smb_mapping', 'ntlm', 'dce_rpc', 'kerberos', 'modbus', 'dnp3')

MODBUS_NAMES = {'READ_COILS': 1, 'READ_DISCRETE_INPUTS': 2, 'READ_HOLDING_REGISTERS': 3, 'READ_INPUT_REGISTERS': 4,
                'WRITE_SINGLE_COIL': 5, 'WRITE_SINGLE_REGISTER': 6, 'READ_EXCEPTION_STATUS': 7, 'DIAGNOSTICS': 8,
                'GET_COMM_EVENT_COUNTER': 11, 'WRITE_MULTIPLE_COILS': 15, 'WRITE_MULTIPLE_REGISTERS': 16,
                'REPORT_SLAVE_ID': 17, 'READ_FILE_RECORD': 20, 'WRITE_FILE_RECORD': 21, 'MASK_WRITE_REGISTER': 22,
                'READ_WRITE_MULTIPLE_REGISTERS': 23, 'READ_FIFO_QUEUE': 24, 'ENCAP_INTERFACE_TRANSPORT': 43}
DNP3_NAMES = {name.upper().replace(' ', '_'): code for code, name in DNP3_FUNCTIONS.items()}
DNP3_NAMES.update({'DIRECT_OPERATE_NR': 6, 'IMMED_FREEZE': 7, 'FREEZE_CLEAR': 9, 'INIT_DATA': 15,
                   'INIT_APPL': 16, 'START_APPL': 17, 'STOP_APPL': 18, 'DELAY_MEASURE': 23,
                   'ACTIVATE_CONFIG': 31})
RPC_ENDPOINTS = {'svcctl': 'svcctl', 'atsvc': 'atsvc', 'itaskschedulerservice': 'taskscheduler',
                 'drsuapi': 'drsuapi', 'winreg': 'winreg'}
CERT_STATUS = (('self signed', 'self-signed'), ('expired', 'expired'), ('not yet valid', 'not valid yet'),
               ('unable to get local issuer', 'issuer unknown'))
NOTICE_TECHNIQUES = (('Scan::', 'T1046', 60), ('SSH::Password_Guessing', 'T1110', 70), ('SSL::', 'T1573', 40),
                     ('Weird::', 'T0000', 35))


def default_dir():
    return os.environ.get('SENTINEL_ZEEK_LOGS', DEFAULT_DIR)


def _ids(rec):
    return rec.get('id.orig_h'), rec.get('id.resp_h'), rec.get('id.orig_p'), rec.get('id.resp_p')


def conn_record(rec):
    """A Zeek conn.log entry as the flow record the detectors take (common.protocol.flow_record)."""
    src, dst, sport, dport = _ids(rec)
    if not src or not dst:
        return None
    start = float(rec.get('ts') or 0)
    duration = float(rec.get('duration') or 0)
    out = {'src': src, 'dst': dst, 'sport': int(sport or 0), 'dport': int(dport or 0),
           'proto': str(rec.get('proto') or 'other').upper(), 'ts': start + duration, 'start': start,
           'duration': duration, 'forward_bytes': int(rec.get('orig_bytes') or 0),
           'backward_bytes': int(rec.get('resp_bytes') or 0), 'forward_packets': int(rec.get('orig_pkts') or 0),
           'backward_packets': int(rec.get('resp_pkts') or 0), 'engine': 'zeek'}
    if rec.get('service'):
        out['service'] = rec['service']
    return out


class ZeekFeeder:
    """Turns one Zeek log entry into detector calls on a DetectionPipeline. Returns new findings."""

    def __init__(self, pipeline):
        self.pipe = pipeline
        self.cooldown = Cooldown(1800)
        self.counts = {name: 0 for name in LOGS}

    def feed(self, log, rec):
        handler = getattr(self, '_' + log, None)
        if handler is None or not isinstance(rec, dict):
            return []
        self.counts[log] = self.counts.get(log, 0) + 1
        try:
            return handler(rec) or []
        except (TypeError, ValueError, KeyError):
            return []

    def _conn(self, rec):
        record = conn_record(rec)
        if record is None:
            return []
        fused = self.pipe.observe_flow(record)
        return [Finding(**{k: f[k] for k in ('kind', 'src', 'severity', 'probability', 'technique', 'evidence',
                                              'details', 'ts')}) for f in fused.get('new_findings', [])]

    def _dns(self, rec):
        src, query = rec.get('id.orig_h'), rec.get('query')
        if not src or not query:
            return []
        return self.pipe.observe_dns(src, query, nxdomain=rec.get('rcode_name') == 'NXDOMAIN', ts=rec.get('ts'))

    def _ssl(self, rec):
        src, dst, _, _ = _ids(rec)
        ts = rec.get('ts') or time.time()
        out = []
        tls = self.pipe.tls
        sni = rec.get('server_name')
        if rec.get('ja4'):
            hello = {'ja3': rec.get('ja3') or '', 'ja4': rec['ja4'], 'sni': sni, 'alpn': [],
                     'version': rec.get('version')}
            with self.pipe._lock:
                out += tls.observe(src, dst, hello, ts)
        elif sni:
            tls.sni[(src, dst)] = sni
        ja4s = rec.get('ja4s')
        if ja4s:
            label = tls.blocklist.get(ja4s.lower())
            if label and tls.cooldown.ready(('tls_blocklist', dst, ja4s), ts):
                out.append(Finding('tls_known_bad', src, 90, 0.9, 'T1071.001',
                                   f'TLS server {dst} answers with fingerprint {ja4s} on the blocklist ({label})',
                                   {'fingerprint': ja4s, 'label': label, 'target': dst}, ts=ts))
        status = (rec.get('validation_status') or '').lower()
        with self.pipe._lock:
            return self._ssl_cert(out, src, dst, sni, status, ts)

    def _ssl_cert(self, out, src, dst, sni, status, ts):
        reasons = [r for key, r in CERT_STATUS if key in status]
        if reasons and is_external(dst) and self.cooldown.ready(('tls_cert', dst, status), ts):
            out.append(Finding('tls_cert_anomaly', src, min(70, 35 + 10 * len(reasons)), 0.35, 'T1573',
                               f'certificate of {dst}' + (f' ({sni})' if sni else '') + ': ' + '; '.join(reasons),
                               {'target': dst, 'sni': sni, 'reasons': reasons, 'source': 'zeek'}, ts=ts))
        return self.pipe._accept(out)

    def _notice(self, rec):
        src = rec.get('src') or rec.get('id.orig_h')
        if not src:
            return []
        note = rec.get('note') or 'Notice'
        technique, severity = 'T0000', 50
        for prefix, t, sev in NOTICE_TECHNIQUES:
            if note.startswith(prefix):
                technique, severity = t, sev
                break
        f = Finding('zeek_notice', src, severity, 0.6, technique, f'Zeek {note}: {rec.get("msg", "")}'.strip(),
                    {'target': rec.get('dst') or rec.get('id.resp_h'), 'note': note, 'sub': rec.get('sub')},
                    ts=rec.get('ts') or time.time())
        return self.pipe.accept([f])

    def _lateral(self, method, *args):
        with self.pipe._lock:
            return self.pipe._accept(getattr(self.pipe.lateral, method)(*args))

    def _smb_mapping(self, rec):
        src, dst, _, _ = _ids(rec)
        share = (rec.get('path') or '').rstrip('\\').rsplit('\\', 1)[-1].upper() or None
        msg = {'command': 'tree connect', 'share': share, 'ntlm': False, 'rpc': []}
        return self._lateral('observe_smb', src, dst, [msg], rec.get('ts'))

    def _ntlm(self, rec):
        src, dst, _, _ = _ids(rec)
        msg = {'command': 'session setup', 'share': None, 'ntlm': True, 'rpc': []}
        return self._lateral('observe_smb', src, dst, [msg], rec.get('ts'))

    def _dce_rpc(self, rec):
        src, dst, _, _ = _ids(rec)
        iface = RPC_ENDPOINTS.get((rec.get('endpoint') or '').lower())
        return self._lateral('observe_rpc', src, dst, [iface], rec.get('ts')) if iface else []

    def _kerberos(self, rec):
        src, dst, _, _ = _ids(rec)
        kind = {'AS': 'as-req', 'TGS': 'tgs-req'}.get(rec.get('request_type'))
        return self._lateral('observe_kerberos', src, dst, kind, rec.get('ts')) if kind else []

    def _ot(self, rec, protocol, msg):
        src, dst, _, _ = _ids(rec)
        with self.pipe._lock:
            return self.pipe._accept(self.pipe.ot.observe(src, dst, protocol, [msg], rec.get('ts')))

    def _modbus(self, rec):
        code = MODBUS_NAMES.get(str(rec.get('func') or '').upper())
        if code is None:
            return []
        return self._ot(rec, 'modbus', _msg('modbus', code, MODBUS_FUNCTIONS[code], code in MODBUS_WRITES))

    def _dnp3(self, rec):
        code = DNP3_NAMES.get(str(rec.get('fc_request') or '').upper())
        if code is None:
            return []
        return self._ot(rec, 'dnp3', _msg('dnp3', code, DNP3_FUNCTIONS[code], code in DNP3_WRITES,
                                          DNP3_STOPS.get(code)))


class ZeekFollower:
    """Follows every known log in a Zeek log directory (rotation-safe) and feeds them."""

    def __init__(self, directory=None, pipeline=None, on_finding=None, poll=0.5, from_start=False):
        self.directory = directory or default_dir()
        if pipeline is None:
            from detection.pipeline import get_pipeline
            pipeline = get_pipeline()
        self.feeder = ZeekFeeder(pipeline)
        self.on_finding = on_finding
        self.poll = poll
        self._stop = threading.Event()
        self.tailers = [EveTailer(os.path.join(self.directory, f'{name}.log'), self._handler(name), poll,
                                  parse=lambda rec: rec, from_start=from_start) for name in LOGS]

    def _handler(self, log):
        def handle(rec):
            for f in self.feeder.feed(log, rec):
                if self.on_finding:
                    self.on_finding(f)
        return handle

    def step(self):
        for t in self.tailers:
            t.step()

    def run(self):
        while not self._stop.is_set():
            self.step()
            self._stop.wait(self.poll)

    def stop(self):
        self._stop.set()


def start_in_engine(alert_logger=None, required=False):
    """Follow Zeek's logs in a background thread when the directory exists (or Zeek is the engine)."""
    directory = default_dir()
    if not os.path.isdir(directory) and not required:
        return None

    def on_finding(f):
        if alert_logger and f.severity >= 50:
            alert_logger.log({'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'initiator_ip': f.src,
                              'responder_ip': f.details.get('target'),
                              'protocol': (f.details.get('protocol') or 'zeek').upper(),
                              'final_risk_score': f.severity, 'severity': 'CRITICAL' if f.severity >= 75 else 'HIGH',
                              'attack_type': f.kind, 'confidence': f.probability, 'mitre_technique_id': f.technique,
                              'explanation': [f.evidence], 'findings': [f.as_dict()], 'engine': 'zeek'})

    follower = ZeekFollower(directory, on_finding=on_finding)
    threading.Thread(target=follower.run, daemon=True, name='zeek-logs').start()
    logger.warning('following Zeek logs in %s', directory)
    return follower
