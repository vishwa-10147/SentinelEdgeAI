"""Optional Suricata on the sensor: its eve.json alerts become another detector input.

The engine follows SENTINEL_SURICATA_EVE (default /var/log/suricata/eve.json)
when the file exists, survives log rotation, and turns every 'alert' event
into a Finding that fusion combines with SentinelEdgeAI's own detections.
"""
import json
import logging
import os
import threading
import time

from detection.detectors import Finding

logger = logging.getLogger('sentinel.suricata')
DEFAULT_EVE = '/var/log/suricata/eve.json'
# Suricata severity 1 is the most serious
SEVERITY = {1: 85, 2: 65, 3: 45}


def finding_from_eve(event):
    if event.get('event_type') != 'alert' or not event.get('src_ip'):
        return None
    alert = event.get('alert') or {}
    sev = SEVERITY.get(int(alert.get('severity') or 3), 45)
    meta = alert.get('metadata') or {}
    technique = (meta.get('mitre_technique_id') or ['T0000'])[0]
    return Finding('suricata', event['src_ip'], sev, 0.8 if sev >= 65 else 0.6, technique,
                   f"Suricata: {alert.get('signature', 'alert')} (sid {alert.get('signature_id')})",
                   {'target': event.get('dest_ip'), 'dport': event.get('dest_port'), 'sid': alert.get('signature_id'),
                    'category': alert.get('category'), 'proto': event.get('proto')})


class EveTailer:
    def __init__(self, path=None, on_finding=None, poll=0.5):
        self.path = path or os.environ.get('SENTINEL_SURICATA_EVE', DEFAULT_EVE)
        self.on_finding = on_finding
        self.poll = poll
        self._stop = threading.Event()
        self.count = 0

    def read_new(self, handle):
        out = []
        while True:
            line = handle.readline()
            if not line:
                break
            if not line.endswith('\n'):
                handle.seek(handle.tell() - len(line))   # partial line: wait for the rest
                break
            try:
                f = finding_from_eve(json.loads(line))
            except (ValueError, TypeError):
                continue
            if f:
                out.append(f)
        return out

    def run(self, from_start=False):
        handle, inode = None, None
        while not self._stop.is_set():
            try:
                st = os.stat(self.path)
                if handle is None or st.st_ino != inode or st.st_size < handle.tell():
                    if handle:
                        handle.close()
                    handle = open(self.path, 'r', encoding='utf-8', errors='replace')
                    inode = st.st_ino
                    if not from_start and self.count == 0:
                        handle.seek(0, os.SEEK_END)      # only new alerts after start-up
                    from_start = True
                for f in self.read_new(handle):
                    self.count += 1
                    if self.on_finding:
                        self.on_finding(f)
            except OSError:
                pass
            self._stop.wait(self.poll)

    def stop(self):
        self._stop.set()


def start_in_engine(alert_logger=None):
    """Follow eve.json in a background thread when Suricata is installed."""
    path = os.environ.get('SENTINEL_SURICATA_EVE', DEFAULT_EVE)
    if not os.path.exists(path):
        return None

    def handle(f):
        from detection.pipeline import get_pipeline
        get_pipeline().fusion.add_findings([f])
        if alert_logger and f.severity >= 50:
            alert_logger.log({'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'), 'initiator_ip': f.src,
                              'responder_ip': f.details.get('target'), 'protocol': f.details.get('proto'),
                              'final_risk_score': f.severity, 'severity': 'CRITICAL' if f.severity >= 75 else 'HIGH',
                              'attack_type': 'suricata', 'confidence': f.probability,
                              'mitre_technique_id': f.technique, 'explanation': [f.evidence],
                              'findings': [f.as_dict()]})

    tailer = EveTailer(path, handle)
    threading.Thread(target=tailer.run, daemon=True, name='suricata-eve').start()
    logger.warning('following Suricata alerts in %s', path)
    return tailer
