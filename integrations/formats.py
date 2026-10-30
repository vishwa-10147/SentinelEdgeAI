"""Alert encodings: syslog RFC 5424 (with structured data), ArcSight CEF, JSON."""
import json
import socket
from datetime import datetime, timezone

VENDOR, PRODUCT = 'SentinelEdgeAI', 'NDR'
# RFC 5424 private enterprise number placeholder for the SD-ID (32473 is reserved for documentation)
SD_ID = 'sentinel@32473'


def _version():
    try:
        import os
        with open(os.path.join(os.path.dirname(__file__), '..', 'VERSION')) as f:
            return f.read().strip()
    except OSError:
        return 'dev'


def severity_number(alert):
    """0-10 CEF severity from the 0-100 risk score."""
    return max(0, min(10, round((alert.get('final_risk_score') or 0) / 10)))


def syslog_severity(alert):
    risk = alert.get('final_risk_score') or 0
    return 2 if risk >= 90 else 3 if risk >= 75 else 4 if risk >= 50 else 5   # crit, err, warning, notice


def _sd_escape(value):
    return str(value).replace('\\', '\\\\').replace('"', '\\"').replace(']', '\\]')


def rfc5424(alert, hostname=None, facility=4):     # facility 4: security/authorization messages
    pri = facility * 8 + syslog_severity(alert)
    ts = datetime.now(timezone.utc).isoformat(timespec='milliseconds').replace('+00:00', 'Z')
    host = (hostname or socket.gethostname())[:255]
    fields = {
        'risk': alert.get('final_risk_score'), 'type': alert.get('attack_type'), 'src': alert.get('initiator_ip'),
        'dst': alert.get('responder_ip'), 'proto': alert.get('protocol'), 'technique': alert.get('mitre_technique_id'),
        'confidence': alert.get('confidence'),
    }
    sd = '[' + SD_ID + ''.join(f' {k}="{_sd_escape(v)}"' for k, v in fields.items() if v is not None) + ']'
    msg = f"{alert.get('severity', 'ALERT')} {alert.get('attack_type') or 'anomaly'} from {alert.get('initiator_ip')}"
    if alert.get('explanation'):
        msg += ': ' + '; '.join(alert['explanation'][:3])
    return f'<{pri}>1 {ts} {host} sentineledgeai - alert {sd} {msg}'


def _cef_header(value):
    return str(value).replace('\\', '\\\\').replace('|', '\\|')


def _cef_ext(value):
    return str(value).replace('\\', '\\\\').replace('=', '\\=').replace('\n', ' ').replace('\r', ' ')


def cef(alert):
    sig = alert.get('attack_type') or 'anomaly'
    name = f"{sig} detected"
    ext = {
        'src': alert.get('initiator_ip'), 'dst': alert.get('responder_ip'), 'proto': alert.get('protocol'),
        'cs1Label': 'mitreTechnique', 'cs1': alert.get('mitre_technique_id'),
        'cn1Label': 'riskScore', 'cn1': alert.get('final_risk_score'),
        'cfp1Label': 'confidence', 'cfp1': alert.get('confidence'),
        'msg': '; '.join((alert.get('explanation') or [])[:3]) or None,
        'rt': int(datetime.now(timezone.utc).timestamp() * 1000),
    }
    extension = ' '.join(f'{k}={_cef_ext(v)}' for k, v in ext.items() if v is not None)
    return (f'CEF:0|{_cef_header(VENDOR)}|{_cef_header(PRODUCT)}|{_cef_header(_version())}|'
            f'{_cef_header(sig)}|{_cef_header(name)}|{severity_number(alert)}|{extension}')


def json_line(alert):
    return json.dumps({'source': 'sentineledgeai', **alert}, default=str, separators=(',', ':'))
