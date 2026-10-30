"""Destinations for alerts. Each sink has send(alert) and raises on failure."""
import hashlib
import hmac
import json
import os
import smtplib
import socket
import ssl
import time
from email.message import EmailMessage

import requests

from integrations import formats


class Sink:
    kind = 'base'

    def __init__(self, config):
        self.config = config
        self.name = config.get('name') or self.kind

    def send(self, alert):
        raise NotImplementedError

    def close(self):
        pass


class SyslogSink(Sink):
    """RFC 5424 or CEF over UDP, TCP (octet-counted framing, RFC 6587) or TLS (RFC 5425)."""
    kind = 'syslog'

    def __init__(self, config):
        super().__init__(config)
        self.host, self.port = config['host'], int(config.get('port', 514))
        self.transport = config.get('transport', 'udp')
        self.format = config.get('format', 'rfc5424')
        self._sock = None

    def _message(self, alert):
        if self.format == 'cef':
            pri = 4 * 8 + formats.syslog_severity(alert)
            return f'<{pri}>1 - {socket.gethostname()} sentineledgeai - alert - {formats.cef(alert)}'
        return formats.rfc5424(alert)

    def _connect(self):
        sock = socket.create_connection((self.host, self.port), timeout=5)
        if self.transport == 'tls':
            ctx = ssl.create_default_context(cafile=self.config.get('ca_file'))
            sock = ctx.wrap_socket(sock, server_hostname=self.host)
        return sock

    def send(self, alert):
        data = self._message(alert).encode('utf-8')
        if self.transport == 'udp':
            with socket.socket(socket.AF_INET6 if ':' in self.host else socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.sendto(data, (self.host, self.port))
            return
        frame = f'{len(data)} '.encode() + data
        for attempt in range(2):
            try:
                if self._sock is None:
                    self._sock = self._connect()
                self._sock.sendall(frame)
                return
            except OSError:
                self.close()
                if attempt:
                    raise

    def close(self):
        if self._sock is not None:
            try:
                self._sock.close()
            finally:
                self._sock = None


class WebhookSink(Sink):
    """HTTPS POST of the alert JSON, signed: X-Sentinel-Signature: t=<ts>,v1=<hex HMAC-SHA256(secret, "<ts>.<body>")>."""
    kind = 'webhook'

    def send(self, alert):
        body = formats.json_line(alert).encode()
        ts = str(int(time.time()))
        headers = {'Content-Type': 'application/json', 'User-Agent': 'SentinelEdgeAI'}
        secret = self.config.get('secret')
        if secret:
            mac = hmac.new(secret.encode(), ts.encode() + b'.' + body, hashlib.sha256).hexdigest()
            headers['X-Sentinel-Signature'] = f't={ts},v1={mac}'
        r = requests.post(self.config['url'], data=body, headers=headers, timeout=5,
                          verify=self.config.get('ca_file') or True)
        r.raise_for_status()


def verify_webhook(secret, body, header, tolerance=300, now=None):
    """Receiver-side check of X-Sentinel-Signature (also used in tests)."""
    try:
        parts = dict(p.split('=', 1) for p in header.split(','))
        ts = int(parts['t'])
    except (ValueError, KeyError):
        return False
    if abs((now or time.time()) - ts) > tolerance:
        return False
    expected = hmac.new(secret.encode(), str(ts).encode() + b'.' + body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts.get('v1', ''))


class JsonlSink(Sink):
    """One JSON object per line, for Filebeat, Splunk Universal Forwarder, Vector, Fluent Bit."""
    kind = 'jsonl'

    def send(self, alert):
        path = self.config.get('path') or 'logs/alerts.jsonl'
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        max_bytes = int(self.config.get('max_bytes', 50_000_000))
        if os.path.exists(path) and os.path.getsize(path) > max_bytes:
            os.replace(path, path + '.1')
        with open(path, 'a', encoding='utf-8') as f:
            f.write(formats.json_line(alert) + '\n')


def _summary(alert):
    lines = [f"*{alert.get('severity', 'ALERT')}* {alert.get('attack_type') or 'anomaly'} "
             f"from {alert.get('initiator_ip')} (risk {alert.get('final_risk_score')})"]
    lines += [f'• {e}' for e in (alert.get('explanation') or [])[:3]]
    return '\n'.join(lines)


class SlackSink(Sink):
    kind = 'slack'

    def send(self, alert):
        requests.post(self.config['webhook_url'], json={'text': _summary(alert)}, timeout=5).raise_for_status()


class TeamsSink(Sink):
    kind = 'teams'

    def send(self, alert):
        card = {'@type': 'MessageCard', '@context': 'https://schema.org/extensions',
                'summary': f"SentinelEdgeAI {alert.get('attack_type')}", 'themeColor': 'D97706',
                'text': _summary(alert).replace('\n', '<br>')}
        requests.post(self.config['webhook_url'], json=card, timeout=5).raise_for_status()


class EmailSink(Sink):
    kind = 'email'

    def send(self, alert):
        msg = EmailMessage()
        msg['Subject'] = f"[SentinelEdgeAI] {alert.get('severity')} {alert.get('attack_type') or 'alert'} " \
                         f"from {alert.get('initiator_ip')}"
        msg['From'] = self.config['from']
        msg['To'] = ', '.join(self.config['to']) if isinstance(self.config['to'], list) else self.config['to']
        msg.set_content(_summary(alert).replace('*', '') + '\n\n' + json.dumps(alert, indent=2, default=str))
        port = int(self.config.get('port', 587))
        with smtplib.SMTP(self.config['host'], port, timeout=10) as smtp:
            if self.config.get('starttls', True):
                smtp.starttls(context=ssl.create_default_context())
            if self.config.get('username'):
                smtp.login(self.config['username'], os.environ.get(self.config.get('password_env', ''), '')
                           or self.config.get('password', ''))
            smtp.send_message(msg)


SINKS = {cls.kind: cls for cls in (SyslogSink, WebhookSink, JsonlSink, SlackSink, TeamsSink, EmailSink)}
REQUIRED = {'syslog': ('host',), 'webhook': ('url',), 'jsonl': (), 'slack': ('webhook_url',),
            'teams': ('webhook_url',), 'email': ('host', 'from', 'to')}


def build(config):
    kind = config.get('type')
    if kind not in SINKS:
        raise ValueError(f"unknown sink type {kind!r}; use one of {', '.join(SINKS)}")
    missing = [k for k in REQUIRED[kind] if not config.get(k)]
    if missing:
        raise ValueError(f"{kind} sink needs: {', '.join(missing)}")
    if kind == 'syslog' and config.get('transport', 'udp') not in ('udp', 'tcp', 'tls'):
        raise ValueError('syslog transport must be udp, tcp or tls')
    if kind == 'syslog' and config.get('format', 'rfc5424') not in ('rfc5424', 'cef'):
        raise ValueError('syslog format must be rfc5424 or cef')
    if kind in ('webhook', 'slack', 'teams'):
        url = config.get('url') or config.get('webhook_url')
        if not str(url).startswith('https://') and not config.get('allow_http'):
            raise ValueError(f'{kind} URL must use https://')
    return SINKS[kind](config)
