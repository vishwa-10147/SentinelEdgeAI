"""Quarantine VLAN through managed-switch APIs (Phase 3, optional).

When enabled, quarantining a device (from the playbook, the console, the CLI or a
fleet remote action) also moves its switch port to the quarantine VLAN, so the
device is isolated at the switch even for traffic that never crosses the
appliance; releasing or expiring the quarantine, an operator rollback and the
watchdog's fail-open put the port back on the VLAN it had. The firewall
quarantine is applied either way: a switch that cannot be reached never stops it.

The port is found from the device's MAC (enforcement.identity) in the switches'
MAC tables. A port is only ever changed when it is an access port, carries that
one MAC only (never an uplink, a trunk or a port with a hub or access point
behind it), and matches the switch's `ports_allow` / not `ports_deny` patterns;
protected and whitelisted hosts are refused as for every restriction. With
FIREWALL_DRY_RUN=1 the move is recorded and audited but no switch is changed.

Drivers:
  arista_eapi     Arista EOS eAPI (JSON-RPC over HTTPS): show mac address-table,
                  show interfaces switchport, switchport access vlan
  cisco_restconf  Cisco IOS-XE RESTCONF: Cisco-IOS-XE-matm-oper MAC table,
                  Cisco-IOS-XE-native switchport access vlan
  webhook         an HMAC-signed HTTPS POST to your own automation (Ansible AWX,
                  n8n, a controller API...), which answers {"port", "original_vlan"}

Configuration (Admin, GET/PUT /api/vlan; data/vlan.json, SENTINEL_VLAN):
  {"enabled": true, "quarantine_vlan": 999, "with_quarantine": true,
   "switches": [{"name": "core1", "driver": "arista_eapi", "url": "https://10.0.0.250",
                 "username": "sentinel", "password": "...", "ca_file": "", "verify_tls": true,
                 "ports_allow": "^Ethernet([1-9]|[1-3][0-9]|4[0-4])$", "ports_deny": "^(Port-Channel|Ethernet4[78])"}]}
Moves are kept in data/vlan_moves.json for restoring.
"""
import hashlib
import hmac
import json
import os
import re
import threading
import time
from urllib.parse import quote

import requests

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
DRIVERS = ('arista_eapi', 'cisco_restconf', 'webhook')
SECRET_FIELDS = ('password', 'secret')
DEFAULTS = {'enabled': False, 'quarantine_vlan': None, 'with_quarantine': True, 'switches': []}
TIMEOUT = 10
_lock = threading.Lock()


class VLANError(ValueError):
    pass


# ---------------- configuration and state ----------------

def config_file():
    return os.environ.get('SENTINEL_VLAN') or os.path.join(ROOT, 'data', 'vlan.json')


def moves_file():
    return os.path.join(os.path.dirname(os.path.abspath(config_file())), 'vlan_moves.json')


def _read(path, default):
    try:
        with open(path, encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def _write(path, data, mode=0o600):
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    fd = os.open(path + '.tmp', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=2)
    os.replace(path + '.tmp', path)


def load_config():
    data = _read(config_file(), {})
    return {**DEFAULTS, **(data if isinstance(data, dict) else {})}


def _vlan_id(value, what):
    try:
        v = int(value)
    except (TypeError, ValueError):
        raise VLANError(f'{what} must be a VLAN id (1-4094)')
    if not 1 <= v <= 4094:
        raise VLANError(f'{what} must be a VLAN id (1-4094)')
    return v


def validate(cfg):
    cfg = {**DEFAULTS, **cfg}
    if cfg['enabled']:
        cfg['quarantine_vlan'] = _vlan_id(cfg['quarantine_vlan'], 'quarantine_vlan')
        if not cfg['switches']:
            raise VLANError('add at least one switch')
    names = set()
    for sw in cfg['switches']:
        if not isinstance(sw, dict) or not sw.get('name') or sw['name'] in names:
            raise VLANError('every switch needs a unique name')
        names.add(sw['name'])
        if sw.get('driver') not in DRIVERS:
            raise VLANError(f'driver must be one of {", ".join(DRIVERS)}')
        if not str(sw.get('url', '')).startswith('https://') and not sw.get('allow_http'):
            raise VLANError(f'{sw["name"]}: the switch API must use https://')
        for key in ('ports_allow', 'ports_deny'):
            if sw.get(key):
                try:
                    re.compile(sw[key])
                except re.error as exc:
                    raise VLANError(f'{sw["name"]}: {key} is not a valid pattern ({exc})')
        if sw['driver'] == 'webhook' and not sw.get('secret'):
            raise VLANError(f'{sw["name"]}: a webhook needs a secret (requests are HMAC-signed)')
    return cfg


def save_config(cfg):
    current = {s['name']: s for s in load_config().get('switches', [])}
    for sw in cfg.get('switches', []) or []:
        for key in SECRET_FIELDS:
            if sw.get(key) == '********':
                sw[key] = current.get(sw.get('name'), {}).get(key)
    cfg = validate(cfg)
    _write(config_file(), cfg)
    return cfg


def redacted(cfg):
    out = dict(cfg)
    out['switches'] = [{**s, **{k: '********' for k in SECRET_FIELDS if s.get(k)}} for s in cfg.get('switches', [])]
    return out


def list_moves():
    return _read(moves_file(), [])


def _normalise_mac(mac):
    from enforcement.identity import normalise_mac
    m = normalise_mac(mac)
    if not m:
        raise VLANError('no valid MAC address for this device')
    return m


# ---------------- drivers ----------------

class Driver:
    def __init__(self, sw, session=None):
        self.sw = sw
        self.http = session or requests.Session()
        self.verify = sw.get('ca_file') or bool(sw.get('verify_tls', True))

    def locate(self, mac):
        """{'port', 'vlan', 'mode' ('access' | other), 'macs_on_port'} or None when the MAC is not on this switch."""
        raise NotImplementedError

    def set_vlan(self, port, vlan):
        raise NotImplementedError


class AristaEAPI(Driver):
    def _run(self, cmds):
        r = self.http.post(self.sw['url'].rstrip('/') + '/command-api', timeout=TIMEOUT, verify=self.verify,
                           auth=(self.sw.get('username', ''), self.sw.get('password', '')),
                           json={'jsonrpc': '2.0', 'method': 'runCmds', 'id': 'sentinel',
                                 'params': {'version': 1, 'cmds': cmds, 'format': 'json'}})
        r.raise_for_status()
        body = r.json()
        if 'error' in body:
            raise VLANError(f'{self.sw["name"]}: {body["error"].get("message", "eAPI error")}')
        return body['result']

    def locate(self, mac):
        dotted = mac.replace(':', '')
        dotted = f'{dotted[0:4]}.{dotted[4:8]}.{dotted[8:12]}'
        entries = self._run([f'show mac address-table address {dotted}'])[0].get('unicastTable', {}).get('tableEntries', [])
        if not entries:
            return None
        port = entries[0]['interface']
        sp, on_port = self._run([f'show interfaces {port} switchport', f'show mac address-table interface {port}'])
        info = sp.get('switchports', {}).get(port, {}).get('switchportInfo', {})
        return {'port': port, 'vlan': info.get('accessVlanId', entries[0].get('vlanId')), 'mode': info.get('mode'),
                'macs_on_port': len(on_port.get('unicastTable', {}).get('tableEntries', []))}

    def set_vlan(self, port, vlan):
        self._run(['enable', 'configure', f'interface {port}', f'switchport access vlan {int(vlan)}', 'end'])


class CiscoRESTCONF(Driver):
    HEADERS = {'Accept': 'application/yang-data+json', 'Content-Type': 'application/yang-data+json'}

    def _url(self, path):
        return self.sw['url'].rstrip('/') + '/restconf/data/' + path

    def _get(self, path):
        r = self.http.get(self._url(path), headers=self.HEADERS, timeout=TIMEOUT, verify=self.verify,
                          auth=(self.sw.get('username', ''), self.sw.get('password', '')))
        if r.status_code == 404:
            return {}
        r.raise_for_status()
        return r.json()

    @staticmethod
    def _split(port):
        m = re.fullmatch(r'([A-Za-z-]+)([0-9/.:]+)', port)
        if not m:
            raise VLANError(f'unexpected interface name {port!r}')
        return m.group(1), m.group(2)

    def _switchport_path(self, port):
        kind, number = self._split(port)
        return f'Cisco-IOS-XE-native:native/interface/{kind}={quote(number, safe="")}/switchport'

    def locate(self, mac):
        data = self._get('Cisco-IOS-XE-matm-oper:matm-oper-data')
        entries = []
        for table in data.get('Cisco-IOS-XE-matm-oper:matm-oper-data', {}).get('matm-table', []):
            entries += table.get('matm-mac-entry', [])
        mine = [e for e in entries if str(e.get('mac', '')).lower() == mac]
        if not mine:
            return None
        port = mine[0]['port']
        sp = self._get(self._switchport_path(port)).get('Cisco-IOS-XE-native:switchport', {})
        mode = 'access' if 'access' in (sp.get('Cisco-IOS-XE-switch:mode') or {}) else \
            ('trunk' if 'trunk' in (sp.get('Cisco-IOS-XE-switch:mode') or {}) else None)
        vlan = ((sp.get('Cisco-IOS-XE-switch:access') or {}).get('vlan') or {}).get('vlan', mine[0].get('vlan-id-number'))
        return {'port': port, 'vlan': vlan, 'mode': mode,
                'macs_on_port': sum(1 for e in entries if e.get('port') == port)}

    def set_vlan(self, port, vlan):
        r = self.http.patch(self._url(self._switchport_path(port)), headers=self.HEADERS, timeout=TIMEOUT,
                            verify=self.verify, auth=(self.sw.get('username', ''), self.sw.get('password', '')),
                            json={'Cisco-IOS-XE-native:switchport': {'Cisco-IOS-XE-switch:access': {'vlan': {'vlan': int(vlan)}}}})
        r.raise_for_status()


class Webhook(Driver):
    """Your automation moves the port; we send what to do and remember what it reports."""

    def _post(self, payload):
        body = json.dumps(payload, sort_keys=True, separators=(',', ':')).encode()
        sig = hmac.new(str(self.sw['secret']).encode(), body, hashlib.sha256).hexdigest()
        r = self.http.post(self.sw['url'], data=body, timeout=TIMEOUT, verify=self.verify,
                           headers={'Content-Type': 'application/json', 'X-Sentinel-Signature': f'sha256={sig}'})
        r.raise_for_status()
        return r.json() if r.content else {}

    def locate(self, mac):
        answer = self._post({'action': 'locate', 'mac': mac})
        if not answer.get('port'):
            return None
        return {'port': str(answer['port']), 'vlan': answer.get('vlan'), 'mode': answer.get('mode', 'access'),
                'macs_on_port': int(answer.get('macs_on_port', 1))}

    def set_vlan(self, port, vlan):
        self._post({'action': 'set_vlan', 'port': port, 'vlan': int(vlan)})


DRIVER_CLASSES = {'arista_eapi': AristaEAPI, 'cisco_restconf': CiscoRESTCONF, 'webhook': Webhook}


def driver(sw, session=None):
    return DRIVER_CLASSES[sw['driver']](sw, session)


# ---------------- moves ----------------

def _port_allowed(sw, port):
    if sw.get('ports_deny') and re.search(sw['ports_deny'], port):
        return False
    return not sw.get('ports_allow') or bool(re.search(sw['ports_allow'], port))


def locate(mac, cfg=None, session=None):
    """(switch config, location) of the MAC's port, or VLANError."""
    cfg = cfg or load_config()
    mac = _normalise_mac(mac)
    errors = []
    for sw in cfg['switches']:
        try:
            loc = driver(sw, session).locate(mac)
        except (requests.RequestException, VLANError, KeyError, ValueError, TypeError) as exc:
            errors.append(f'{sw["name"]}: {str(exc)[:120]}')
            continue
        if loc:
            return sw, loc
    raise VLANError(f'{mac} is not in any switch MAC table' + (f' ({"; ".join(errors)})' if errors else ''))


def _check_target(ip):
    from core import firewall
    if ip in set(firewall.get_policy().get('whitelist', [])):
        raise VLANError(f'refusing to move whitelisted host {ip}')
    from enforcement.protected import why_protected
    why = why_protected(ip)
    if why:
        raise VLANError(f'refusing to move protected host {ip} ({why})')


def move(ip, mac=None, ttl=None, reason='', cfg=None, session=None, now=None):
    """Move the device's access port to the quarantine VLAN; returns the recorded move."""
    from core import firewall
    cfg = cfg or load_config()
    if not cfg.get('enabled'):
        raise VLANError('VLAN quarantine is not enabled')
    _check_target(ip)
    if mac is None:
        from enforcement.identity import get_registry
        device = get_registry().by_ip(ip)
        mac = device['mac'] if device else None
    mac = _normalise_mac(mac)
    target = int(cfg['quarantine_vlan'])
    sw, loc = locate(mac, cfg, session)
    port = loc['port']
    if loc.get('mode') != 'access':
        raise VLANError(f'{sw["name"]} {port} is not an access port ({loc.get("mode") or "unknown mode"}); not changed')
    if int(loc.get('macs_on_port') or 0) > 1:
        raise VLANError(f'{sw["name"]} {port} carries {loc["macs_on_port"]} MAC addresses (uplink, hub or access '
                        'point?); not changed')
    if not _port_allowed(sw, port):
        raise VLANError(f'{sw["name"]} {port} is excluded by ports_allow / ports_deny; not changed')
    with _lock:
        moves = list_moves()
        existing = next((m for m in moves if m['mac'] == mac), None)
        original = existing['original_vlan'] if existing else loc.get('vlan')
        if original is None:
            raise VLANError(f'{sw["name"]} {port}: current VLAN unknown, so it could not be restored; not changed')
        if int(original) == target and not existing:
            raise VLANError(f'{sw["name"]} {port} is already on the quarantine VLAN {target}')
        dry = firewall.FIREWALL_DRY_RUN
        if not dry:
            try:
                driver(sw, session).set_vlan(port, target)
            except (requests.RequestException, VLANError) as exc:
                raise VLANError(f'{sw["name"]} {port}: the switch refused the change ({str(exc)[:160]})')
        now = int(now or time.time())
        ttl = int(ttl) if ttl else None
        record = {'ip': ip, 'mac': mac, 'switch': sw['name'], 'port': port, 'original_vlan': int(original),
                  'vlan': target, 'created': now, 'expires': now + ttl if ttl else None, 'reason': reason,
                  'dry_run': dry}
        _write(moves_file(), [m for m in moves if m['mac'] != mac] + [record], mode=0o640)
    _audit('vlan_move', record)
    return record


def _restore_one(m, cfg, session, why):
    from core import firewall
    sw = next((s for s in cfg['switches'] if s['name'] == m['switch']), None)
    if sw is None:
        raise VLANError(f'switch {m["switch"]} is no longer configured; restore {m["port"]} to VLAN '
                        f'{m["original_vlan"]} by hand')
    if not m.get('dry_run') and not firewall.FIREWALL_DRY_RUN:
        driver(sw, session).set_vlan(m['port'], m['original_vlan'])
    _audit('vlan_restore', {**m, 'why': why})


def restore(ip=None, mac=None, cfg=None, session=None, why='release'):
    """Put the port(s) of `ip` / `mac` back on their original VLAN. Returns the number restored."""
    cfg = cfg or load_config()
    done, errors = 0, []
    with _lock:
        moves = list_moves()
        keep = []
        for m in moves:
            if (ip and m['ip'] == ip) or (mac and m['mac'] == mac):
                try:
                    _restore_one(m, cfg, session, why)
                    done += 1
                    continue
                except (requests.RequestException, VLANError) as exc:
                    errors.append(str(exc)[:200])
            keep.append(m)
        _write(moves_file(), keep, mode=0o640)
    if errors:
        raise VLANError('; '.join(errors))
    return done


def restore_all(why='rollback', cfg=None, session=None):
    """Every moved port back (operator rollback, watchdog fail-open). Never raises; returns (restored, failed)."""
    cfg = cfg or load_config()
    restored, failed = 0, []
    with _lock:
        moves = list_moves()
        for m in moves:
            try:
                _restore_one(m, cfg, session, why)
                restored += 1
            except Exception as exc:
                failed.append({**m, 'error': str(exc)[:200]})
        _write(moves_file(), failed, mode=0o640)   # what could not be restored stays listed, to retry
    return restored, failed


def expire(now=None, cfg=None, session=None):
    now = int(now or time.time())
    due = [m for m in list_moves() if m.get('expires') and int(m['expires']) <= now]
    for m in due:
        try:
            restore(mac=m['mac'], cfg=cfg, session=session, why='expired')
        except VLANError:
            pass
    return len(due)


def _audit(action, record):
    try:
        from core import audit
        audit.record(action, actor='enforcement', actor_kind='system', target=record.get('ip'),
                     details={k: record.get(k) for k in ('mac', 'switch', 'port', 'original_vlan', 'vlan',
                                                         'reason', 'why', 'dry_run')})
    except Exception:
        pass


# ---------------- hooks from core.firewall ----------------

def on_quarantine(ip, mac, ttl, reason):
    """Best effort, after a firewall quarantine: never raises (the firewall quarantine stands either way)."""
    try:
        cfg = load_config()
        if cfg.get('enabled') and cfg.get('with_quarantine'):
            return move(ip, mac=mac, ttl=ttl, reason=reason, cfg=cfg)
    except Exception as exc:
        _audit('vlan_move_failed', {'ip': ip, 'mac': mac, 'reason': f'{reason}: {str(exc)[:200]}'})
    return None


def on_release(ip):
    try:
        if any(m['ip'] == ip for m in list_moves()):
            restore(ip=ip, why='release')
    except Exception as exc:
        _audit('vlan_restore_failed', {'ip': ip, 'reason': str(exc)[:200]})
