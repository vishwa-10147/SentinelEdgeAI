"""Quarantine VLAN on managed switches (Arista eAPI, Cisco RESTCONF, webhook) and its safety rules."""
import hashlib
import hmac
import json

import pytest

import core.firewall as firewall
from enforcement import identity, vlan

MAC = '3c:22:fb:00:00:42'
IP = '10.99.0.42'


class Resp:
    def __init__(self, body, status=200):
        self._body, self.status_code = body, status
        self.content = json.dumps(body).encode()

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            import requests
            raise requests.HTTPError(f'HTTP {self.status_code}')


class FakeArista:
    """Answers eAPI runCmds like EOS (format json)."""

    def __init__(self, mode='access', vlan_id=20, macs=1, port='Ethernet7'):
        self.mode, self.vlan, self.macs, self.port = mode, vlan_id, macs, port
        self.config = []

    def post(self, url, json=None, auth=None, verify=None, timeout=None):
        assert url.endswith('/command-api') and json['method'] == 'runCmds' and json['params']['format'] == 'json'
        assert auth == ('sentinel', 's3cret') and verify is True
        out = []
        for cmd in json['params']['cmds']:
            if cmd.startswith('show mac address-table address'):
                assert cmd.endswith('3c22.fb00.0042')
                out.append({'unicastTable': {'tableEntries': [{'vlanId': self.vlan, 'macAddress': '3c22.fb00.0042',
                                                               'interface': self.port, 'entryType': 'dynamic'}]}})
            elif cmd.startswith('show interfaces') and cmd.endswith('switchport'):
                out.append({'switchports': {self.port: {'switchportInfo': {'mode': self.mode, 'accessVlanId': self.vlan}}}})
            elif cmd.startswith('show mac address-table interface'):
                out.append({'unicastTable': {'tableEntries': [{}] * self.macs}})
            else:
                self.config.append(cmd)
                if cmd.startswith('switchport access vlan'):
                    self.vlan = int(cmd.split()[-1])
                out.append({})
        return Resp({'jsonrpc': '2.0', 'id': json['id'], 'result': out})


class FakeRestconf:
    def __init__(self):
        self.vlan = 30
        self.patched = []

    def get(self, url, headers=None, timeout=None, verify=None, auth=None):
        assert headers['Accept'] == 'application/yang-data+json'
        if url.endswith('Cisco-IOS-XE-matm-oper:matm-oper-data'):
            return Resp({'Cisco-IOS-XE-matm-oper:matm-oper-data': {'matm-table': [{'matm-mac-entry': [
                {'mac': MAC, 'vlan-id-number': self.vlan, 'port': 'GigabitEthernet1/0/5'},
                {'mac': 'aa:bb:cc:00:00:01', 'vlan-id-number': 1, 'port': 'GigabitEthernet1/0/48'}]}]}})
        assert url.endswith('interface/GigabitEthernet=1%2F0%2F5/switchport')
        return Resp({'Cisco-IOS-XE-native:switchport': {'Cisco-IOS-XE-switch:access': {'vlan': {'vlan': self.vlan}},
                                                        'Cisco-IOS-XE-switch:mode': {'access': {}}}})

    def patch(self, url, headers=None, timeout=None, verify=None, auth=None, json=None):
        assert url.endswith('interface/GigabitEthernet=1%2F0%2F5/switchport')
        self.vlan = json['Cisco-IOS-XE-native:switchport']['Cisco-IOS-XE-switch:access']['vlan']['vlan']
        self.patched.append(self.vlan)
        return Resp({}, 204)


def config(driver='arista_eapi', **sw):
    return vlan.save_config({'enabled': True, 'quarantine_vlan': 999, 'switches': [
        {'name': 'core1', 'driver': driver, 'url': 'https://10.99.0.250', 'username': 'sentinel',
         'password': 's3cret', 'ports_deny': '^(Port-Channel|Ethernet48)', **sw}]})


@pytest.fixture()
def live(monkeypatch):
    monkeypatch.setattr(firewall, 'FIREWALL_DRY_RUN', False)       # the switch is really changed (a fake one)


def test_arista_move_and_restore(live):
    sw = FakeArista()
    cfg = config()
    m = vlan.move(IP, mac=MAC, ttl=600, reason='test', cfg=cfg, session=sw, now=1000)
    assert (m['port'], m['original_vlan'], m['vlan'], m['expires']) == ('Ethernet7', 20, 999, 1600)
    assert sw.config == ['enable', 'configure', 'interface Ethernet7', 'switchport access vlan 999', 'end']
    assert vlan.list_moves()[0]['mac'] == MAC
    assert vlan.restore(ip=IP, cfg=cfg, session=sw) == 1
    assert sw.vlan == 20 and vlan.list_moves() == []


def test_cisco_restconf_move(live):
    sw = FakeRestconf()
    cfg = config('cisco_restconf')
    m = vlan.move(IP, mac=MAC, cfg=cfg, session=sw)
    assert (m['port'], m['original_vlan']) == ('GigabitEthernet1/0/5', 30) and sw.patched == [999]
    vlan.restore(mac=MAC, cfg=cfg, session=sw)
    assert sw.patched == [999, 30]


def test_webhook_is_signed(live):
    calls = []

    class Hook:
        def post(self, url, data=None, timeout=None, verify=None, headers=None):
            sig = hmac.new(b'hook-secret', data, hashlib.sha256).hexdigest()
            assert headers['X-Sentinel-Signature'] == f'sha256={sig}'
            body = json.loads(data)
            calls.append(body)
            return Resp({'port': 'ge-0/0/3', 'vlan': 40, 'mode': 'access'} if body['action'] == 'locate' else {})

    cfg = config('webhook', secret='hook-secret', url='https://automation.corp.example/hooks/vlan')
    m = vlan.move(IP, mac=MAC, cfg=cfg, session=Hook())
    assert m['original_vlan'] == 40 and calls[-1] == {'action': 'set_vlan', 'port': 'ge-0/0/3', 'vlan': 999}


def test_safety_refusals(live):
    cfg = config()
    with pytest.raises(vlan.VLANError, match='not an access port'):
        vlan.move(IP, mac=MAC, cfg=cfg, session=FakeArista(mode='trunk'))
    with pytest.raises(vlan.VLANError, match='3 MAC addresses'):
        vlan.move(IP, mac=MAC, cfg=cfg, session=FakeArista(macs=3))
    with pytest.raises(vlan.VLANError, match='excluded'):
        vlan.move(IP, mac=MAC, cfg=cfg, session=FakeArista(port='Ethernet48'))
    with pytest.raises(vlan.VLANError, match='already on the quarantine VLAN'):
        vlan.move(IP, mac=MAC, cfg=cfg, session=FakeArista(vlan_id=999))
    with pytest.raises(vlan.VLANError, match='whitelisted|protected'):
        vlan.move('127.0.0.1', mac=MAC, cfg=cfg, session=FakeArista())
    with pytest.raises(vlan.VLANError, match='MAC'):
        vlan.move(IP, mac='not-a-mac', cfg=cfg, session=FakeArista())
    assert vlan.list_moves() == []


def test_config_validation():
    with pytest.raises(vlan.VLANError, match='VLAN id'):
        vlan.validate({'enabled': True, 'quarantine_vlan': 5000, 'switches': [{}]})
    with pytest.raises(vlan.VLANError, match='https'):
        vlan.validate({'enabled': True, 'quarantine_vlan': 9, 'switches': [
            {'name': 'a', 'driver': 'arista_eapi', 'url': 'http://sw'}]})
    with pytest.raises(vlan.VLANError, match='secret'):
        vlan.validate({'switches': [{'name': 'a', 'driver': 'webhook', 'url': 'https://h'}]})
    cfg = config()
    assert vlan.redacted(cfg)['switches'][0]['password'] == '********'
    saved = vlan.save_config({**vlan.redacted(cfg)})                 # a redacted secret sent back keeps the stored one
    assert saved['switches'][0]['password'] == 's3cret'


def test_dry_run_records_without_touching_the_switch():
    sw = FakeArista()
    m = vlan.move(IP, mac=MAC, cfg=config(), session=sw)
    assert m['dry_run'] is True and sw.config == []


def test_quarantine_moves_and_release_restores(monkeypatch, tmp_path):
    """The firewall quarantine drives the VLAN move; release, expiry and rollback put it back (dry run)."""
    monkeypatch.setattr(firewall, 'ROOT', str(tmp_path))          # firewall state files in the test directory
    config()
    identity.get_registry().observe(MAC, ip=IP)
    fake = FakeArista()
    monkeypatch.setattr(vlan, 'driver', lambda sw, session=None: vlan.AristaEAPI(sw, fake))
    item = firewall.add_restriction('quarantine', IP, ttl=300, reason='test')
    assert item['vlan']['port'] == 'Ethernet7' and vlan.list_moves()[0]['ip'] == IP
    firewall.remove_restriction('quarantine', IP)
    assert vlan.list_moves() == []
    firewall.add_restriction('quarantine', IP, ttl=300, reason='test')
    firewall.rollback_blocks(reason='test')
    assert vlan.list_moves() == []
    # the switch being unreachable never stops the firewall quarantine
    def broken(sw, session=None):
        raise vlan.VLANError('switch down')
    monkeypatch.setattr(vlan, 'driver', broken)
    item = firewall.add_restriction('quarantine', IP, ttl=300, reason='test')
    assert 'vlan' not in item and any(r['ip'] == IP for r in firewall.list_restrictions())


def test_expiry_restores(monkeypatch):
    cfg = config()
    sw = FakeArista()
    vlan.move(IP, mac=MAC, ttl=60, cfg=cfg, session=sw, now=1000)
    assert vlan.expire(now=1030, cfg=cfg, session=sw) == 0 and vlan.list_moves()
    assert vlan.expire(now=1061, cfg=cfg, session=sw) == 1 and vlan.list_moves() == []
