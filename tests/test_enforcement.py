import json
import time

import pytest

import core.audit as audit
import core.firewall as fw
from enforcement import identity, playbook, policy, protected, watchdog


@pytest.fixture(autouse=True)
def sandbox(tmp_path, monkeypatch):
    monkeypatch.setattr(fw, 'ROOT', str(tmp_path))
    monkeypatch.setattr(fw, 'FIREWALL_DRY_RUN', True)
    monkeypatch.setenv('SENTINEL_BRIDGE', '0')
    hosts = {'loopback': {'127.0.0.0/8', '::1'}, 'gateway': {'192.168.1.1'}, 'dns': {'192.168.1.1', '1.1.1.1'},
             'dhcp': {'192.168.1.1'}, 'appliance': {'192.168.1.2'}, 'management': {'10.10.0.0/24'},
             'whitelist': set()}
    monkeypatch.setattr(protected, 'protected_hosts', lambda refresh=False: hosts)
    yield hosts


# ---------- protected hosts ----------

def test_protected_reasons(sandbox):
    assert protected.why_protected('192.168.1.1', sandbox) == 'gateway'
    assert protected.why_protected('1.1.1.1', sandbox) == 'dns'
    assert protected.why_protected('10.10.0.77', sandbox) == 'management'
    assert protected.why_protected('127.0.0.9', sandbox) == 'loopback'
    assert protected.why_protected('198.51.100.7', sandbox) is None
    assert protected.why_protected('garbage', sandbox) is None


def test_discovery_parsers(tmp_path):
    route = tmp_path / 'route'
    route.write_text('Iface\tDestination\tGateway\tFlags\n'
                     'eth0\t00000000\t0132A8C0\t0003\n'
                     'eth0\t0032A8C0\t00000000\t0001\n')
    assert protected._gateways_v4(str(route)) == {'192.168.50.1'}
    resolv = tmp_path / 'resolv.conf'
    resolv.write_text('# x\nnameserver 192.168.50.1\nnameserver fe80::1%eth0\nsearch lan\n')
    assert protected._dns_servers(str(resolv)) >= {'192.168.50.1', 'fe80::1'}
    lease = tmp_path / 'x.leases'
    lease.write_text('lease {\n  option dhcp-server-identifier 192.168.50.1;\n}\n')
    assert protected._dhcp_servers((str(tmp_path / '*.leases'),)) == {'192.168.50.1'}


def test_firewall_refuses_protected_hosts():
    with pytest.raises(ValueError, match=r'protected host 192.168.1.1 \(gateway\)'):
        fw.add_block('192.168.1.1')
    with pytest.raises(ValueError, match='protected host'):
        fw.add_restriction('quarantine', '192.168.1.2')
    assert fw.add_block('198.51.100.7')['ip'] == '198.51.100.7'


# ---------- device identity ----------

def test_identity_tracks_ip_changes(tmp_path):
    reg = identity.DeviceRegistry(str(tmp_path / 'd.db'))
    reg.observe('3C-22-FB-11-22-33', ip='192.168.1.50', hostname='laptop')
    reg.observe('3c:22:fb:11:22:33', ip='192.168.1.77')
    d = reg.get('3c:22:fb:11:22:33')
    assert d['ip'] == '192.168.1.77' and d['ips'] == ['192.168.1.50', '192.168.1.77']
    assert d['hostname'] == 'laptop'
    assert reg.by_ip('192.168.1.77')['mac'] == '3c:22:fb:11:22:33'
    assert reg.observe('ff:ff:ff:ff:ff:ff') is None and reg.observe('nope') is None
    assert identity.vendor('02:00:00:00:00:01') == 'Private (randomised MAC)'


def test_arp_table_parsing(tmp_path):
    arp = tmp_path / 'arp'
    arp.write_text('IP address HW type Flags HW address Mask Device\n'
                   '192.168.1.1 0x1 0x2 7c:f1:7e:6e:ab:e4 * eth0\n'
                   '192.168.1.9 0x1 0x0 00:00:00:00:00:00 * eth0\n')
    assert identity.arp_table(str(arp)) == [('192.168.1.1', '7c:f1:7e:6e:ab:e4', 'eth0')]


# ---------- restrictions ----------

def test_quarantine_and_ratelimit_lifecycle():
    q = fw.add_restriction('quarantine', '198.51.100.20', ttl=60, reason='test', mac='3c:22:fb:11:22:33')
    fw.add_restriction('ratelimit', '2001:db8::5', ttl=60)
    assert {(r['kind'], r['ip']) for r in fw.list_restrictions()} == {
        ('quarantine', '198.51.100.20'), ('ratelimit', '2001:db8::5')}
    assert q['mac'] == '3c:22:fb:11:22:33' and q['dry_run'] is True
    # re-quarantining replaces, never duplicates
    fw.add_restriction('quarantine', '198.51.100.20', ttl=120)
    assert len(fw.list_restrictions()) == 2
    assert fw.remove_restriction('quarantine', '198.51.100.20') == {'removed': 1}
    assert fw.rollback_blocks()['restrictions_removed'] == 1
    assert fw.list_restrictions() == []
    with pytest.raises(ValueError):
        fw.add_restriction('nuke', '198.51.100.20')


def test_restrictions_expire(monkeypatch):
    fw.add_restriction('ratelimit', '198.51.100.21', ttl=60)
    real = time.time
    monkeypatch.setattr(fw.time, 'time', lambda: real() + 120)
    assert fw.list_restrictions() == []


def test_enforcement_script_shape():
    script = fw._enforcement_script(bridge=False)
    assert 'add rule inet sentinel enf_input ip saddr @quarantine jump quarantine_check' in script
    assert 'flush chain inet sentinel enf_forward' in script
    assert 'limit rate over 100/second' in script
    assert 'tcp dport { 53, 9000 } return' in script
    assert 'bridge' not in script
    bridged = fw._enforcement_script(bridge=True)
    assert 'add table bridge sentinel' in bridged and 'ether saddr @qmac drop' in bridged


# ---------- playbook ----------

class FakeFw:
    def __init__(self):
        self.calls = []

    def add_block(self, ip, ttl=None, reason=''):
        if ip == '192.168.1.1':
            raise ValueError('refusing to block protected host 192.168.1.1 (gateway)')
        self.calls.append(('block', ip, ttl))

    def add_restriction(self, kind, ip, ttl=None, reason='', mac=None):
        self.calls.append((kind, ip, ttl))


def make_playbook(tmp_path, approval=None, clock=None):
    cfg = json.loads(json.dumps(playbook.DEFAULT_PLAYBOOK))
    cfg['approval'] = approval or {'required_from_risk': None}
    return playbook.Playbook(cfg, path=str(tmp_path / 'pb.db'), firewall_module=FakeFw(),
                             clock=clock or time.time)


def test_steps_by_risk(tmp_path):
    pb = make_playbook(tmp_path)
    assert pb.evaluate('198.51.100.1', 30)['status'] == 'below_threshold'
    assert pb.evaluate('198.51.100.2', 55)['action'] == 'alert'
    out = pb.evaluate('198.51.100.3', 70)
    assert (out['action'], out['status']) == ('rate_limit', 'applied')
    assert out['tuning']['mode'] == 'recommend'                      # response tuning only recommends by default
    assert pb.evaluate('198.51.100.4', 80)['action'] == 'block'
    assert pb.evaluate('198.51.100.5', 95)['action'] == 'quarantine'
    assert pb.fw.calls == [('ratelimit', '198.51.100.3', 600), ('block', '198.51.100.4', 3600),
                           ('quarantine', '198.51.100.5', 86400)]


def test_repeat_offender_escalates(tmp_path):
    pb = make_playbook(tmp_path)
    results = [pb.evaluate('198.51.100.9', 70)['action'] for _ in range(4)]
    assert results == ['rate_limit', 'rate_limit', 'block', 'block']


def test_protected_host_is_refused_not_enforced(tmp_path):
    pb = make_playbook(tmp_path)
    r = pb.evaluate('192.168.1.1', 80)
    assert r['status'] == 'refused' and 'gateway' in r['detail']


def test_approval_gate(tmp_path):
    pb = make_playbook(tmp_path, approval={'required_from_risk': 75, 'until': time.time() + 3600})
    assert pb.evaluate('198.51.100.30', 70)['status'] == 'applied'           # below the gate
    r = pb.evaluate('198.51.100.31', 80)
    assert r['status'] == 'awaiting_approval' and pb.fw.calls == [('ratelimit', '198.51.100.30', 600)]
    assert pb.evaluate('198.51.100.31', 82)['pending_id'] == r['pending_id']  # no duplicate request
    assert [p['ip'] for p in pb.pending()] == ['198.51.100.31']
    assert pb.decide(r['pending_id'], True, 'otto')['status'] == 'approved'
    assert pb.fw.calls[-1] == ('block', '198.51.100.31', 3600)
    with pytest.raises(ValueError):
        pb.decide(r['pending_id'], True, 'otto')
    r2 = pb.evaluate('198.51.100.32', 80)
    assert pb.decide(r2['pending_id'], False, 'otto')['status'] == 'denied'
    assert len(pb.fw.calls) == 2


def test_approval_period_ends(tmp_path):
    now = [time.time()]
    pb = make_playbook(tmp_path, approval={'required_from_risk': 75, 'until': now[0] + 10}, clock=lambda: now[0])
    assert pb.evaluate('198.51.100.40', 80)['status'] == 'awaiting_approval'
    now[0] += 20
    assert pb.evaluate('198.51.100.41', 80)['status'] == 'applied'


# ---------- policy as code ----------

GOOD = """
version: 1
response_mode: auto_block
default_ttl: 600
whitelist: [198.51.100.250]
management_hosts: [10.20.0.0/24]
playbook:
  steps:
    - {action: alert, min_risk: 40}
    - {action: block, min_risk: 80, ttl: 1800}
  escalate_after: 5
  window_seconds: 300
  approval: {required_from_risk: 80, days: 30}
"""


def test_policy_validate_diff_apply(tmp_path, monkeypatch):
    monkeypatch.setattr(policy, 'protected', protected, raising=False)
    new, errors, warnings = policy.validate(policy.parse(GOOD))
    assert errors == []
    changed = {k for k, _, _ in policy.diff(new)}
    assert changed == {'response_mode', 'default_ttl', 'whitelist', 'management_hosts', 'playbook'}
    result = policy.apply(policy.parse(GOOD), by='adam')
    assert fw.get_policy()['response_mode'] == 'auto_block'
    assert policy.current()['management_hosts'] == ['10.20.0.0/24']
    until = policy.current()['playbook']['approval']['until']
    assert 29 * 86400 < until - time.time() <= 30 * 86400
    assert policy.diff(policy.validate(policy.parse(GOOD))[0]) != []  # days vs until is normalised at apply
    assert len(list((tmp_path / 'policy_history').glob('*.yaml'))) == 1
    assert audit.get_log().entries(action='policy_apply')[0]['actor'] == 'adam'
    assert {c[0] for c in result['changes']} == changed


@pytest.mark.parametrize('text, message', [
    ('response_mode: nuke', 'response_mode'),
    ('default_ttl: 900\nmax_ttl: 600', 'default_ttl cannot exceed max_ttl'),
    ('whitelist: [not-an-ip]', 'not a valid address'),
    ('playbook: {steps: [{action: block, min_risk: 80}, {action: alert, min_risk: 50}]}', 'higher than the previous'),
    ('playbook: {steps: [{action: format, min_risk: 80}]}', 'action must be one of'),
    ('surprise: 1', 'unknown keys'),
    ('- just\n- a list', 'mapping'),
])
def test_policy_errors(text, message):
    try:
        _, errors, _ = policy.validate(policy.parse(text))
    except ValueError as exc:
        errors = [str(exc)]
    assert any(message in e for e in errors), errors


def test_policy_apply_refuses_invalid():
    with pytest.raises(ValueError, match='response_mode'):
        policy.apply(policy.parse('response_mode: nuke'))
    assert fw.get_policy()['response_mode'] == 'monitor'


def test_policy_conflict_warning():
    fw.add_block('198.51.100.66')
    _, errors, warnings = policy.validate(policy.parse('whitelist: [198.51.100.66, 198.51.100.66]'))
    assert errors == []
    assert any('currently blocked' in w for w in warnings) and any('duplicate' in w for w in warnings)


def test_policy_export_round_trips():
    new, errors, _ = policy.validate(policy.parse(policy.export()))
    assert errors == [] and policy.diff(new) == []


# ---------- watchdog ----------

def test_watchdog_fails_open_after_threshold(monkeypatch):
    fw.add_block('198.51.100.70')
    fw.add_restriction('quarantine', '198.51.100.71')
    down = lambda name: 'engine' not in name
    assert watchdog.check(is_active=down).endswith('1/3')
    assert watchdog.check(is_active=down).endswith('2/3')
    assert watchdog.check(is_active=down).startswith('fail-open')
    assert [r for r in fw.list_rules() if r.get('blocked')] == [] and fw.list_restrictions() == []
    assert audit.get_log().entries(action='watchdog_failopen')


def test_watchdog_noop_when_healthy_or_idle():
    assert watchdog.check(is_active=lambda n: True) == 'healthy'
    assert 'nothing enforced' in watchdog.check(is_active=lambda n: False)


@pytest.mark.parametrize('preset', ['home', 'office', 'ot', 'enterprise'])
def test_presets_validate_and_apply(preset):
    import os
    path = os.path.join(os.path.dirname(__file__), '..', 'presets', f'{preset}.yaml')
    doc = policy.parse(open(path).read())
    _, errors, _ = policy.validate(doc)
    assert errors == []
    policy.apply(doc, by='preset-test')
    assert fw.get_policy()['response_mode'] == doc['response_mode']
