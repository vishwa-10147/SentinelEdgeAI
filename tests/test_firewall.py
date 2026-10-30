import os
import json
import tempfile
import shutil
import core.firewall as fw
import pytest


@pytest.fixture(autouse=True)
def isolated_firewall_root(tmp_path, monkeypatch):
    tmp = tmp_path / 'firewall'
    tmp.mkdir()
    monkeypatch.setattr(fw, 'ROOT', str(tmp))
    monkeypatch.setattr(fw, 'FIREWALL_DRY_RUN', True)
    return tmp


def test_add_and_remove_block():
    # default dry-run True, add block
    res = fw.add_block('203.0.113.5', ttl=60, reason='test')
    assert res['ip'] == '203.0.113.5'
    assert res['dry_run'] is True
    assert res['expires'] is not None

    rules = fw.list_rules()
    assert any(r['ip']=='203.0.113.5' for r in rules)

    rem = fw.remove_block('203.0.113.5')
    assert rem['removed'] >= 1
    rules2 = fw.list_rules()
    assert all(r['ip']!='203.0.113.5' for r in rules2)


def test_rejects_command_injection_ip():
    with pytest.raises(ValueError):
        fw.add_block('203.0.113.5; touch /tmp/sentinel-owned')


def test_rejects_invalid_ttl():
    with pytest.raises(ValueError):
        fw.add_block('203.0.113.5', ttl=-1)


def test_default_policy_ttl_applies():
    res = fw.add_block('203.0.113.6')
    assert res['expires'] - res['created'] == 300


def test_whitelist_blocks_enforcement():
    fw.add_whitelist('203.0.113.7')
    with pytest.raises(ValueError, match='whitelisted'):
        fw.add_block('203.0.113.7', ttl=60)


def test_policy_update_validates_ttl_bounds():
    with pytest.raises(ValueError):
        fw.update_policy({'default_ttl': 500, 'max_ttl': 100})


def test_policy_update_supports_response_modes():
    policy = fw.update_policy({'response_mode': 'auto_block', 'auto_block_min_risk': 80})
    assert policy['response_mode'] == 'auto_block'
    assert policy['auto_block_min_risk'] == 80


def test_policy_update_rejects_invalid_response_mode():
    with pytest.raises(ValueError):
        fw.update_policy({'response_mode': 'destroy'})


def test_expire_rules_removes_expired_rule():
    res = fw.add_block('203.0.113.8', ttl=1)
    expired_at = res['expires'] + 1
    result = fw.expire_rules(now=expired_at)
    assert result['expired'] == 1
    assert fw.list_rules() == []


def test_rollback_blocks_removes_all_active_rules():
    fw.add_block('203.0.113.9', ttl=60)
    fw.add_block('203.0.113.10', ttl=60)
    result = fw.rollback_blocks()
    assert result['removed'] == 2
    assert fw.list_rules() == []


def test_duplicate_block_replaces_existing_rule():
    first = fw.add_block('203.0.113.11', ttl=60)
    second = fw.add_block('203.0.113.11', ttl=120)
    rules = fw.list_rules()
    assert len(rules) == 1
    assert rules[0]['ip'] == '203.0.113.11'
    assert second['expires'] > first['expires']


class FakeKernel:
    """Stands in for _run_cmd: records commands and tracks iptables/nft state."""

    def __init__(self):
        self.calls = []
        self.iptables = []          # list of (chain, tuple(spec))
        self.nft_chains = set()
        self.nft_table = False
        self.nft_set = set()
        self.nft_scripts = []

    def __call__(self, cmd):
        self.calls.append(list(cmd))
        prog, args = cmd[0], list(cmd[1:])
        if prog == 'iptables':
            op = args[0]
            if op == '-S':
                lines = [f"-A {c} {' '.join(s)}" for c, s in self.iptables if c == args[1]]
                return True, '\n'.join(lines)
            chain, spec = args[1], tuple(args[2:])
            if op == '-C':
                return (chain, spec) in self.iptables, ''
            if op == '-I':
                self.iptables.insert(0, (chain, spec))
                return True, ''
            if op == '-D':
                if (chain, spec) in self.iptables:
                    self.iptables.remove((chain, spec))
                    return True, ''
                return False, 'Bad rule'
        if prog == 'nft':
            if args[0] == '-f':
                with open(args[1]) as f:
                    script = f.read()
                self.nft_scripts.append(script)
                self.nft_table = True
                for line in script.splitlines():
                    if line.startswith('add chain'):
                        self.nft_chains.add(line.split()[4])
                return True, ''
            if args[:2] == ['list', 'chain']:
                return args[4] in self.nft_chains, ''
            if args[:2] == ['list', 'table']:
                return self.nft_table, ''
            if args[:2] == ['add', 'element']:
                self.nft_set.add(args[6])
                return True, ''
            if args[:2] == ['delete', 'element']:
                self.nft_set.discard(args[6])
                return True, ''
            if args[:2] == ['delete', 'table']:
                self.nft_table, self.nft_chains, self.nft_set = False, set(), set()
                return True, ''
        return False, 'unexpected command'


@pytest.fixture
def kernel(monkeypatch):
    fake = FakeKernel()
    monkeypatch.setattr(fw, 'FIREWALL_DRY_RUN', False)
    monkeypatch.setattr(fw, '_run_cmd', fake)
    monkeypatch.setattr(fw.shutil, 'which', lambda name: f'/usr/sbin/{name}')
    return fake


def test_nft_block_creates_chains_that_use_the_set(kernel, monkeypatch):
    monkeypatch.setattr(fw, 'FIREWALL_BACKEND', 'nft')
    rule = fw.add_block('203.0.113.20', ttl=60)
    assert rule['applied'] is True
    script = kernel.nft_scripts[0]
    assert 'type filter hook input' in script
    assert 'type filter hook forward' in script
    assert 'add rule inet sentinel input ip saddr @blacklist drop' in script
    assert 'add rule inet sentinel forward ip daddr @blacklist drop' in script
    assert kernel.nft_set == {'203.0.113.20'}


def test_nft_second_block_does_not_duplicate_chain_rules(kernel, monkeypatch):
    monkeypatch.setattr(fw, 'FIREWALL_BACKEND', 'nft')
    fw.add_block('203.0.113.21', ttl=60)
    fw.add_block('203.0.113.22', ttl=60)
    assert 'add rule' not in kernel.nft_scripts[1]
    assert kernel.nft_set == {'203.0.113.21', '203.0.113.22'}


def test_nft_unblock_removes_set_element(kernel, monkeypatch):
    monkeypatch.setattr(fw, 'FIREWALL_BACKEND', 'nft')
    fw.add_block('203.0.113.23', ttl=60)
    fw.remove_block('203.0.113.23')
    assert kernel.nft_set == set()


def test_iptables_block_covers_input_and_forward(kernel, monkeypatch):
    monkeypatch.setattr(fw, 'FIREWALL_BACKEND', 'iptables')
    rule = fw.add_block('203.0.113.30', ttl=60)
    assert rule['applied'] is True
    chains = sorted((c, s[0]) for c, s in kernel.iptables)
    assert chains == [('FORWARD', '-d'), ('FORWARD', '-s'), ('INPUT', '-s')]
    assert all('SentinelEdgeAI' in s for _, s in kernel.iptables)


def test_iptables_reblock_is_idempotent(kernel, monkeypatch):
    monkeypatch.setattr(fw, 'FIREWALL_BACKEND', 'iptables')
    fw.add_block('203.0.113.31', ttl=60)
    fw.add_block('203.0.113.31', ttl=120)
    assert len(kernel.iptables) == 3


def test_iptables_unblock_removes_every_rule(kernel, monkeypatch):
    monkeypatch.setattr(fw, 'FIREWALL_BACKEND', 'iptables')
    fw.add_block('203.0.113.32', ttl=60)
    # simulate a duplicate left behind by an older version
    kernel.iptables.append(kernel.iptables[0])
    fw.remove_block('203.0.113.32')
    assert kernel.iptables == []


def test_rollback_flushes_rules_missing_from_state(kernel, monkeypatch):
    monkeypatch.setattr(fw, 'FIREWALL_BACKEND', 'auto')
    fw.add_block('203.0.113.33', ttl=60)
    kernel.iptables.append(('INPUT', ('-s', '198.51.100.9/32', '-m', 'comment', '--comment', 'SentinelEdgeAI', '-j', 'DROP')))
    kernel.iptables.append(('INPUT', ('-s', '198.51.100.10/32', '-j', 'ACCEPT')))
    fw.rollback_blocks()
    assert kernel.nft_table is False
    assert kernel.iptables == [('INPUT', ('-s', '198.51.100.10/32', '-j', 'ACCEPT'))]


def test_run_cmd_refuses_non_firewall_binaries():
    ok, out = fw._run_cmd(['rm', '-rf', '/tmp/x'])
    assert ok is False
    assert 'not allowed' in out


def test_run_cmd_refuses_shell_metacharacters():
    ok, out = fw._run_cmd(['iptables', '-L', ';', 'reboot'])
    assert ok is False
