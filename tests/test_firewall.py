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
