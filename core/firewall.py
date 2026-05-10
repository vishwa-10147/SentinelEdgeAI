import os
import json
import subprocess
import time
import ipaddress
import shutil
import logging

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

FIREWALL_DRY_RUN = os.environ.get('FIREWALL_DRY_RUN', '1') == '1'
FIREWALL_BACKEND = os.environ.get('SENTINEL_FIREWALL_BACKEND', 'auto').lower()

def _rules_file():
    return os.path.join(ROOT, 'firewall_rules.json')

def _policy_file():
    return os.path.join(ROOT, 'firewall_policy.json')

def _log_dir():
    return os.path.join(ROOT, 'logs')

def _actions_log():
    return os.path.join(_log_dir(), 'firewall_actions.jsonl')

def _ensure_files():
    os.makedirs(_log_dir(), exist_ok=True)
    if not os.path.exists(_rules_file()):
        with open(_rules_file(), 'w') as f:
            json.dump([], f)
    if not os.path.exists(_policy_file()):
        with open(_policy_file(), 'w') as f:
            json.dump(_default_policy(), f, indent=2)

def _default_policy():
    return {
        'whitelist': ['127.0.0.1'],
        'default_ttl': 300,
        'max_ttl': 86400,
        'response_mode': 'monitor',
        'auto_block_min_risk': 75,
    }

def _log_action(action: dict):
    _ensure_files()
    action['ts'] = time.time()
    with open(_actions_log(), 'a') as f:
        f.write(json.dumps(action) + '\n')

def _read_rules():
    _ensure_files()
    try:
        with open(_rules_file(), 'r') as f:
            return json.load(f)
    except Exception:
        return []

def _write_rules(rules):
    _ensure_files()
    with open(_rules_file(), 'w') as f:
        json.dump(rules, f, indent=2)

def get_policy():
    _ensure_files()
    try:
        with open(_policy_file(), 'r') as f:
            raw = json.load(f) or {}
    except Exception:
        raw = {}
    policy = _default_policy()
    policy.update(raw)
    policy['whitelist'] = sorted({_validate_ip(ip) for ip in policy.get('whitelist', [])})
    policy['default_ttl'] = _validate_ttl(policy.get('default_ttl'), allow_none=True)
    policy['max_ttl'] = _validate_ttl(policy.get('max_ttl'), allow_none=False)
    return policy

def update_policy(policy_update: dict):
    current = get_policy()
    updated = dict(current)
    if 'whitelist' in policy_update:
        updated['whitelist'] = sorted({_validate_ip(ip) for ip in policy_update.get('whitelist', [])})
    if 'default_ttl' in policy_update:
        updated['default_ttl'] = _validate_ttl(policy_update.get('default_ttl'), allow_none=True)
    if 'max_ttl' in policy_update:
        updated['max_ttl'] = _validate_ttl(policy_update.get('max_ttl'), allow_none=False)
    if 'response_mode' in policy_update:
        updated['response_mode'] = _validate_response_mode(policy_update.get('response_mode'))
    if 'auto_block_min_risk' in policy_update:
        updated['auto_block_min_risk'] = _validate_risk_threshold(policy_update.get('auto_block_min_risk'))
    if updated['default_ttl'] is not None and updated['default_ttl'] > updated['max_ttl']:
        raise ValueError("default_ttl cannot exceed max_ttl")
    _ensure_files()
    with open(_policy_file(), 'w') as f:
        json.dump(updated, f, indent=2)
    _log_action({'action': 'policy_update', 'policy': updated})
    return updated

def add_whitelist(ip: str):
    ip = _validate_ip(ip)
    policy = get_policy()
    whitelist = set(policy.get('whitelist', []))
    whitelist.add(ip)
    return update_policy({'whitelist': sorted(whitelist)})

def remove_whitelist(ip: str):
    ip = _validate_ip(ip)
    policy = get_policy()
    whitelist = set(policy.get('whitelist', []))
    whitelist.discard(ip)
    return update_policy({'whitelist': sorted(whitelist)})

def _validate_ip(ip: str) -> str:
    try:
        parsed = ipaddress.ip_address(str(ip))
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {ip}") from exc
    if parsed.version != 4:
        raise ValueError("only IPv4 addresses are currently supported")
    return str(parsed)

def _validate_ttl(ttl, allow_none=True, max_ttl=86400):
    if ttl is None:
        if allow_none:
            return None
        raise ValueError("ttl is required")
    if ttl == '':
        if allow_none:
            return None
        raise ValueError("ttl is required")
    try:
        max_ttl = int(max_ttl)
    except (TypeError, ValueError) as exc:
        raise ValueError("max_ttl must be an integer") from exc
    if max_ttl <= 0:
        raise ValueError("max_ttl must be greater than zero")
    try:
        ttl = int(ttl)
    except (TypeError, ValueError) as exc:
        raise ValueError("ttl must be an integer") from exc
    if ttl <= 0 or ttl > max_ttl:
        raise ValueError(f"ttl must be between 1 and {max_ttl} seconds")
    return ttl

def _validate_response_mode(mode):
    mode = str(mode or 'monitor').lower()
    if mode not in {'monitor', 'alert', 'auto_block'}:
        raise ValueError("response_mode must be monitor, alert, or auto_block")
    return mode

def _validate_risk_threshold(value):
    try:
        value = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError("auto_block_min_risk must be an integer") from exc
    if value < 1 or value > 100:
        raise ValueError("auto_block_min_risk must be between 1 and 100")
    return value

def _resolve_ttl(ttl, policy):
    if ttl is None:
        ttl = policy.get('default_ttl')
    return _validate_ttl(ttl, allow_none=True, max_ttl=policy.get('max_ttl', 86400))

def _apply_block_rule(ip):
    backend = FIREWALL_BACKEND
    if backend not in ('auto', 'nft', 'iptables'):
        raise ValueError("SENTINEL_FIREWALL_BACKEND must be auto, nft, or iptables")
    if backend in ('auto', 'nft') and shutil.which('nft'):
        _ensure_nft_blacklist()
        return _run_cmd(['nft', 'add', 'element', 'inet', 'sentinel', 'blacklist', '{', ip, '}'])
    if backend == 'nft':
        return False, 'nft command not found'
    return _run_cmd(['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP', '-m', 'comment', '--comment', 'SentinelEdgeAI'])

def _ensure_nft_blacklist():
    _run_cmd(['nft', 'add', 'table', 'inet', 'sentinel'])
    _run_cmd(['nft', 'add', 'set', 'inet', 'sentinel', 'blacklist', '{', 'type', 'ipv4_addr', ';', '}'])

def _remove_block_rule(ip):
    results = []
    backend = FIREWALL_BACKEND
    if backend in ('auto', 'iptables'):
        results.append(_run_cmd(['iptables', '-D', 'INPUT', '-s', ip, '-j', 'DROP']))
    if backend in ('auto', 'nft') and shutil.which('nft'):
        results.append(_run_cmd(['nft', 'delete', 'element', 'inet', 'sentinel', 'blacklist', '{', ip, '}']))
    return results

def _is_active(rule, now=None):
    if not rule.get('blocked'):
        return False
    expires = rule.get('expires')
    if not expires:
        return True
    now = int(now or time.time())
    return int(expires) > now

def expire_rules(now=None):
    """Remove expired TTL rules from active state and best-effort remove system rules."""
    now = int(now or time.time())
    rules = _read_rules()
    expired = []
    active = []
    for rule in rules:
        if rule.get('blocked') and rule.get('expires') and int(rule.get('expires')) <= now:
            expired.append(rule)
        else:
            active.append(rule)
    if not expired:
        return {'expired': 0, 'rules_left': len(rules)}
    _write_rules(active)
    for rule in expired:
        ip = rule.get('ip')
        if ip and not FIREWALL_DRY_RUN:
            _remove_block_rule(ip)
        _log_action({'action': 'expire', 'ip': ip, 'reason': 'ttl_expired', 'dry_run': FIREWALL_DRY_RUN})
    return {'expired': len(expired), 'rules_left': len(active)}

def _run_cmd(cmd):
    """Run a system command safely.

    Expectations and mitigations for Bandit:
    - `cmd` must be a sequence (list/tuple) of argument strings.
    - We validate that no shell meta-characters are present in args.
    - The executable must exist on PATH (checked with `shutil.which`).
    This keeps `shell=False` while reducing risk of executing untrusted input.
    """
    logger = logging.getLogger("sentinel.firewall")

    # Basic validation: expect non-empty list/tuple of strings
    if not isinstance(cmd, (list, tuple)) or not cmd:
        logger.error("Invalid command passed to _run_cmd: not a list/tuple or empty")
        return False, "invalid command"

    for part in cmd:
        if not isinstance(part, str):
            logger.error("Invalid command part type: %r", type(part))
            return False, "invalid command part"
        # reject obvious shell metacharacters in any argument
        if any(ch in part for ch in (';', '&', '|', '>', '<', '$', '`')):
            logger.error("Unsafe character detected in command argument: %r", part)
            return False, "unsafe command"

    # Ensure executable exists (prevent accidental shell lookups)
    prog = shutil.which(cmd[0])
    if not prog:
        logger.error("Command not found on PATH: %s", cmd[0])
        return False, f"command not found: {cmd[0]}"

    try:
        subprocess.check_output(cmd, shell=False, stderr=subprocess.STDOUT)
        return True, None
    except subprocess.CalledProcessError as e:
        return False, e.output.decode('utf-8', errors='ignore')

def add_block(ip: str, ttl: int = None, reason: str = ''):
    """Add a blocking rule for `ip`. If FIREWALL_DRY_RUN is True this only records the action.

    Returns a dict describing the rule and action result.
    """
    expire_rules()
    ip = _validate_ip(ip)
    policy = get_policy()
    if ip in set(policy.get('whitelist', [])):
        raise ValueError(f"refusing to block whitelisted IP: {ip}")
    ttl = _resolve_ttl(ttl, policy)
    rules = _read_rules()
    now = int(time.time())
    expires = (now + ttl) if ttl else None
    rule = {
        'ip': ip,
        'blocked': True,
        'created': now,
        'expires': expires,
        'reason': reason,
        'dry_run': FIREWALL_DRY_RUN,
    }

    # attempt to apply system firewall if not dry-run
    if not FIREWALL_DRY_RUN:
        success, out = _apply_block_rule(ip)
        rule['applied'] = success
        rule['apply_output'] = out

    rules = [r for r in rules if not (r.get('ip') == ip and r.get('blocked'))]
    rules.append(rule)
    _write_rules(rules)
    _log_action({'action': 'block', 'ip': ip, 'ttl': ttl, 'reason': reason, 'dry_run': FIREWALL_DRY_RUN})
    return rule

def remove_block(ip: str):
    expire_rules()
    ip = _validate_ip(ip)
    rules = _read_rules()
    removed = []
    remaining = []
    for r in rules:
        if r.get('ip') == ip and r.get('blocked'):
            removed.append(r)
        else:
            remaining.append(r)
    _write_rules(remaining)
    if not FIREWALL_DRY_RUN:
        _remove_block_rule(ip)
    _log_action({'action': 'unblock', 'ip': ip, 'count': len(removed), 'dry_run': FIREWALL_DRY_RUN})
    return {'removed': len(removed), 'rules_left': len(remaining)}

def rollback_blocks(reason: str = 'operator_rollback'):
    """Remove every active block. Use as an emergency rollback primitive."""
    expire_rules()
    rules = _read_rules()
    active = [r for r in rules if r.get('blocked')]
    for rule in active:
        if not FIREWALL_DRY_RUN:
            _remove_block_rule(rule.get('ip'))
        _log_action({'action': 'rollback_unblock', 'ip': rule.get('ip'), 'reason': reason, 'dry_run': FIREWALL_DRY_RUN})
    _write_rules([r for r in rules if not r.get('blocked')])
    _log_action({'action': 'rollback', 'count': len(active), 'reason': reason, 'dry_run': FIREWALL_DRY_RUN})
    return {'removed': len(active), 'rules_left': 0}

def list_rules():
    expire_rules()
    return _read_rules()
