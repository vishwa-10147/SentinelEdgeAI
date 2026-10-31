import os
import json
import subprocess  # nosec B404 - only fixed firewall binaries are run, see _run_cmd
import tempfile
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
        'whitelist': ['127.0.0.1', '::1'],
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
    if parsed.version == 6 and parsed.ipv4_mapped:
        # ::ffff:a.b.c.d reaches the kernel as plain IPv4 traffic
        parsed = parsed.ipv4_mapped
    return str(parsed)


def _ip_version(ip: str) -> int:
    return ipaddress.ip_address(ip).version

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

RULE_COMMENT = 'SentinelEdgeAI'
NFT_TABLE = ('inet', 'sentinel')
NFT_SET = 'blacklist'
NFT_SET6 = 'blacklist6'
NFT_SETS = {NFT_SET: 'ipv4_addr', NFT_SET6: 'ipv6_addr'}

# Each chain drops blacklisted sources; FORWARD also drops traffic *to* a
# blocked host so a device behind the appliance (inline mode) is isolated.
NFT_CHAINS = {
    'input': ['ip saddr @blacklist drop', 'ip6 saddr @blacklist6 drop'],
    'forward': [
        'ip saddr @blacklist drop', 'ip daddr @blacklist drop',
        'ip6 saddr @blacklist6 drop', 'ip6 daddr @blacklist6 drop',
    ],
}

IPTABLES_TOOLS = {4: 'iptables', 6: 'ip6tables'}


def _nft_set_for(ip):
    return NFT_SET6 if _ip_version(ip) == 6 else NFT_SET


def _iptables_tool(ip):
    return IPTABLES_TOOLS[_ip_version(ip)]


def _use_nft():
    backend = FIREWALL_BACKEND
    if backend not in ('auto', 'nft', 'iptables'):
        raise ValueError("SENTINEL_FIREWALL_BACKEND must be auto, nft, or iptables")
    if backend == 'iptables':
        return False
    if shutil.which('nft'):
        return True
    if backend == 'nft':
        raise RuntimeError('nft command not found')
    return False


def _iptables_specs(ip):
    """(chain, match) pairs for one blocked IP. Insert, check and delete all use these."""
    target = ['-j', 'DROP', '-m', 'comment', '--comment', RULE_COMMENT]
    return [
        ('INPUT', ['-s', ip] + target),
        ('FORWARD', ['-s', ip] + target),
        ('FORWARD', ['-d', ip] + target),
    ]


def _nft_ruleset_script():
    """nft script that creates whatever part of the sentinel table is missing.

    `add table`/`add set` are idempotent. A missing chain is created with all of
    its rules; an existing chain only gets the rules it lacks (e.g. the IPv6
    rules on a device upgraded from an IPv4-only release), so repeated calls
    never duplicate rules.
    """
    family, table = NFT_TABLE
    lines = [f'add table {family} {table}']
    lines.extend(
        f'add set {family} {table} {name} {{ type {addr_type} ; }}'
        for name, addr_type in NFT_SETS.items()
    )
    for chain, rules in NFT_CHAINS.items():
        exists, listing = _run_cmd(['nft', 'list', 'chain', family, table, chain])
        if exists:
            missing = [rule for rule in rules if rule not in listing]
        else:
            missing = rules
            lines.append(
                f'add chain {family} {table} {chain} '
                f'{{ type filter hook {chain} priority -10 ; policy accept ; }}'
            )
        lines.extend(f'add rule {family} {table} {chain} {rule}' for rule in missing)
    return '\n'.join(lines) + '\n'


def _ensure_nft_ruleset():
    script = _nft_ruleset_script()
    fd, path = tempfile.mkstemp(prefix='sentinel-nft-', suffix='.nft')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(script)
        return _run_cmd(['nft', '-f', path])
    finally:
        os.unlink(path)


def _apply_block_rule(ip):
    try:
        use_nft = _use_nft()
    except RuntimeError as exc:
        return False, str(exc)
    if use_nft:
        ok, out = _ensure_nft_ruleset()
        if not ok:
            return False, out
        ok, out = _run_cmd(['nft', 'add', 'element', *NFT_TABLE, _nft_set_for(ip), '{', ip, '}'])
        if ok and bridge_enabled():
            bok, bout = _run_nft_script(_enforcement_script(bridge=True))
            if bok:
                _run_cmd(['nft', 'add', 'element', *BRIDGE_TABLE, _nft_set_for(ip), '{', ip, '}'])
        return ok, out
    tool = _iptables_tool(ip)
    outputs = []
    for chain, spec in _iptables_specs(ip):
        exists, _ = _run_cmd([tool, '-C', chain] + spec)
        if exists:
            continue
        ok, out = _run_cmd([tool, '-I', chain] + spec)
        if not ok:
            return False, out
        outputs.append(out)
    return True, ''.join(outputs)


def _remove_iptables_rule(ip):
    tool = _iptables_tool(ip)
    results = []
    for chain, spec in _iptables_specs(ip):
        # also clears duplicates left by older versions that inserted blindly
        for _ in range(16):
            exists, _ = _run_cmd([tool, '-C', chain] + spec)
            if not exists:
                break
            results.append(_run_cmd([tool, '-D', chain] + spec))
    return results


def _remove_block_rule(ip):
    results = []
    backend = FIREWALL_BACKEND
    if backend in ('auto', 'iptables') and shutil.which(_iptables_tool(ip)):
        results.extend(_remove_iptables_rule(ip))
    if backend in ('auto', 'nft') and shutil.which('nft'):
        results.append(_run_cmd(['nft', 'delete', 'element', *NFT_TABLE, _nft_set_for(ip), '{', ip, '}']))
        if bridge_enabled():
            results.append(_run_cmd(['nft', 'delete', 'element', *BRIDGE_TABLE, _nft_set_for(ip), '{', ip, '}']))
    return results


def _flush_all_rules():
    """Remove every kernel rule SentinelEdgeAI owns, even ones missing from the state file."""
    results = []
    backend = FIREWALL_BACKEND
    if backend in ('auto', 'nft') and shutil.which('nft'):
        for table in (NFT_TABLE, BRIDGE_TABLE):
            ok, _ = _run_cmd(['nft', 'list', 'table', *table])
            if ok:
                results.append(_run_cmd(['nft', 'delete', 'table', *table]))
    if backend in ('auto', 'iptables'):
        for tool in IPTABLES_TOOLS.values():
            if not shutil.which(tool):
                continue
            for chain in ('INPUT', 'FORWARD'):
                ok, listing = _run_cmd([tool, '-S', chain])
                if not ok:
                    continue
                for line in listing.splitlines():
                    parts = line.split()
                    if len(parts) > 2 and parts[0] == '-A' and RULE_COMMENT in parts:
                        results.append(_run_cmd([tool, '-D'] + parts[1:]))
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

ALLOWED_FIREWALL_COMMANDS = frozenset({'nft', 'iptables', 'ip6tables'})


def _run_cmd(cmd):
    """Run a firewall command safely and return (ok, output).

    Expectations and mitigations for Bandit:
    - `cmd` must be a sequence (list/tuple) of argument strings.
    - Only the binaries in ALLOWED_FIREWALL_COMMANDS may be executed.
    - We validate that no shell meta-characters are present in args.
    - The executable is resolved to an absolute path with `shutil.which`.
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

    if cmd[0] not in ALLOWED_FIREWALL_COMMANDS:
        logger.error("Refusing to run non-firewall command: %s", cmd[0])
        return False, f"command not allowed: {cmd[0]}"

    # Ensure executable exists (prevent accidental shell lookups)
    prog = shutil.which(cmd[0])
    if not prog:
        logger.error("Command not found on PATH: %s", cmd[0])
        return False, f"command not found: {cmd[0]}"

    try:
        cp = subprocess.run(  # nosec B603 - allowlisted binary, validated args, no shell
            [prog] + list(cmd[1:]),
            shell=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as e:
        logger.error("Firewall command failed to run: %s", e)
        return False, str(e)
    output = (cp.stdout or b'').decode('utf-8', errors='ignore')
    return cp.returncode == 0, output

def add_block(ip: str, ttl: int = None, reason: str = ''):
    """Add a blocking rule for `ip`. If FIREWALL_DRY_RUN is True this only records the action.

    Returns a dict describing the rule and action result.
    """
    expire_rules()
    ip = _validate_ip(ip)
    policy = get_policy()
    if ip in set(policy.get('whitelist', [])):
        raise ValueError(f"refusing to block whitelisted IP: {ip}")
    from enforcement.protected import why_protected
    reason_protected = why_protected(ip)
    if reason_protected:
        # gateway, DNS, DHCP, the appliance itself, management hosts
        raise ValueError(f"refusing to block protected host {ip} ({reason_protected})")
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
    if not FIREWALL_DRY_RUN:
        # catch kernel rules the state file no longer knows about
        _flush_all_rules()
    _write_rules([r for r in rules if not r.get('blocked')])
    restricted = _read_restrictions()
    if restricted:
        for r in restricted:
            _remove_restriction_kernel(r)
        _write_restrictions([])
    try:
        from enforcement import segmentation
        segmentation.on_rollback(reason)       # the tables are gone; segmentation stays off until re-enabled
    except Exception:
        pass
    _log_action({'action': 'rollback', 'count': len(active), 'restrictions': len(restricted),
                 'reason': reason, 'dry_run': FIREWALL_DRY_RUN})
    return {'removed': len(active), 'restrictions_removed': len(restricted), 'rules_left': 0}

def list_rules():
    expire_rules()
    return _read_rules()


# ---------- Phase 3: quarantine, rate limiting, inline bridge ----------
#
# Separate chains in the same table, rebuilt atomically on every apply
# (flush + add inside one nft transaction), so set contents survive.
# A quarantined host may only use DNS, DHCP and the console's quarantine page
# (and replies to its existing connections); a rate-limited host is limited
# per source address. A contained host (Phase 7) keeps only the peers and ports
# of its learned profile (detection.peers), plus DNS and DHCP. With inline placement the same sets and rules are
# mirrored into a `bridge` table, which sees bridged frames that the `inet`
# hooks never do.

RESTRICTION_SETS = {
    'quarantine': {4: 'quarantine', 6: 'quarantine6'},
    'ratelimit': {4: 'ratelimit', 6: 'ratelimit6'},
    'contain': {4: 'contain', 6: 'contain6'},
}
PRIVATE4 = '{ 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 100.64.0.0/10 }'
BRIDGE_TABLE = ('bridge', 'sentinel')


def _restrictions_file():
    return os.path.join(ROOT, 'firewall_restrictions.json')


def _read_restrictions():
    try:
        with open(_restrictions_file(), 'r') as f:
            return json.load(f)
    except Exception:
        return []


def _write_restrictions(items):
    _ensure_files()
    fd, tmp = tempfile.mkstemp(dir=ROOT, prefix='.restrictions-')
    with os.fdopen(fd, 'w') as f:
        json.dump(items, f, indent=2)
    os.replace(tmp, _restrictions_file())


def bridge_enabled():
    if os.environ.get('SENTINEL_BRIDGE') in ('0', '1'):
        return os.environ['SENTINEL_BRIDGE'] == '1'
    try:
        from core import setup as device_setup
        return device_setup.load().get('placement') == 'inline'
    except Exception:
        return False


def _enforcement_script(bridge=None):
    captive = int(os.environ.get('SENTINEL_PORT', '9000'))
    pps = int(os.environ.get('SENTINEL_RATELIMIT_PPS', '100'))
    burst = max(pps * 2, 10)
    fam, tbl = NFT_TABLE
    t = f'{fam} {tbl}'
    lines = [f'add table {t}']
    for sets in RESTRICTION_SETS.values():
        lines.append(f'add set {t} {sets[4]} {{ type ipv4_addr ; }}')
        lines.append(f'add set {t} {sets[6]} {{ type ipv6_addr ; }}')
    lines += [
        f'add set {t} rlmeter {{ type ipv4_addr ; flags dynamic ; timeout 1m ; }}',
        f'add set {t} rlmeter6 {{ type ipv6_addr ; flags dynamic ; timeout 1m ; }}',
        f'add chain {t} quarantine_check',
        f'flush chain {t} quarantine_check',
        f'add rule {t} quarantine_check udp dport {{ 53, 67, 68 }} return',
        f'add rule {t} quarantine_check tcp dport {{ 53, {captive} }} return',
        f'add rule {t} quarantine_check ct state established,related return',
        f'add rule {t} quarantine_check drop',
    ]
    lines += _contain_chain(t, conntrack=True)
    limit4 = f'update @rlmeter {{ ip saddr limit rate over {pps}/second burst {burst} packets }} drop'
    limit6 = f'update @rlmeter6 {{ ip6 saddr limit rate over {pps}/second burst {burst} packets }} drop'
    for chain, hook in (('enf_input', 'input'), ('enf_forward', 'forward')):
        lines += [
            f'add chain {t} {chain} {{ type filter hook {hook} priority -20 ; policy accept ; }}',
            f'flush chain {t} {chain}',
            f'add rule {t} {chain} ip saddr @quarantine jump quarantine_check',
            f'add rule {t} {chain} ip6 saddr @quarantine6 jump quarantine_check',
            f'add rule {t} {chain} ip saddr @contain jump contain_check',
            f'add rule {t} {chain} ip saddr @ratelimit {limit4}',
            f'add rule {t} {chain} ip6 saddr @ratelimit6 {limit6}',
        ]
        if hook == 'forward':
            # nothing new may reach a quarantined host
            lines += [f'add rule {t} {chain} ip daddr @quarantine ct state new drop',
                      f'add rule {t} {chain} ip6 daddr @quarantine6 ct state new drop']
    if bridge if bridge is not None else bridge_enabled():
        b = ' '.join(BRIDGE_TABLE)
        lines += [f'add table {b}',
                  f'add set {b} blacklist {{ type ipv4_addr ; }}', f'add set {b} blacklist6 {{ type ipv6_addr ; }}',
                  f'add set {b} quarantine {{ type ipv4_addr ; }}', f'add set {b} quarantine6 {{ type ipv6_addr ; }}',
                  f'add set {b} qmac {{ type ether_addr ; }}',
                  f'add set {b} contain {{ type ipv4_addr ; }}']
        lines += _contain_chain(b, conntrack=False)
        lines += [f'add chain {b} forward {{ type filter hook forward priority -10 ; policy accept ; }}',
                  f'flush chain {b} forward']
        lines += [f'add rule {b} forward {r}' for r in (
            'ip saddr @blacklist drop', 'ip daddr @blacklist drop',
            'ip6 saddr @blacklist6 drop', 'ip6 daddr @blacklist6 drop',
            'ether saddr @qmac udp dport { 53, 67, 68 } accept',
            'ether saddr @qmac drop',
            'ip saddr @quarantine udp dport { 53, 67, 68 } accept',
            'ip saddr @quarantine drop', 'ip6 saddr @quarantine6 drop',
            'ip saddr @contain jump contain_check',
        )]
    return '\n'.join(lines) + '\n'


def _contain_chain(t, conntrack):
    """contain_check for table `t`: DNS/DHCP, then the learned peers, then nothing internal, then learned internet ports.

    Bridged frames have no conntrack here, so the bridge chain lets packets of
    existing TCP connections through and stops only new ones (SYN without ACK).
    """
    lines = [f'add set {t} contain_peers {{ type ipv4_addr . ipv4_addr . inet_proto . inet_service ; }}',
             f'add set {t} contain_ext {{ type ipv4_addr . inet_proto . inet_service ; }}',
             f'add chain {t} contain_check', f'flush chain {t} contain_check']
    first = 'ct state established,related return' if conntrack else 'tcp flags & (syn | ack) != syn return'
    lines += [f'add rule {t} contain_check {r}' for r in (
        first, 'udp dport { 53, 67, 68 } return',
        'ip saddr . ip daddr . meta l4proto . th dport @contain_peers return',
        f'ip daddr {PRIVATE4} drop',
        'ip saddr . meta l4proto . th dport @contain_ext return',
        'drop')]
    return lines


def _contain_elements_script(bridge=None):
    """Refill the peer sets from the learned profiles of every contained host."""
    from detection.peers import PeerStore
    contained = sorted({r['ip'] for r in _read_restrictions() if r['kind'] == 'contain'})
    peers, ext = [], []
    store = PeerStore()
    try:
        for ip in contained:
            profile = store.profile(ip) or {'internal': [], 'external': []}
            peers += [f'{ip} . {dst} . {proto} . {port}' for dst, proto, port in profile['internal']]
            ext += [f'{ip} . {proto} . {port}' for proto, port in profile['external']]
    finally:
        store.close()
    tables = [NFT_TABLE] + ([BRIDGE_TABLE] if (bridge if bridge is not None else bridge_enabled()) else [])
    lines = []
    for fam, tbl in tables:
        t = f'{fam} {tbl}'
        lines += [f'flush set {t} contain_peers', f'flush set {t} contain_ext']
        if peers:
            lines.append(f'add element {t} contain_peers {{ {", ".join(peers)} }}')
        if ext:
            lines.append(f'add element {t} contain_ext {{ {", ".join(ext)} }}')
    return '\n'.join(lines) + '\n'


def _run_nft_script(script):
    fd, path = tempfile.mkstemp(prefix='sentinel-nft-', suffix='.nft')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(script)
        return _run_cmd(['nft', '-f', path])
    finally:
        os.unlink(path)


def _set_element(op, table, name, value):
    return _run_cmd(['nft', op, 'element', *table, name, '{', value, '}'])


def _expire_restrictions(now=None):
    now = int(now or time.time())
    items = _read_restrictions()
    keep = [r for r in items if not r.get('expires') or int(r['expires']) > now]
    for r in items:
        if r not in keep:
            _remove_restriction_kernel(r)
            _log_action({'action': f"{r['kind']}_expire", 'ip': r['ip'], 'dry_run': FIREWALL_DRY_RUN})
    if len(keep) != len(items):
        _write_restrictions(keep)
    return keep


def _remove_restriction_kernel(r):
    if FIREWALL_DRY_RUN or not shutil.which('nft'):
        return
    name = RESTRICTION_SETS[r['kind']][_ip_version(r['ip'])]
    _set_element('delete', NFT_TABLE, name, r['ip'])
    if r['kind'] in ('quarantine', 'contain') and bridge_enabled():
        _set_element('delete', BRIDGE_TABLE, name, r['ip'])
        if r.get('mac'):
            _set_element('delete', BRIDGE_TABLE, 'qmac', r['mac'])


def add_restriction(kind, ip, ttl=None, reason='', mac=None):
    """Quarantine, rate-limit or contain `ip` (refused for whitelisted and protected hosts)."""
    if kind not in RESTRICTION_SETS:
        raise ValueError('kind must be quarantine, ratelimit or contain')
    ip = _validate_ip(ip)
    policy = get_policy()
    if ip in set(policy.get('whitelist', [])):
        raise ValueError(f'refusing to {kind} whitelisted IP: {ip}')
    from enforcement.protected import why_protected
    reason_protected = why_protected(ip)
    if reason_protected:
        raise ValueError(f'refusing to {kind} protected host {ip} ({reason_protected})')
    if kind == 'contain':
        from detection.peers import PeerStore, learned
        if _ip_version(ip) != 4:
            raise ValueError('containment is IPv4 only; quarantine an IPv6 host instead')
        store = PeerStore()
        try:
            profile = store.profile(ip)
        finally:
            store.close()
        if not learned(profile):
            raise ValueError(f'{ip} has no learned peer profile yet (7 days); quarantine it instead')
    ttl = _resolve_ttl(ttl, policy)
    now = int(time.time())
    item = {'kind': kind, 'ip': ip, 'mac': mac, 'created': now, 'expires': (now + ttl) if ttl else None,
            'reason': reason, 'dry_run': FIREWALL_DRY_RUN}
    if not FIREWALL_DRY_RUN:
        ok, out = _run_nft_script(_enforcement_script())
        if ok:
            ok, out = _set_element('add', NFT_TABLE, RESTRICTION_SETS[kind][_ip_version(ip)], ip)
        if ok and kind in ('quarantine', 'contain') and bridge_enabled():
            _set_element('add', BRIDGE_TABLE, RESTRICTION_SETS[kind][_ip_version(ip)], ip)
            if mac and kind == 'quarantine':
                _set_element('add', BRIDGE_TABLE, 'qmac', mac)
        item['applied'], item['apply_output'] = ok, out
    items = [r for r in _expire_restrictions() if not (r['kind'] == kind and r['ip'] == ip)]
    items.append(item)
    _write_restrictions(items)
    if kind == 'contain' and not FIREWALL_DRY_RUN and item.get('applied'):
        ok, out = _run_nft_script(_contain_elements_script())
        if not ok:
            item['applied'], item['apply_output'] = False, out
            _write_restrictions(items)
    _log_action({'action': kind, 'ip': ip, 'ttl': ttl, 'reason': reason, 'dry_run': FIREWALL_DRY_RUN})
    return item


def remove_restriction(kind, ip):
    ip = _validate_ip(ip)
    items = _expire_restrictions()
    removed = [r for r in items if r['kind'] == kind and r['ip'] == ip]
    for r in removed:
        _remove_restriction_kernel(r)
    _write_restrictions([r for r in items if r not in removed])
    _log_action({'action': f'{kind}_release', 'ip': ip, 'count': len(removed), 'dry_run': FIREWALL_DRY_RUN})
    return {'removed': len(removed)}


def list_restrictions():
    return _expire_restrictions()
