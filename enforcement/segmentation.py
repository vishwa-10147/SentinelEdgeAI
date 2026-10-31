"""OT micro-segmentation from the OT detector's learned allow-lists (Phase 7).

Every controller that finished its learning period gets its industrial ports
guarded: only the hosts seen commanding it (plus management and whitelisted
hosts, and any exception an Admin adds) may open new connections to them.

Modes:
  off      nothing is installed
  monitor  the plan is shown; the OT detector already alerts on new masters
  enforce  nftables rules in the `sentinel` tables drop everything else

Enforcement uses a frozen snapshot of the plan, so a new master the detector
learns afterwards is not silently allowed: an Admin adds it (`allow`) or takes
a new snapshot (`refresh`). Enforcing needs inline placement, since a passive
sensor sees traffic but cannot stop it. An operator or watchdog rollback
deletes the sentinel tables and turns segmentation off, so nothing comes back
without a person deciding it (availability first).
"""
import ipaddress
import json
import os
import re
import time

import core.audit as audit
import core.firewall as firewall
from detection.ot import OTStore

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
MODES = ('off', 'monitor', 'enforce')
LEARNING = 7 * 86400
PORTS = {'modbus': [('tcp', 502)], 'dnp3': [('tcp', 20000), ('udp', 20000)],
         'bacnet': [('udp', 47808)], 'opcua': [('tcp', 4840)]}
CHAIN = 'ot_segment'


def state_file():
    return os.environ.get('SENTINEL_OT_SEGMENTATION') or os.path.join(ROOT, 'data', 'ot_segmentation.json')


def load():
    try:
        with open(state_file(), 'r', encoding='utf-8') as f:
            state = json.load(f)
    except (OSError, ValueError):
        state = {}
    state.setdefault('mode', 'off')
    state.setdefault('extra', [])
    state.setdefault('plan', None)
    return state


def _save(state):
    path = state_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(state, f, indent=2, sort_keys=True)
    os.replace(tmp, path)


def _ipv4(ip):
    try:
        return ipaddress.ip_address(ip).version == 4
    except ValueError:
        return False


def _always_allowed():
    hosts = set(firewall.get_policy().get('whitelist', []))
    try:
        from enforcement.policy import management_hosts
        hosts |= management_hosts()
    except Exception:
        pass
    return sorted(h for h in hosts if _ipv4(h) and not ipaddress.ip_address(h).is_loopback)   # loopback is never forwarded


def build_plan(store=None, extra=(), now=None, learning=LEARNING, always=None):
    """Controllers to guard and who may reach them, from what the OT detector learned."""
    from enforcement.protected import why_protected
    now = now or time.time()
    own = store is None
    store = store or OTStore()
    try:
        servers, links = store.load()
    finally:
        if own:
            store.close()
    masters = {}
    for src, dst, protocol, function, _ in links:
        masters.setdefault((dst, protocol), set()).add(src)
    for src, dst, protocol in extra:
        masters.setdefault((dst, protocol), set()).add(src)
    always = _always_allowed() if always is None else always
    controllers, learning_now, skipped = [], [], []
    for (ip, protocol), first in sorted(servers.items()):
        if protocol not in PORTS or not _ipv4(ip):
            continue
        reason = why_protected(ip)
        if reason:
            skipped.append({'ip': ip, 'protocol': protocol, 'reason': reason})
            continue
        if now - first < learning:
            learning_now.append({'ip': ip, 'protocol': protocol, 'learned_at': first + learning})
            continue
        allowed = sorted({m for m in masters.get((ip, protocol), ()) if _ipv4(m)} | set(always))
        controllers.append({'ip': ip, 'protocol': protocol, 'allowed': allowed})
    return {'created': now, 'controllers': controllers, 'learning': learning_now, 'skipped': skipped}


def _elements(plan):
    guarded, allowed = set(), set()
    for c in plan['controllers']:
        for l4, port in PORTS[c['protocol']]:
            guarded.add(f"{c['ip']} . {l4} . {port}")
            allowed.update(f"{src} . {c['ip']} . {l4} . {port}" for src in c['allowed'])
    return sorted(guarded), sorted(allowed)


def nft_script(plan, bridge=False):
    """Atomic nft script installing the plan in the inet table (and the bridge table when inline)."""
    guarded, allowed = _elements(plan)
    lines = []
    tables = [(firewall.NFT_TABLE, True)] + ([(firewall.BRIDGE_TABLE, False)] if bridge else [])
    for (family, name), conntrack in tables:
        t = f'{family} {name}'
        lines += [f'add table {t}',
                  f'add set {t} ot_guarded {{ type ipv4_addr . inet_proto . inet_service ; }}',
                  f'add set {t} ot_allowed {{ type ipv4_addr . ipv4_addr . inet_proto . inet_service ; }}',
                  f'flush set {t} ot_guarded', f'flush set {t} ot_allowed']
        if guarded:
            lines.append(f'add element {t} ot_guarded {{ {", ".join(guarded)} }}')
        if allowed:
            lines.append(f'add element {t} ot_allowed {{ {", ".join(allowed)} }}')
        lines += [f'add chain {t} {CHAIN} {{ type filter hook forward priority -15 ; policy accept ; }}',
                  f'flush chain {t} {CHAIN}']
        if conntrack:                                     # replies are never cut (bridged traffic has no conntrack)
            lines.append(f'add rule {t} {CHAIN} ct state established,related return')
        lines += [f'add rule {t} {CHAIN} ip saddr . ip daddr . meta l4proto . th dport @ot_allowed return',
                  f'add rule {t} {CHAIN} ip daddr . meta l4proto . th dport @ot_guarded counter drop']
    return '\n'.join(lines) + '\n'


def _remove_kernel():
    for table in (firewall.NFT_TABLE, firewall.BRIDGE_TABLE):
        ok, _ = firewall._run_cmd(['nft', 'list', 'chain', *table, CHAIN])
        if ok:
            firewall._run_cmd(['nft', 'delete', 'chain', *table, CHAIN])
            firewall._run_cmd(['nft', 'delete', 'set', *table, 'ot_allowed'])
            firewall._run_cmd(['nft', 'delete', 'set', *table, 'ot_guarded'])


def _install(plan):
    if firewall.FIREWALL_DRY_RUN:
        return True, 'dry run'
    return firewall._run_nft_script(nft_script(plan, bridge=firewall.bridge_enabled()))


def _record(action, by, details, outcome='success'):
    audit.record(action, actor=by or 'system', target='ot_segmentation', outcome=outcome, details=details)


def set_mode(mode, by='cli'):
    if mode not in MODES:
        raise ValueError(f'mode must be one of {", ".join(MODES)}')
    state = load()
    if mode == 'enforce':
        if not firewall.bridge_enabled():
            raise ValueError('enforcing segmentation needs inline placement; a passive sensor cannot stop traffic')
        plan = build_plan(extra=state['extra'])
        if not plan['controllers']:
            raise ValueError('no OT controller has finished its learning period yet')
        ok, out = _install(plan)
        if not ok:
            _record('ot_segmentation', by, {'mode': mode, 'error': str(out)[:300]}, outcome='failed')
            raise RuntimeError(f'nftables refused the segmentation rules: {out}')
        state['plan'] = plan
    else:
        if not firewall.FIREWALL_DRY_RUN:
            _remove_kernel()
        state['plan'] = None
    state.update(mode=mode, updated=time.time(), by=by)
    state.pop('suspended', None)
    _save(state)
    _record('ot_segmentation', by, {'mode': mode, 'controllers': len((state['plan'] or {}).get('controllers', []))})
    return status()


def allow(src, dst, protocol, by='cli'):
    """Add an exception: `src` may command controller `dst` over `protocol`."""
    for ip in (src, dst):
        if not _ipv4(ip):
            raise ValueError(f'not an IPv4 address: {ip}')
    if protocol not in PORTS:
        raise ValueError(f'protocol must be one of {", ".join(PORTS)}')
    state = load()
    entry = [src, dst, protocol]
    if entry not in state['extra']:
        state['extra'].append(entry)
    if state['mode'] == 'enforce' and state['plan']:
        for c in state['plan']['controllers']:
            if c['ip'] == dst and c['protocol'] == protocol and src not in c['allowed']:
                c['allowed'] = sorted(c['allowed'] + [src])
        ok, out = _install(state['plan'])
        if not ok:
            raise RuntimeError(f'nftables refused the segmentation rules: {out}')
    _save(state)
    _record('ot_segmentation_allow', by, {'src': src, 'dst': dst, 'protocol': protocol})
    return status()


def refresh(by='cli'):
    """Take a new snapshot of the learned allow-lists while enforcing."""
    state = load()
    if state['mode'] != 'enforce':
        raise ValueError('refresh applies while enforcing; in monitor mode the plan is always current')
    plan = build_plan(extra=state['extra'])
    ok, out = _install(plan)
    if not ok:
        raise RuntimeError(f'nftables refused the segmentation rules: {out}')
    state.update(plan=plan, updated=time.time(), by=by)
    _save(state)
    _record('ot_segmentation_refresh', by, {'controllers': len(plan['controllers'])})
    return status()


def reapply():
    """Re-install an enforced plan after a reboot (the kernel ruleset does not survive one)."""
    state = load()
    if state['mode'] == 'enforce' and state['plan']:
        return _install(state['plan'])
    return True, 'nothing to apply'


def on_rollback(reason):
    """A rollback removed every rule; stay off until a person turns segmentation back on."""
    state = load()
    if state['mode'] != 'enforce':
        return
    state.update(mode='off', plan=None, suspended={'reason': reason, 'at': time.time()})
    _save(state)
    _record('ot_segmentation', 'system', {'mode': 'off', 'reason': reason})


def _drops():
    if firewall.FIREWALL_DRY_RUN:
        return None
    total = 0
    for table in (firewall.NFT_TABLE, firewall.BRIDGE_TABLE):
        ok, listing = firewall._run_cmd(['nft', 'list', 'chain', *table, CHAIN])
        if ok:
            total += sum(int(n) for n in re.findall(r'counter packets (\d+)', listing))
    return total


def status():
    state = load()
    out = {'mode': state['mode'], 'updated': state.get('updated'), 'by': state.get('by'),
           'exceptions': state['extra'], 'inline': firewall.bridge_enabled(), 'dry_run': firewall.FIREWALL_DRY_RUN}
    if state.get('suspended'):
        out['suspended'] = state['suspended']
    if state['mode'] == 'enforce':
        out['plan'] = state['plan']
        out['dropped_packets'] = _drops()
    else:
        out['plan'] = build_plan(extra=state['extra'])
    return out
