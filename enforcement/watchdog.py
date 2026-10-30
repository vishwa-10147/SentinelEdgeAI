"""Fail-open watchdog: if the enforcer dies, its rules must not keep cutting traffic.

Run every 20 s by sentineledgeai-watchdog.timer. When the engine or the API
has been down for THRESHOLD consecutive checks while blocks, quarantines or
rate limits are active, every SentinelEdgeAI kernel rule is removed (the
same as an operator rollback), so the network keeps working without the
appliance. Nothing happens while enforcement is not active.
"""
import json
import os
import subprocess  # nosec B404 - fixed systemctl invocation only
import sys
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
SERVICES = ('sentineledgeai-engine.service', 'sentineledgeai-api.service')
THRESHOLD = int(os.environ.get('SENTINEL_WATCHDOG_THRESHOLD', '3'))


def state_file():
    return os.environ.get('SENTINEL_WATCHDOG_STATE') or os.path.join(ROOT, 'data', 'watchdog.json')


def service_active(name):
    try:
        cp = subprocess.run(['systemctl', 'is-active', '--quiet', name], timeout=10, check=False)  # nosec B603 B607
        return cp.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


def _load():
    try:
        with open(state_file(), 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {'failures': 0}


def _save(state):
    os.makedirs(os.path.dirname(os.path.abspath(state_file())), exist_ok=True)
    with open(state_file(), 'w', encoding='utf-8') as f:
        json.dump(state, f)


def check(is_active=service_active, firewall_module=None):
    """One watchdog pass. Returns a short status string."""
    import core.firewall as firewall
    fw = firewall_module or firewall
    down = [s for s in SERVICES if not is_active(s)]
    state = _load()
    if not down:
        if state.get('failures'):
            _save({'failures': 0})
        return 'healthy'
    state['failures'] = int(state.get('failures', 0)) + 1
    state['down'] = down
    state['last'] = time.time()
    _save(state)
    active = [r for r in fw.list_rules() if r.get('blocked')] + list(fw.list_restrictions())
    if not active:
        return f"down ({', '.join(down)}), nothing enforced"
    if state['failures'] < THRESHOLD:
        return f"down ({', '.join(down)}), {state['failures']}/{THRESHOLD}"
    result = fw.rollback_blocks(reason='watchdog: enforcer down')
    import core.audit as audit
    audit.record('watchdog_failopen', actor='watchdog', actor_kind='system',
                 details={'down': down, 'result': result})
    _save({'failures': 0, 'failopen_at': time.time()})
    return f"fail-open: removed all rules ({', '.join(down)} down)"


def main():
    print(check(), flush=True)
    return 0


if __name__ == '__main__':
    sys.exit(main())
