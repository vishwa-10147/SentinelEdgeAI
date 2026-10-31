"""Response policy as code: one versioned YAML document, validated and diffed before apply.

    python -m enforcement policy export > policy.yaml
    python -m enforcement policy validate policy.yaml
    python -m enforcement policy diff policy.yaml      # dry run: what would change
    python -m enforcement policy apply policy.yaml

Example:

    version: 1
    response_mode: auto_block          # monitor | alert | auto_block
    default_ttl: 300
    max_ttl: 86400
    whitelist: [192.168.1.10]
    management_hosts: [192.168.1.0/28]  # never blocked, like the gateway
    playbook:
      steps:
        - {action: alert, min_risk: 50}
        - {action: rate_limit, min_risk: 65, ttl: 600}
        - {action: block, min_risk: 75, ttl: 3600}
        - {action: quarantine, min_risk: 90, ttl: 86400}
      escalate_after: 3
      window_seconds: 600
      approval: {required_from_risk: 75, days: 30}   # Operator approval for the first 30 days

Every apply is stored in data/policy_history/ and in the audit log.
"""
import copy
import ipaddress
import json
import os
import time

import yaml

import core.firewall as firewall
from enforcement.playbook import ACTIONS, DEFAULT_PLAYBOOK

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
VERSION = 1
KEYS = ('version', 'response_mode', 'default_ttl', 'max_ttl', 'auto_block_min_risk', 'whitelist',
        'management_hosts', 'playbook')


def policy_file():
    return os.environ.get('SENTINEL_RESPONSE_POLICY') or os.path.join(ROOT, 'data', 'response_policy.json')


def history_dir():
    return os.path.join(os.path.dirname(os.path.abspath(policy_file())), 'policy_history')


def _stored():
    try:
        with open(policy_file(), 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def current():
    """The effective policy: firewall settings plus the stored playbook and management hosts."""
    fw = firewall.get_policy()
    stored = _stored()
    return {
        'version': VERSION,
        'response_mode': fw['response_mode'],
        'default_ttl': fw['default_ttl'],
        'max_ttl': fw['max_ttl'],
        'auto_block_min_risk': fw['auto_block_min_risk'],
        'whitelist': fw['whitelist'],
        'management_hosts': stored.get('management_hosts', []),
        'playbook': stored.get('playbook') or copy.deepcopy(DEFAULT_PLAYBOOK),
    }


def parse(text):
    try:
        doc = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise ValueError(f'invalid YAML: {exc}')
    if not isinstance(doc, dict):
        raise ValueError('the policy must be a YAML mapping')
    return doc


def validate(doc):
    """Return (normalised_policy, errors, warnings). Missing keys keep their current value."""
    errors, warnings = [], []
    base = current()
    unknown = sorted(set(doc) - set(KEYS))
    if unknown:
        errors.append(f"unknown keys: {', '.join(unknown)}")
    if doc.get('version', VERSION) != VERSION:
        errors.append(f'version must be {VERSION}')
    out = {k: doc.get(k, base[k]) for k in KEYS}
    out['version'] = VERSION

    if out['response_mode'] not in ('monitor', 'alert', 'auto_block'):
        errors.append('response_mode must be monitor, alert or auto_block')
    for key in ('default_ttl', 'max_ttl'):
        v = out[key]
        # same limit core.firewall enforces, so a valid policy always applies
        if v is not None and (not isinstance(v, int) or v < 1 or v > 86400):
            errors.append(f'{key} must be between 1 and 86400 seconds')
    if isinstance(out['default_ttl'], int) and isinstance(out['max_ttl'], int) and out['default_ttl'] > out['max_ttl']:
        errors.append('default_ttl cannot exceed max_ttl')
    if not isinstance(out['auto_block_min_risk'], int) or not 1 <= out['auto_block_min_risk'] <= 100:
        errors.append('auto_block_min_risk must be 1-100')

    def addresses(key, allow_networks):
        clean = []
        for item in out[key] or []:
            try:
                value = str(ipaddress.ip_network(str(item), strict=False)) if allow_networks and '/' in str(item) \
                    else str(ipaddress.ip_address(str(item)))
            except ValueError:
                errors.append(f'{key}: {item!r} is not a valid address')
                continue
            if value in clean:
                warnings.append(f'{key}: duplicate entry {value}')
                continue
            clean.append(value)
        out[key] = clean

    addresses('whitelist', allow_networks=False)
    addresses('management_hosts', allow_networks=True)

    pb = out['playbook']
    if not isinstance(pb, dict) or not isinstance(pb.get('steps'), list) or not pb['steps']:
        errors.append('playbook.steps must be a non-empty list')
    else:
        last = 0
        for i, step in enumerate(pb['steps']):
            if not isinstance(step, dict) or step.get('action') not in ACTIONS:
                errors.append(f'playbook.steps[{i}].action must be one of {", ".join(ACTIONS)}')
                continue
            risk = step.get('min_risk')
            if not isinstance(risk, int) or not 1 <= risk <= 100:
                errors.append(f'playbook.steps[{i}].min_risk must be 1-100')
            elif risk <= last:
                errors.append(f'playbook.steps[{i}].min_risk must be higher than the previous step')
            else:
                last = risk
            ttl = step.get('ttl')
            if ttl is not None and isinstance(out['max_ttl'], int) and (not isinstance(ttl, int) or ttl > out['max_ttl']):
                errors.append(f'playbook.steps[{i}].ttl must be at most max_ttl ({out["max_ttl"]})')
        for key, lo, hi in (('escalate_after', 1, 100), ('window_seconds', 10, 86400)):
            v = pb.get(key, DEFAULT_PLAYBOOK[key])
            if not isinstance(v, int) or not lo <= v <= hi:
                errors.append(f'playbook.{key} must be {lo}-{hi}')
        approval = pb.get('approval') or {}
        if not isinstance(approval, dict):
            errors.append('playbook.approval must be a mapping')
        else:
            r = approval.get('required_from_risk')
            if r is not None and (not isinstance(r, int) or not 1 <= r <= 100):
                errors.append('playbook.approval.required_from_risk must be 1-100 or empty')
            if 'days' in approval and (not isinstance(approval['days'], int) or approval['days'] < 0):
                errors.append('playbook.approval.days must be a whole number of days')
    if out['response_mode'] == 'auto_block' and not any(
            isinstance(s, dict) and s.get('action') != 'alert' for s in (pb or {}).get('steps', [])):
        warnings.append('auto_block is set but the playbook never enforces (only alert steps)')

    # conflicts with live state
    blocked = {r.get('ip') for r in firewall.list_rules() if r.get('blocked')}
    for ip in out['whitelist']:
        if ip in blocked:
            warnings.append(f'{ip} is whitelisted but currently blocked; the block stays until it expires or is removed')
    return out, errors, warnings


def diff(new, old=None):
    """[(key, old, new)] for every top-level setting that changes."""
    old = old or current()
    changes = []
    for key in KEYS:
        if key == 'version':
            continue
        if old.get(key) != new.get(key):
            changes.append((key, old.get(key), new.get(key)))
    return changes


def apply(doc, by='cli'):
    """Validate and apply; returns {'changes', 'warnings'} or raises ValueError with all errors."""
    new, errors, warnings = validate(doc)
    if errors:
        raise ValueError('; '.join(errors))
    changes = diff(new)
    pb = copy.deepcopy(new['playbook'])
    approval = pb.get('approval') or {}
    if 'days' in approval:
        # turn "for N days" into a fixed end time at apply
        approval['until'] = int(time.time()) + approval.pop('days') * 86400 if approval['days'] else None
        pb['approval'] = approval
    firewall.update_policy({k: new[k] for k in ('response_mode', 'default_ttl', 'max_ttl',
                                                 'auto_block_min_risk', 'whitelist')})
    stored = {'management_hosts': new['management_hosts'], 'playbook': pb, 'applied': int(time.time()),
              'applied_by': str(by)}
    path = policy_file()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(stored, f, indent=2)
    os.replace(tmp, path)
    os.makedirs(history_dir(), exist_ok=True)
    stamp = time.strftime('%Y%m%dT%H%M%S')
    with open(os.path.join(history_dir(), f'{stamp}-{by}.yaml'.replace('/', '_')), 'w', encoding='utf-8') as f:
        f.write(export(new))
    from enforcement import protected
    protected.protected_hosts(refresh=True)
    import core.audit as audit
    audit.record('policy_apply', actor=str(by), details={'changed': [c[0] for c in changes]})
    return {'changes': changes, 'warnings': warnings}


def export(policy=None):
    return yaml.safe_dump(policy or current(), sort_keys=False, default_flow_style=None)


def management_hosts():
    return set(_stored().get('management_hosts', []))
