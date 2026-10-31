"""Fleet management actions shared by the CLI and the console API (validated, audited)."""
import os
import time

import core.audit as audit
from fleet import keys, rollout
from fleet.store import FleetStore

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
PRESETS = ('home', 'office', 'ot', 'enterprise')


def store():
    return FleetStore()


def overview(st=None):
    st = st or store()
    now = time.time()
    sites = st.list_sites()
    return {'server': keys.enabled(), 'ca_fingerprint': keys.ca_fingerprint() if keys.enabled() else None,
            'sites': sites,
            'groups': [{**g, 'rollout': rollout.rollout_status(g, sites, now)} for g in st.list_groups()],
            'templates': st.list_templates(), 'federated': st.rounds()}


def put_template(name, yaml_text=None, preset=None, by='cli', st=None):
    from enforcement import policy
    if not name or len(name) > 64:
        raise ValueError('template name must be 1-64 characters')
    if preset:
        if preset not in PRESETS:
            raise ValueError(f'preset must be one of {", ".join(PRESETS)}')
        with open(os.path.join(ROOT, 'presets', f'{preset}.yaml'), 'r', encoding='utf-8') as f:
            yaml_text = f.read()
    if not yaml_text:
        raise ValueError('a template needs YAML or a preset')
    _, errors, _ = policy.validate(policy.parse(yaml_text))
    if errors:
        raise ValueError('; '.join(errors))
    version = (st or store()).put_template(name, yaml_text, by)
    audit.record('fleet_template_put', actor=by, target=name, details={'version': version})
    return version


def put_group(name, template=None, target_version=None, stages=None, by='cli', st=None):
    st = st or store()
    if not name or len(name) > 64:
        raise ValueError('group name must be 1-64 characters')
    old = st.get_group(name) or {}
    if template and not st.get_template(template):
        raise ValueError(f'unknown template: {template}')
    if target_version and not rollout.VERSION.match(str(target_version)):
        raise ValueError('target version must look like 2.4.0')
    stages = rollout.validate_stages(stages) if stages else (old.get('stages') or None)
    group = st.put_group(name, template if template is not None else old.get('template'),
                         target_version if target_version is not None else old.get('target_version'), stages, by)
    audit.record('fleet_group_put', actor=by, target=name,
                 details={'template': group['template'], 'target_version': group['target_version']})
    return group


def set_rollout(name, action, by='cli', st=None):
    st = st or store()
    if not st.get_group(name):
        raise ValueError(f'unknown group: {name}')
    if action == 'pause':
        st.pause_group(name, f'paused by {by}')
    elif action == 'resume':
        st.resume_group(name)
    else:
        raise ValueError('action must be pause or resume')
    audit.record(f'fleet_rollout_{action}', actor=by, target=name)
    return st.get_group(name)


def enrolment_code(group='default', by='cli', st=None):
    code = (st or store()).create_code(group)
    audit.record('fleet_code', actor=by, details={'group': group})
    return {'code': code, 'group': group, 'ca_fingerprint': keys.ca_fingerprint() if keys.enabled() else None}


def start_round(min_sites=2, model='autoencoder', by='cli', st=None):
    if model != 'autoencoder':
        raise ValueError('only the autoencoder is trained federated')
    if not 1 <= int(min_sites) <= 1000:
        raise ValueError('min_sites must be between 1 and 1000')
    r = (st or store()).start_round(model, int(min_sites), by)
    audit.record('federated_round_start', actor=by, target=f"round {r['id']}", details={'min_sites': r['min_sites']})
    return r


def close_round(round_id, by='cli', st=None):
    (st or store()).close_round(int(round_id))
    audit.record('federated_round_close', actor=by, target=f'round {round_id}')
    return {'closed': int(round_id)}


ACTIONS = ('block', 'unblock', 'quarantine', 'ratelimit', 'contain', 'release')
RELEASABLE = ('quarantine', 'ratelimit', 'contain')
MAX_TTL = 86400


def queue_action(site_id, kind, ip, ttl=3600, reason='', release_kind=None, by='cli', st=None):
    """Queue a response for one site. It is delivered with the site's next report (within 5 minutes) and runs
    through that site's own checks: whitelist, protected hosts, learned profiles, TTL limits."""
    import ipaddress
    st = st or store()
    site = st.get_site(site_id)
    if not site or site['revoked']:
        raise ValueError(f'unknown or revoked site: {site_id}')
    if kind not in ACTIONS:
        raise ValueError(f'action must be one of {", ".join(ACTIONS)}')
    try:
        ip = str(ipaddress.ip_address(str(ip)))
    except ValueError:
        raise ValueError(f'invalid ip: {ip}')
    if kind == 'release':
        if release_kind not in RELEASABLE:
            raise ValueError(f'release needs kind {", ".join(RELEASABLE)}')
        kind = f'release:{release_kind}'
        ttl = None
    elif kind == 'unblock':
        ttl = None
    else:
        try:
            ttl = int(ttl if ttl is not None else 3600)
        except (TypeError, ValueError):
            raise ValueError('ttl must be a number of seconds')
        if not 60 <= ttl <= MAX_TTL:
            raise ValueError(f'remote actions must expire: ttl between 60 and {MAX_TTL} seconds')
    action = st.queue_action(site_id, kind, ip, ttl, reason, by)
    audit.record('fleet_action_queued', actor=by, target=f'{site_id}:{ip}',
                 details={'id': action['id'], 'kind': kind, 'ttl': ttl, 'reason': (reason or '')[:200]})
    return action


def cancel_action(action_id, by='cli', st=None):
    if not (st or store()).cancel_action(action_id):
        raise ValueError('only queued (not yet delivered) actions can be cancelled')
    audit.record('fleet_action_cancelled', actor=by, target=f'action {action_id}')
    return {'cancelled': int(action_id)}


def search_alerts(by='cli', st=None, **filters):
    import ipaddress
    if filters.get('ip'):
        try:
            filters['ip'] = str(ipaddress.ip_address(str(filters['ip'])))
        except ValueError:
            raise ValueError('invalid ip')
    for k in ('min_score', 'since', 'until', 'limit'):
        if filters.get(k) in ('', None):
            filters.pop(k, None)
            continue
        try:
            filters[k] = float(filters[k]) if k == 'min_score' else int(filters[k])
        except (TypeError, ValueError):
            raise ValueError(f'{k} must be a number')
    filters = {k: v for k, v in filters.items() if v not in (None, '')}
    rows = (st or store()).search_alerts(**filters)
    return {'alerts': rows, 'count': len(rows)}
