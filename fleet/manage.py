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
            'templates': st.list_templates()}


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
