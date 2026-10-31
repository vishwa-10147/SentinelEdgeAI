"""Fleet agent: runs on every site, reports to the fleet server and applies its desired state.

  enroll   pin the fleet CA by fingerprint, send a CSR with a one-time code; the key stays here
  report   send a status report (every 5 minutes from sentineledgeai-fleet-agent.timer) and apply:
             - the group's configuration template (response policy as code), validated before it is applied
             - the target version, written to desired_version for the root update timer
               (sentinelctl fleet-update), because the agent itself runs unprivileged

State lives in SENTINEL_FLEET_AGENT_DIR (default data/fleet_agent).
"""
import json
import os
import socket
import time
import warnings

import requests
import urllib3

import core.audit as audit
from common import pki

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
TIMEOUT = 10


class AgentError(RuntimeError):
    pass


def agent_dir():
    return os.environ.get('SENTINEL_FLEET_AGENT_DIR') or os.path.join(ROOT, 'data', 'fleet_agent')


def _path(name):
    return os.path.join(agent_dir(), name)


def _write(name, text, private=False):
    os.makedirs(agent_dir(), mode=0o700, exist_ok=True)
    tmp = _path(name + '.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600 if private else 0o644)
    with os.fdopen(fd, 'w', encoding='utf-8') as f:
        f.write(text)
    os.replace(tmp, _path(name))


def _read_json(name, default=None):
    try:
        with open(_path(name), 'r', encoding='utf-8') as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def identity():
    return _read_json('site.json')


def enroll(fleet_url, code, ca_fingerprint, name=None, timeout=TIMEOUT):
    """Enrol this site; returns its site id."""
    fleet_url = fleet_url.rstrip('/')
    try:
        with warnings.catch_warnings():
            warnings.simplefilter('ignore', urllib3.exceptions.InsecureRequestWarning)
            ca = requests.get(f'{fleet_url}/v1/ca', verify=False, timeout=timeout).json()['ca']  # nosec B501 - pinned below
    except (requests.RequestException, ValueError, KeyError) as exc:
        raise AgentError(f'could not reach the fleet server: {exc}')
    if pki.fingerprint(ca) != ca_fingerprint.replace(':', '').lower():
        raise AgentError('the fleet CA fingerprint does not match; refusing to enrol')
    _write('ca.pem', ca)
    key, csr = pki.make_csr(name or socket.gethostname())
    try:
        r = requests.post(f'{fleet_url}/v1/enroll', json={'code': code, 'csr': csr, 'name': name or socket.gethostname()},
                          verify=_path('ca.pem'), timeout=timeout)
    except requests.RequestException as exc:
        raise AgentError(f'enrolment request failed: {exc}')
    if r.status_code != 200:
        raise AgentError(f"fleet server refused enrolment: {r.json().get('detail', r.text)}")
    body = r.json()
    _write('site.key', key, private=True)
    _write('site.pem', body['certificate'])
    _write('site.json', json.dumps({'site_id': body['site_id'], 'group': body['group'], 'fleet_url': fleet_url,
                                    'enrolled': int(time.time())}, indent=2))
    audit.record('fleet_enroll', target=body['site_id'], details={'fleet': fleet_url, 'group': body['group']})
    return body['site_id']


def version():
    try:
        with open(os.path.join(ROOT, 'VERSION'), 'r', encoding='utf-8') as f:
            return f.read().strip()
    except OSError:
        return 'unknown'


def _part(fn, default=None):
    try:
        return fn()
    except Exception:
        return default


def _alerts_24h():
    from core.storage import get_storage
    s = get_storage('data/sentinel.db')
    s.connect()
    since = time.time() - 86400
    out = {'critical': 0, 'high': 0, 'other': 0}
    for a in s.get_alerts(limit=5000):
        if float(a.get('timestamp') or 0) < since:
            continue
        score = float(a.get('score') or 0)
        out['critical' if score >= 75 else 'high' if score >= 50 else 'other'] += 1
    return out


def _trust():
    from enforcement import trust
    out = {'trusted': 0, 'watch': 0, 'untrusted': 0}
    for d in trust.scores():
        out[d['level']] += 1
    return out


def _restrictions():
    import core.firewall as firewall
    out = {'block': sum(1 for r in firewall.list_rules() if r.get('blocked'))}
    for r in firewall.list_restrictions():
        out[r['kind']] = out.get(r['kind'], 0) + 1
    return out


def _system():
    import psutil
    temps = _part(lambda: psutil.sensors_temperatures(), {}) or {}
    temp = next((t[0].current for t in temps.values() if t), None)
    return {'uptime_s': int(time.time() - psutil.boot_time()), 'cpu_percent': psutil.cpu_percent(interval=0.2),
            'memory_percent': psutil.virtual_memory().percent, 'temperature_c': temp}


def collect_report():
    """Compact site status: no flows, no packet data, nothing that identifies a person."""
    from core import setup as device_setup
    from enforcement import segmentation
    from detection.ot import OTStore
    setup = _part(device_setup.load, {}) or {}

    def ot_controllers():
        s = OTStore()
        try:
            return len(s.load()[0])
        finally:
            s.close()
    return {
        'version': version(), 'hostname': socket.gethostname(), 'time': int(time.time()),
        'role': setup.get('network_role', 'standalone'), 'placement': setup.get('placement', 'passive'),
        'response_mode': setup.get('response_mode'),
        'alerts_24h': _part(_alerts_24h, {}), 'trust': _part(_trust, {}), 'restrictions': _part(_restrictions, {}),
        'segmentation': _part(lambda: segmentation.load()['mode'], 'unknown'), 'ot_controllers': _part(ot_controllers, 0),
        'system': _part(_system, {}), 'template': (_read_json('state.json', {}) or {}).get('template'),
        'update': _read_json('update_result.json'),
        'federated': {'installed_round': ((_read_json('state.json', {}) or {}).get('federated') or {}).get('installed_round'),
                      'samples': _part(lambda: _samples().stats()['samples'], 0)},
    }


def _samples():
    from detection.samples import SampleStore
    return SampleStore()


def _federated(desired, state, session, ident):
    """Answer an open round with a local update; install a new global model as a shadow model."""
    from detection import federated, registry
    fed = state.setdefault('federated', {})
    rnd, latest = desired.get('federated_round'), desired.get('federated_model')
    if not rnd and not latest:
        return
    store = _samples()
    try:
        rows = store.rows()
    finally:
        store.close()
    if rnd and fed.get('submitted_round') != rnd['round']:
        if len(rows) < federated.MIN_SAMPLES:
            fed['note'] = f'round {rnd["round"]}: only {len(rows)} normal flows sampled, need {federated.MIN_SAMPLES}'
        else:
            update = federated.local_update(rows, rnd.get('base'))
            r = session.post(f"{ident['fleet_url']}/v1/federated/update",
                             json={'round': rnd['round'], 'model': rnd.get('model', 'autoencoder'), 'update': update},
                             timeout=TIMEOUT)
            if r.status_code == 200:
                fed.update(submitted_round=rnd['round'], note=None)
                audit.record('federated_update', actor='fleet', target=f"round {rnd['round']}",
                             details={'n_samples': update['n_samples']})
            else:
                fed['note'] = f"round {rnd['round']}: update refused ({r.status_code})"
    if latest and fed.get('installed_round') != latest['round']:
        model = federated.build_model(latest['global'])
        local = len(rows) >= federated.MIN_SAMPLES
        if local:
            federated.calibrate(model, rows)              # the threshold fits this site's own traffic
        version = registry.register('autoencoder', model, {
            'federated_round': latest['round'], 'sites': latest['global'].get('sites'),
            'n_samples': latest['global'].get('n_samples'), 'threshold': round(model.threshold, 5),
            'threshold_from': 'local traffic' if local else 'federation'}, model.features,
            notes=f"federated round {latest['round']}")
        fed.update(installed_round=latest['round'], installed_version=version)
        audit.record('federated_model', actor='fleet', target=f'autoencoder v{version}',
                     details={'round': latest['round'], 'stage': 'shadow'})


def _apply_template(template, state):
    """Validate and apply the group's policy template if it changed. Returns a status string."""
    if not template:
        return 'none'
    if state.get('template', {}).get('version') == template['version']:
        return 'unchanged'
    from enforcement import policy
    try:
        result = policy.apply(policy.parse(template['yaml']), by=f"fleet:{template['name']}")
    except ValueError as exc:
        audit.record('fleet_template', target=template['name'], outcome='rejected', details={'error': str(exc)[:300]})
        state['template_error'] = str(exc)[:300]
        return 'rejected'
    state['template'] = {'name': template['name'], 'version': template['version'], 'applied': int(time.time())}
    state.pop('template_error', None)
    audit.record('fleet_template', actor='fleet', target=template['name'],
                 details={'version': template['version'], 'changed': [c[0] for c in result['changes']]})
    return 'applied'


def _apply_version(target):
    if target:
        _write('desired_version', target + '\n')
    elif os.path.exists(_path('desired_version')):
        os.remove(_path('desired_version'))


def report_once(session=None):
    """Send one report and apply the answer. Returns the agent state."""
    ident = identity()
    if not ident:
        raise AgentError('this site is not enrolled; run: python -m fleet enroll ...')
    state = _read_json('state.json', {}) or {}
    if session is None:
        session = requests.Session()
        session.cert = (_path('site.pem'), _path('site.key'))
        session.verify = _path('ca.pem')
    try:
        r = session.post(f"{ident['fleet_url']}/v1/report", json=collect_report(), timeout=TIMEOUT)
        r.raise_for_status()
        desired = r.json()
    except (requests.RequestException, ValueError) as exc:
        state.update(last_error=str(exc)[:300], last_attempt=int(time.time()))
        _write('state.json', json.dumps(state, indent=2))
        return state
    state['template_status'] = _apply_template(desired.get('template'), state)
    _apply_version(desired.get('target_version'))
    try:
        _federated(desired, state, session, ident)
    except (requests.RequestException, ValueError, OSError) as exc:
        state.setdefault('federated', {})['note'] = f'federated learning failed: {str(exc)[:200]}'
    state.update(last_report=int(time.time()), last_error=None, group=desired.get('group'),
                 desired_version=desired.get('target_version'))
    _write('state.json', json.dumps(state, indent=2))
    return state


def status():
    ident = identity()
    return {'enrolled': bool(ident), **(ident or {}), 'version': version(), 'state': _read_json('state.json', {}),
            'update': _read_json('update_result.json')}
