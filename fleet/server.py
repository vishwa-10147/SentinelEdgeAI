"""Fleet server: the site-facing mutual-TLS endpoint (port 9444).

  GET  /v1/ca       the fleet CA (sites pin it by fingerprint before trusting it)
  POST /v1/enroll   one-time code + CSR -> client certificate whose CN is the site id
  POST /v1/report   a site's status report (+ new alert summaries) -> its desired state
                    (template, target version, queued remote actions)
  POST /v1/actions/result   a site's outcome for a remote action

Started by sentineledgeai-fleet.path once `python -m fleet init` marked this
device as a fleet server. Admins manage the fleet from the console
(/api/fleet/*), not here.
"""
import os
import secrets
import ssl
import sys
import time

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel

import core.audit as audit
from brain.server import PEER_CERT_KEY, PeerCertProtocol
from common import pki
from fleet import keys, rollout
from fleet.store import FleetStore

app = FastAPI(title='SentinelEdgeAI fleet', openapi_url=None, docs_url=None, redoc_url=None)
_store = None


def store():
    global _store
    if _store is None:
        _store = FleetStore()
    return _store


def site_identity(request: Request):
    der = request.scope.get(PEER_CERT_KEY)
    if not der:
        raise HTTPException(status_code=401, detail='client certificate required')
    site_id = pki.common_name(der)
    site = store().get_site(site_id) if site_id else None
    if not site or site['revoked'] or site['cert_fp'] != pki.fingerprint(der):
        raise HTTPException(status_code=403, detail='site not enrolled or revoked')
    return site


class Enrolment(BaseModel):
    code: str
    csr: str
    name: str = 'site'


@app.get('/v1/ca')
def ca_certificate():
    return {'ca': keys.read('ca.pem')}


@app.post('/v1/enroll')
def enroll(payload: Enrolment):
    site_id = f'site-{secrets.token_hex(4)}'
    group = store().redeem_code(payload.code, site_id)
    if not group:
        audit.record('fleet_enroll', actor=payload.name[:64], outcome='rejected', details={'reason': 'bad code'})
        raise HTTPException(status_code=403, detail='enrolment code is unknown, used or expired')
    try:
        cert = pki.sign_sensor_csr(keys.read('ca.key'), keys.read('ca.pem'), payload.csr, site_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f'invalid certificate request: {exc}')
    store().add_site(site_id, payload.name, pki.fingerprint(cert), group)
    audit.record('fleet_enroll', actor=payload.name[:64], target=site_id, details={'group': group})
    return {'site_id': site_id, 'group': group, 'certificate': cert}


def desired_state(site, report, now=None):
    """What this site should run, given its group; pauses the group's rollout on a failed update."""
    now = now or time.time()
    st = store()
    group = st.get_group(site['grp']) or {'name': site['grp'], 'template': None, 'target_version': None, 'stages': []}
    if rollout.failed_update(report, group.get('target_version')) and not group.get('paused'):
        reason = f"update to {group['target_version']} failed on {site['name']} ({site['id']})"
        st.pause_group(group['name'], reason)
        audit.record('fleet_rollout_paused', target=group['name'], details={'reason': reason})
        group['paused'] = reason
    template = st.get_template(group['template']) if group.get('template') else None
    return {**federated_state(site, report),
            'group': group['name'],
            'template': {'name': template['name'], 'version': template['version'], 'yaml': template['yaml']}
            if template else None,
            'target_version': rollout.desired_version(group, site['id'], report.get('version'), now),
            'actions': st.pending_actions(site['id'], now),
            'server_time': int(now)}


def federated_state(site, report, model='autoencoder'):
    """An open round this site has not answered (with its starting model), and the newest global model
    if the site does not have it yet."""
    st = store()
    out = {}
    rnd = st.open_round(model)
    if rnd and not st.submitted(rnd['id'], site['id']):
        base = st.latest_global(model)
        out['federated_round'] = {'round': rnd['id'], 'model': model, 'base': base['global'] if base else None}
    latest = st.latest_global(model)
    installed = ((report or {}).get('federated') or {}).get('installed_round')
    if latest and installed != latest['round']:
        out['federated_model'] = latest
    return out


@app.post('/v1/federated/update')
def federated_update(body: dict, site: dict = Depends(site_identity)):
    """A site's model update for the open round (parameters and counts only, never flows)."""
    from detection import federated
    st = store()
    rnd = st.open_round(str(body.get('model', 'autoencoder')))
    update = body.get('update') or {}
    if not rnd or body.get('round') != rnd['id']:
        raise HTTPException(status_code=409, detail='that round is not open')
    if not isinstance(update.get('n_samples'), int) or update['n_samples'] < federated.MIN_SAMPLES:
        raise HTTPException(status_code=400, detail='update needs n_samples >= %d' % federated.MIN_SAMPLES)
    if update.get('hidden') != list(federated.HIDDEN) or not 0 < len(update.get('features') or []) <= 64:
        raise HTTPException(status_code=400, detail='update has an unexpected network shape')
    base = st.latest_global(rnd['model'])
    if base and update['features'] != base['global']['features']:
        raise HTTPException(status_code=400, detail='update was trained on different features than the global model')
    others = st.updates(rnd['id'])
    try:
        if others:
            federated._compatible(others + [update])
        federated.validate_update(update)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f'invalid update: {exc}')
    count = st.add_update(rnd['id'], site['id'], update)
    audit.record('federated_update', actor=site['name'][:64], target=f"round {rnd['id']}",
                 details={'site': site['id'], 'n_samples': update['n_samples']})
    if count >= rnd['min_sites']:
        global_model = federated.aggregate(st.updates(rnd['id']), round_id=rnd['id'], previous=base['global'] if base else None)
        st.finish_round(rnd['id'], global_model)
        audit.record('federated_round_done', target=f"round {rnd['id']}",
                     details={'sites': global_model['sites'], 'n_samples': global_model['n_samples']})
        return {'accepted': True, 'aggregated': True}
    return {'accepted': True, 'aggregated': False, 'waiting_for': rnd['min_sites'] - count}


@app.post('/v1/report')
def report(body: dict, site: dict = Depends(site_identity)):
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail='report must be an object')
    alerts = body.pop('alerts', None)
    accepted = store().add_alerts(site['id'], alerts) if isinstance(alerts, list) else 0
    store().add_report(site['id'], body)
    return {**desired_state(site, body), 'alerts_accepted': accepted}


class ActionResult(BaseModel):
    id: int
    ok: bool
    result: dict = {}


@app.post('/v1/actions/result')
def action_result(payload: ActionResult, site: dict = Depends(site_identity)):
    if not store().finish_action(site['id'], payload.id, payload.ok, payload.result):
        raise HTTPException(status_code=404, detail='no open action with that id for this site')
    audit.record('fleet_action_done', actor=site['name'][:64], target=f"{site['id']} action {payload.id}",
                 outcome='success' if payload.ok else 'failure',
                 details={k: str(v)[:200] for k, v in (payload.result or {}).items()})
    return {'recorded': payload.id}


def ssl_options():
    return {'ssl_keyfile': keys.path('server.key'), 'ssl_certfile': keys.path('server.pem'),
            'ssl_ca_certs': keys.path('ca.pem'),
            # optional at the TLS layer so enrolment works; enforced per endpoint
            'ssl_cert_reqs': ssl.CERT_OPTIONAL}


def main():
    import uvicorn
    if not keys.enabled() and os.environ.get('SENTINEL_FLEET_FORCE') != '1':
        print('this device is not a fleet server (run: python -m fleet init)', file=sys.stderr)
        return 78  # EX_CONFIG: RestartPreventExitStatus=78 stops systemd retrying
    keys.init()
    host = os.environ.get('SENTINEL_FLEET_HOST', '0.0.0.0')  # nosec B104 - sites connect from the network
    port = int(os.environ.get('SENTINEL_FLEET_PORT', '9444'))
    print(f'sentineledgeai fleet: listening on https://{host}:{port} (CA {keys.ca_fingerprint()[:16]}…)', flush=True)
    uvicorn.run(app, host=host, port=port, http=PeerCertProtocol, **ssl_options())
    return 0


if __name__ == '__main__':
    sys.exit(main())
