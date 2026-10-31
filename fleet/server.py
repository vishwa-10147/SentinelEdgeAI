"""Fleet server: the site-facing mutual-TLS endpoint (port 9444).

  GET  /v1/ca       the fleet CA (sites pin it by fingerprint before trusting it)
  POST /v1/enroll   one-time code + CSR -> client certificate whose CN is the site id
  POST /v1/report   a site's status report -> its desired state (template, target version)

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
    return {'group': group['name'],
            'template': {'name': template['name'], 'version': template['version'], 'yaml': template['yaml']}
            if template else None,
            'target_version': rollout.desired_version(group, site['id'], report.get('version'), now),
            'server_time': int(now)}


@app.post('/v1/report')
def report(body: dict, site: dict = Depends(site_identity)):
    if not isinstance(body, dict):
        raise HTTPException(status_code=400, detail='report must be an object')
    store().add_report(site['id'], body)
    return desired_state(site, body)


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
