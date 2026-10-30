"""Sensor-facing service of the brain (mutual TLS, default port 9443).

    python -m brain.server

Sensors enrol once with a one-time code (GET /v1/ca, POST /v1/enroll need no
client certificate). Every other endpoint requires the client certificate
the brain issued: its common name is the sensor id, and its fingerprint
must match the one recorded at enrolment, so a revoked sensor is refused
even though its certificate still chains to the CA.
"""
import logging
import os
import secrets
import ssl
import sys

from fastapi import Depends, FastAPI, HTTPException, Request
from pydantic import BaseModel
from uvicorn.protocols.http.httptools_impl import HttpToolsProtocol

import core.audit as audit
from brain import keys
from brain.manage import store
from common import pki, protocol

logger = logging.getLogger('sentinel.brain')
app = FastAPI(title='SentinelEdgeAI brain', openapi_url=None, docs_url=None, redoc_url=None)
PEER_CERT_KEY = 'sentinel.peer_cert'


class PeerCertProtocol(HttpToolsProtocol):
    """uvicorn protocol that puts the verified client certificate (DER) in the ASGI scope."""

    def connection_made(self, transport):
        super().connection_made(transport)
        ssl_object = transport.get_extra_info('ssl_object')
        self._peer_der = ssl_object.getpeercert(binary_form=True) if ssl_object else None

    def on_message_begin(self):
        super().on_message_begin()
        self.scope[PEER_CERT_KEY] = self._peer_der


def sensor_identity(request: Request):
    der = request.scope.get(PEER_CERT_KEY)
    if not der:
        raise HTTPException(status_code=401, detail='client certificate required')
    sensor_id = pki.common_name(der)
    sensor = store().get_sensor(sensor_id) if sensor_id else None
    if not sensor or sensor['revoked'] or sensor['cert_fp'] != pki.fingerprint(der):
        raise HTTPException(status_code=403, detail='sensor not enrolled or revoked')
    return sensor


class Enrolment(BaseModel):
    code: str
    csr: str
    name: str = 'sensor'


class FlowBatch(BaseModel):
    records: list  # [[rid, record], ...]


class CommandResult(BaseModel):
    seq: int
    status: str
    detail: object = None


@app.get('/v1/ca')
def ca_certificate():
    return {'ca': keys.read('ca.pem'), 'fingerprint': keys.ca_fingerprint()}


@app.post('/v1/enroll')
def enroll(payload: Enrolment, request: Request):
    sensor_id = 'sensor-' + secrets.token_hex(4)
    if not store().redeem_code(payload.code, sensor_id):
        audit.record('sensor_enroll', actor='unknown', actor_kind='sensor', target=payload.name[:64],
                     client_ip=request.client.host if request.client else None, outcome='rejected')
        raise HTTPException(status_code=403, detail='enrolment code is invalid, used or expired')
    try:
        cert = pki.sign_sensor_csr(keys.read('ca.key'), keys.read('ca.pem'), payload.csr, sensor_id)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    store().add_sensor(sensor_id, payload.name, pki.fingerprint(cert))
    audit.record('sensor_enroll', actor=sensor_id, actor_kind='sensor', target=payload.name[:64],
                 client_ip=request.client.host if request.client else None)
    logger.info('enrolled %s (%s)', sensor_id, payload.name)
    return {'sensor_id': sensor_id, 'certificate': cert, 'signing_public_key': keys.read('signing.pub'),
            'protocol': protocol.PROTOCOL_VERSION}


@app.post('/v1/flows')
def receive_flows(batch: FlowBatch, sensor: dict = Depends(sensor_identity)):
    if len(batch.records) > protocol.MAX_BATCH:
        raise HTTPException(status_code=413, detail=f'at most {protocol.MAX_BATCH} records per batch')
    items = []
    try:
        for rid, record in batch.records:
            items.append((int(rid), protocol.validate_record(record)))
    except (TypeError, ValueError) as exc:
        raise HTTPException(status_code=400, detail=f'bad record: {exc}')
    new = store().add_flows(sensor['id'], items)
    store().touch(sensor['id'])
    return {'stored': new, 'acked': [rid for rid, _ in items]}


@app.post('/v1/health')
def receive_health(health: dict, sensor: dict = Depends(sensor_identity)):
    store().touch(sensor['id'], health)
    return {'status': 'ok'}


@app.get('/v1/commands')
def commands(after: int = 0, sensor: dict = Depends(sensor_identity)):
    store().touch(sensor['id'])
    return {'commands': store().pending_commands(sensor['id'], after)}


@app.post('/v1/commands/result')
def command_result(result: CommandResult, sensor: dict = Depends(sensor_identity)):
    store().command_result(sensor['id'], result.seq, result.status, result.detail)
    return {'status': 'ok'}


def ssl_options():
    return {
        'ssl_keyfile': keys.path('server.key'),
        'ssl_certfile': keys.path('server.pem'),
        'ssl_ca_certs': keys.path('ca.pem'),
        # optional at the TLS layer so enrolment works; enforced per endpoint
        'ssl_cert_reqs': ssl.CERT_OPTIONAL,
    }


def main():
    import uvicorn

    keys.init()
    host = os.environ.get('SENTINEL_BRAIN_HOST', '0.0.0.0')  # nosec B104 - sensors connect from the network
    port = int(os.environ.get('SENTINEL_BRAIN_PORT', '9443'))
    print(f'sentineledgeai brain: listening on https://{host}:{port} (CA {keys.ca_fingerprint()[:16]}…)', flush=True)
    uvicorn.run(app, host=host, port=port, http=PeerCertProtocol, **ssl_options())
    return 0


if __name__ == '__main__':
    sys.exit(main())
