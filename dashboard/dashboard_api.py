from fastapi import FastAPI, HTTPException, Depends, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi import WebSocket, WebSocketDisconnect
import os, json, time, asyncio
from utils.subprocess_safe import safe_popen, PIPE, DEVNULL
import logging
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from utils import metrics as metrics_utils
import sys
from typing import Optional
import threading
import hashlib
import re
import ipaddress
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
import core.audit as audit_core
import core.setup as setup_core
import core.auth as auth_core
from core.product_intelligence import (
    build_incident_timeline,
    build_security_report,
    explain_alert,
)

from dashboard.auth_routes import (
    router as auth_router,
    require_viewer,
    require_analyst,
    require_operator,
    require_admin,
    resolve_principal,
    audit_event,
    pending_setup,
)

from contextlib import asynccontextmanager
from core.db_maintenance import start_background


@asynccontextmanager
async def lifespan(app: FastAPI):
    # one event bus feeds every WebSocket (core.events)
    from core.events import EventBus
    app.state.bus = EventBus(sanitize=maybe_sanitize)
    app.state.loop = asyncio.get_running_loop()
    app.state.bus.start()
    # start optional DB maintenance background thread (vacuum + retention)
    try:
        app.state.db_maintenance = start_background()
    except Exception:
        app.state.db_maintenance = None
    # if CAPTURE_IN_PROCESS=1, attempt to import and run sniffer in a background thread
    if os.environ.get('CAPTURE_IN_PROCESS', '0') == '1':
        try:
            import capture.sniffer as sniffer
            loop = asyncio.get_event_loop()

            def pub(evt):
                try:
                    loop.call_soon_threadsafe(app.state.bus.publish, evt.get('type', 'event'), evt)
                except Exception:
                    logger.exception('event publish failed')

            sniffer.set_event_publisher(pub)
            t = threading.Thread(target=sniffer.start_sniffing, kwargs={'interface': os.environ.get('CAPTURE_IFACE')}, daemon=True)
            t.start()
            app.state.sniffer_thread = t
            app.state.sniffer_module = sniffer
            print('started sniffer in-process')
        except Exception as e:
            logger.exception('failed to start sniffer in-process')
    try:
        yield
    finally:
        await app.state.bus.stop()
        # attempt graceful shutdown of sniffer if supported
        try:
            sniffer = getattr(app.state, 'sniffer_module', None)
            if sniffer and hasattr(sniffer, 'stop_sniffing'):
                try:
                    sniffer.stop_sniffing()
                except Exception:
                    logger.exception('failed to stop sniffer')
        except Exception:
            logger.exception('error during sniffer shutdown')
        # stop DB maintenance thread if running
        try:
            m = getattr(app.state, 'db_maintenance', None)
            if m and hasattr(m, 'stop'):
                try:
                    m.stop()
                except Exception:
                    logger.exception('failed to stop db maintenance')
        except Exception:
            logger.exception('error during db maintenance shutdown')


# ---------- logging & metrics setup ----------
logging.basicConfig(level=os.environ.get('SENTINEL_LOG_LEVEL','INFO'))
logger = logging.getLogger('sentinel')

# initialize centralized metrics
metrics_utils.init_metrics()



app = FastAPI(title="SentinelEdgeAI Dashboard API", lifespan=lifespan, openapi_url=None, docs_url=None, redoc_url=None)

# Compatibility: allow disabling legacy file fallbacks via env
ENABLE_FILE_FALLBACK = os.environ.get('ENABLE_FILE_FALLBACK', '1') == '1'


# simple request metrics middleware
@app.middleware("http")
async def prometheus_middleware(request: Request, call_next):
    path = request.url.path
    method = request.method
    try:
        resp = await call_next(request)
        status = str(resp.status_code)
    except Exception:
        status = '500'
        raise
    finally:
        try:
            if metrics_utils.REQUEST_COUNT is not None:
                metrics_utils.REQUEST_COUNT.labels(method=method, path=path, status=status).inc()
        except Exception:
            logger.exception('metrics update failed')
    return resp

# General API rate limits per client address, on top of the stricter login
# throttle. One open console polls about 80 requests a minute. 0 disables.
RATE_LIMIT_READ = int(os.environ.get('SENTINEL_RATE_LIMIT_READ', '600'))
RATE_LIMIT_WRITE = int(os.environ.get('SENTINEL_RATE_LIMIT_WRITE', '60'))
RATE_LIMIT_WINDOW = 60
WRITE_METHODS = ('POST', 'PUT', 'PATCH', 'DELETE')
read_limiter = auth_core.SlidingWindowLimiter(RATE_LIMIT_READ, RATE_LIMIT_WINDOW)
write_limiter = auth_core.SlidingWindowLimiter(RATE_LIMIT_WRITE, RATE_LIMIT_WINDOW)


@app.middleware("http")
async def rate_limit_middleware(request: Request, call_next):
    path = request.url.path
    if not path.startswith('/api/') or request.method == 'OPTIONS':
        return await call_next(request)
    if request.method in WRITE_METHODS:
        limiter, limit = write_limiter, RATE_LIMIT_WRITE
    else:
        limiter, limit = read_limiter, RATE_LIMIT_READ
    client = request.client.host if request.client else 'unknown'
    if limit > 0 and not limiter.allow(client):
        logger.warning('rate limit exceeded for %s on %s %s', client, request.method, path)
        return JSONResponse(
            {'detail': 'rate limit exceeded; try again later'},
            status_code=429,
            headers={'Retry-After': str(limiter.retry_after(client))},
        )
    return await call_next(request)

# Browser hardening headers on every response. The built console loads only
# same-origin scripts and styles; the TOTP QR code is a data: image. 'self' in
# connect-src covers the same-origin WebSocket. Override the CSP with
# SENTINEL_CSP if the console is hosted elsewhere. Registered after the rate
# limiter so it wraps it and 429 responses carry the headers too.
DEFAULT_CSP = (
    "default-src 'self'; "
    "script-src 'self'; "
    "style-src 'self'; "
    "img-src 'self' data:; "
    "font-src 'self'; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'none'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)
SECURITY_HEADERS = {
    'Content-Security-Policy': os.environ.get('SENTINEL_CSP', DEFAULT_CSP),
    'X-Frame-Options': 'DENY',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), payment=(), usb=()',
    'Cross-Origin-Opener-Policy': 'same-origin',
    'Cross-Origin-Embedder-Policy': 'require-corp',
    'Cross-Origin-Resource-Policy': 'same-origin',
}
# fingerprinted build output (assets/index-<hash>.js) never changes; everything
# else, API responses above all, must not be stored by browsers or proxies
ASSET_CACHE = 'public, max-age=31536000, immutable'
NO_CACHE = 'no-cache, no-store, must-revalidate'
HSTS = f"max-age={int(os.environ.get('SENTINEL_HSTS_MAX_AGE', '31536000'))}"


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    resp = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        resp.headers.setdefault(name, value)
    if request.url.path.startswith('/assets/') and resp.status_code == 200:
        resp.headers['Cache-Control'] = ASSET_CACHE
    else:
        resp.headers.setdefault('Cache-Control', NO_CACHE)
    if request.url.scheme == 'https':
        # browsers ignore HSTS from a certificate they do not trust, so the
        # self-signed install certificate cannot lock anyone out
        resp.headers.setdefault('Strict-Transport-Security', HSTS)
    return resp

# The console is normally served by this API (same origin). Cross-origin
# access is only for the Vite dev server or a separately hosted console.
CORS_ORIGINS = [
    o.strip() for o in os.environ.get(
        'SENTINEL_CORS_ORIGINS', 'http://localhost:5173,http://127.0.0.1:5173'
    ).split(',') if o.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key", "X-Sentinel-CSRF"],
)
app.include_router(auth_router)

# Serve built frontend if present (build into frontend/dist)
ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
import sys
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# frontend static will be mounted after API route definitions so /api/* is not shadowed
DIST_DIR = os.path.join(ROOT, 'frontend', 'dist')

def read_json_file(name):
    path = os.path.join(ROOT, name)
    if not os.path.exists(path):
        raise HTTPException(status_code=404, detail=f"{name} not found")
    with open(path, "r") as f:
        try:
            return json.load(f)
        except Exception:
            raise HTTPException(status_code=500, detail=f"failed to parse {name}")


def read_json_file_optional(name, default):
    path = os.path.join(ROOT, name)
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def read_jsonl_optional(name, limit=500):
    path = os.path.join(ROOT, name)
    if not os.path.exists(path):
        return []
    rows = []
    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return rows[-limit:]


@app.get('/metrics')
def metrics(principal: dict = Depends(require_viewer)):
    # expose prometheus metrics from centralized registry
    try:
        reg = metrics_utils.REGISTRY
        if reg is None:
            metrics_utils.init_metrics()
            reg = metrics_utils.REGISTRY
        data = generate_latest(reg)
        return Response(content=data, media_type=CONTENT_TYPE_LATEST)
    except Exception:
        return Response(content=b"", media_type="text/plain")


@app.get('/openapi.json')
def openapi_spec(principal: dict = Depends(require_viewer)):
    try:
        return app.openapi()
    except Exception:
        raise HTTPException(status_code=500, detail='failed to generate openapi.json')


# Redaction / sanitization settings
REDACT_SENSITIVE = os.environ.get('REDACT_SENSITIVE', '0') == '1'
REDACT_SALT = os.environ.get('REDACT_SALT', '')
_ip_mac_re = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$|^\d+\.\d+\.\d+\.\d+$")

def _hash_id(value: str) -> str:
    h = hashlib.sha256((str(value) + REDACT_SALT).encode('utf-8')).hexdigest()
    return h[:12]

def sanitize_item(obj):
    # sanitize keys that look like ips or macs or known names
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if v is None:
                out[k] = v
                continue
            lk = k.lower()
            if lk in ('src','dst','src_ip','dst_ip','initiator_ip','responder_ip','ip') and isinstance(v, str):
                if _ip_mac_re.match(v):
                    out[k] = _hash_id(v)
                else:
                    out[k] = v
            elif lk in ('src_mac','dst_mac','mac') and isinstance(v, str):
                out[k] = _hash_id(v)
            else:
                out[k] = sanitize_item(v)
        return out
    elif isinstance(obj, list):
        return [sanitize_item(x) for x in obj]
    else:
        return obj

def maybe_sanitize(obj):
    if REDACT_SENSITIVE:
        try:
            return sanitize_item(obj)
        except Exception:
            return obj
    return obj

def _validate_ipv4(value):
    if not value:
        return None
    try:
        parsed = ipaddress.ip_address(str(value))
    except ValueError:
        raise HTTPException(status_code=400, detail='invalid ip')
    if parsed.version != 4:
        raise HTTPException(status_code=400, detail='only IPv4 addresses are currently supported')
    return str(parsed)


# Firewall endpoints (protected by API key when set)
try:
    import core.firewall as firewall
except Exception:
    firewall = None


@app.get('/api/firewall/rules')
def firewall_rules(principal: dict = Depends(require_viewer)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    return maybe_sanitize(firewall.list_rules())


@app.post('/api/firewall/block')
def firewall_block(payload: dict, principal: dict = Depends(require_operator)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    ip = payload.get('ip')
    ttl = payload.get('ttl')
    reason = payload.get('reason','')
    if not ip:
        raise HTTPException(status_code=400, detail='missing ip')
    try:
        res = firewall.add_block(ip, ttl=ttl, reason=reason)
    except ValueError as exc:
        audit_event(principal, 'firewall_block', target=ip, outcome='rejected', details={'error': str(exc)})
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'firewall_block', target=res.get('ip'),
                details={'ttl': ttl, 'reason': reason, 'dry_run': res.get('dry_run')})
    return maybe_sanitize(res)


@app.post('/api/firewall/unblock')
def firewall_unblock(payload: dict, principal: dict = Depends(require_operator)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    ip = payload.get('ip')
    if not ip:
        raise HTTPException(status_code=400, detail='missing ip')
    try:
        res = firewall.remove_block(ip)
    except ValueError as exc:
        audit_event(principal, 'firewall_unblock', target=ip, outcome='rejected', details={'error': str(exc)})
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'firewall_unblock', target=ip, details={'removed': res.get('removed')})
    return maybe_sanitize(res)


@app.get('/api/firewall/actions')
def firewall_actions(principal: dict = Depends(require_viewer)):
    # return recent firewall action log lines
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    try:
        path = os.path.join(ROOT, 'logs', 'firewall_actions.jsonl')
        if not os.path.exists(path):
            return []
        out = []
        now = time.time()
        with open(path, 'r') as f:
            for line in f:
                try:
                    item = json.loads(line)
                except Exception:
                    logger.exception('failed to parse firewall action line')
                    continue
                # enrich with status when ttl present
                if item.get('action') == 'block' and 'timestamp' in item:
                    ts = None
                    try:
                        ts = float(item.get('timestamp'))
                    except Exception:
                        try:
                            # try parsing ISO
                            ts = time.mktime(time.strptime(item.get('timestamp')[0:19], "%Y-%m-%d %H:%M:%S"))
                        except Exception:
                            logger.exception('failed to parse timestamp in firewall action')
                            ts = None
                    ttl = item.get('ttl')
                    if ts and ttl:
                        expiry = ts + float(ttl)
                        item['status'] = 'active' if now < expiry else 'expired'
                        item['remaining_ttl'] = max(0, int(expiry - now))
                    else:
                        item['status'] = 'active' if item.get('active', True) else 'unknown'
                out.append(item)
        return maybe_sanitize(out[-200:])
    except Exception:
        raise HTTPException(status_code=500, detail='failed to read firewall actions')


@app.get('/api/firewall/policy')
def firewall_policy(principal: dict = Depends(require_viewer)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    try:
        return maybe_sanitize(firewall.get_policy())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post('/api/firewall/policy')
def firewall_policy_update(payload: dict, principal: dict = Depends(require_admin)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    try:
        policy = firewall.update_policy(payload or {})
    except ValueError as exc:
        audit_event(principal, 'firewall_policy', outcome='rejected', details={'error': str(exc)})
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'firewall_policy', details={'changed': sorted((payload or {}).keys()),
                                                        'response_mode': policy.get('response_mode')})
    return maybe_sanitize(policy)


@app.post('/api/firewall/whitelist')
def firewall_whitelist(payload: dict, principal: dict = Depends(require_operator)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    ip = payload.get('ip')
    action = payload.get('action', 'add')
    if not ip:
        raise HTTPException(status_code=400, detail='missing ip')
    if action not in ('add', 'remove'):
        raise HTTPException(status_code=400, detail='invalid whitelist action')
    try:
        res = firewall.add_whitelist(ip) if action == 'add' else firewall.remove_whitelist(ip)
    except ValueError as exc:
        audit_event(principal, f'whitelist_{action}', target=ip, outcome='rejected', details={'error': str(exc)})
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, f'whitelist_{action}', target=ip)
    return maybe_sanitize(res)


@app.post('/api/firewall/expire')
def firewall_expire(principal: dict = Depends(require_operator)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    res = firewall.expire_rules()
    audit_event(principal, 'firewall_expire', details={'result': res})
    return maybe_sanitize(res)


@app.post('/api/firewall/rollback')
def firewall_rollback(payload: dict = {}, principal: dict = Depends(require_operator)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    reason = (payload or {}).get('reason', 'operator_rollback')
    res = firewall.rollback_blocks(reason=reason)
    audit_event(principal, 'firewall_rollback', details={'reason': reason, 'removed': res.get('removed')})
    return maybe_sanitize(res)



@app.get('/api/audit')
def audit_entries(limit: int = 100, before: Optional[int] = None, action: Optional[str] = None,
                  actor: Optional[str] = None, principal: dict = Depends(require_admin)):
    return audit_core.get_log().entries(limit=limit, before=before, action=action, actor=actor)


@app.get('/api/setup')
def setup_get(principal: dict = Depends(require_admin)):
    return {
        **setup_core.load(),
        'interfaces': setup_core.list_interfaces(),
        'options': setup_core.options(),
        'enforcement': 'dry_run' if getattr(firewall, 'FIREWALL_DRY_RUN', True) else 'enforcing',
    }


@app.post('/api/setup')
def setup_save(payload: dict, principal: dict = Depends(require_admin)):
    first_time = not setup_core.is_complete()
    try:
        values = setup_core.validate(payload or {})
        if firewall is not None:
            firewall.update_policy({'response_mode': values['response_mode']})
        settings = setup_core.save(values, by=principal.get('username'))
    except ValueError as exc:
        audit_event(principal, 'setup', outcome='rejected', details={'error': str(exc)})
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'setup', details={**values, 'first_run': first_time})
    return settings


# ---------- Phase 5: integrations and operations ----------

@app.get('/api/integrations')
def integrations_get(principal: dict = Depends(require_admin)):
    from integrations import dispatcher
    return {'config': dispatcher.redacted(dispatcher.load_config()), 'status': dispatcher.read_status()}


@app.put('/api/integrations')
def integrations_put(payload: dict, principal: dict = Depends(require_admin)):
    from integrations import dispatcher
    cfg = {'sinks': (payload or {}).get('sinks', [])}
    current = dispatcher.load_config()
    # a redacted secret sent back unchanged keeps the stored value
    by_name = {s.get('name'): s for s in current.get('sinks', [])}
    for s in cfg['sinks']:
        for k in dispatcher.SECRET_KEYS:
            if s.get(k) == '********' and s.get('name') in by_name:
                s[k] = by_name[s['name']].get(k)
    try:
        dispatcher.save_config(cfg)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'integrations_update', details={'sinks': [s.get('type') for s in cfg['sinks']]})
    return dispatcher.redacted(cfg)


@app.post('/api/integrations/test')
def integrations_test(payload: dict, principal: dict = Depends(require_admin)):
    from integrations import dispatcher
    try:
        ok, message, latency = dispatcher.get_dispatcher().test((payload or {}).get('sink') or {})
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'integrations_test', outcome='success' if ok else 'failure',
                details={'type': ((payload or {}).get('sink') or {}).get('type'), 'message': message})
    return {'ok': ok, 'message': message, 'latency_ms': latency}


@app.get('/api/intel')
def intel_status(principal: dict = Depends(require_viewer)):
    from intel.store import get_store
    store = get_store()
    return {'indicators': store.counts(), 'feeds': store.feeds()}


@app.post('/api/intel/import')
def intel_import(payload: dict, principal: dict = Depends(require_admin)):
    from intel import store as intel_store
    payload = payload or {}
    source, text = payload.get('source'), payload.get('text') or ''
    if not source:
        raise HTTPException(status_code=400, detail='missing source name')
    fmt = payload.get('format') or ('stix' if text.lstrip().startswith('{') else 'plain')
    try:
        parsed = intel_store.parse_plain(text) if fmt == 'plain' else intel_store.parse_stix(text)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=f'could not parse: {exc}')
    n = intel_store.get_store().replace_source(str(source)[:64], parsed)
    audit_event(principal, 'intel_import', target=source, details={'indicators': n, 'format': fmt})
    return {'source': source, 'indicators': n}


@app.post('/api/intel/feeds')
def intel_add_feed(payload: dict, principal: dict = Depends(require_admin)):
    from intel.store import get_store
    payload = payload or {}
    try:
        get_store().add_feed(str(payload.get('name') or '')[:64], payload.get('url') or '', payload.get('format', 'plain'))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'intel_feed_add', target=payload.get('name'), details={'url': payload.get('url')})
    return get_store().feeds()


@app.post('/api/intel/update')
def intel_update(principal: dict = Depends(require_admin)):
    from intel.store import get_store
    result = get_store().update_feeds()
    audit_event(principal, 'intel_update', details=result)
    return result


@app.get('/api/reports/summary')
def report_summary(period: str = 'daily', format: str = 'json', principal: dict = Depends(require_viewer)):
    from reporting import summary
    if period not in summary.PERIODS:
        raise HTTPException(status_code=400, detail='period must be daily or weekly')
    report = summary.build(period)
    if format == 'pdf':
        return Response(summary.to_pdf(report), media_type='application/pdf',
                        headers={'Content-Disposition': f'attachment; filename="sentineledgeai-{period}.pdf"'})
    return report


@app.get('/api/devices/{ip}/history')
def device_history(ip: str, principal: dict = Depends(require_viewer)):
    from reporting import summary
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise HTTPException(status_code=400, detail='invalid ip')
    return Response(summary.device_history_csv(ip), media_type='text/csv',
                    headers={'Content-Disposition': f'attachment; filename="device-{ip}.csv"'})


@app.get('/api/export/compliance')
def compliance(start: Optional[float] = None, end: Optional[float] = None, principal: dict = Depends(require_admin)):
    from reporting import summary
    end = end or time.time()
    start = start or end - 30 * 86400
    audit_event(principal, 'compliance_export', details={'from': start, 'to': end})
    return summary.compliance_export(start, end)


# ---------- Phase 4: detection quality ----------

@app.post('/api/alerts/feedback')
def alert_feedback(payload: dict, principal: dict = Depends(require_analyst)):
    from detection.feedback import get_store
    payload = payload or {}
    alert = payload.get('alert') or {}
    try:
        fid = get_store().add(payload.get('kind') or alert.get('attack_type'), payload.get('label'),
                              src=alert.get('initiator_ip'), alert=alert, by=principal.get('username'),
                              note=payload.get('note', ''))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'alert_feedback', target=alert.get('initiator_ip'),
                details={'label': payload.get('label'), 'kind': payload.get('kind') or alert.get('attack_type')})
    return {'id': fid}


@app.get('/api/alerts/feedback')
def alert_feedback_summary(principal: dict = Depends(require_viewer)):
    from detection.feedback import get_store
    return get_store().summary()


@app.get('/api/models')
def models_list(principal: dict = Depends(require_viewer)):
    from detection import registry
    return registry.index()


@app.post('/api/models/{name}/{version}/stage')
def models_stage(name: str, version: int, payload: dict, principal: dict = Depends(require_admin)):
    from detection import registry
    try:
        entry = registry.set_stage(name, version, (payload or {}).get('stage'), (payload or {}).get('percent'))
    except KeyError:
        raise HTTPException(status_code=404, detail='model version not found')
    except (ValueError, registry.RegistryError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'model_stage', target=f'{name} v{version}', details={'stage': (payload or {}).get('stage')})
    return entry


@app.post('/api/models/{name}/rollback')
def models_rollback(name: str, principal: dict = Depends(require_admin)):
    from detection import registry
    try:
        entry = registry.rollback(name)
    except (ValueError, registry.RegistryError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'model_rollback', target=name, details={'active': entry['active']})
    return entry


@app.get('/api/eval/latest')
def eval_latest(principal: dict = Depends(require_viewer)):
    import glob
    reports = sorted(glob.glob(os.path.join(ROOT, 'reports', 'eval', '*.json')), key=os.path.getmtime)
    if not reports:
        raise HTTPException(status_code=404, detail='no evaluation report yet; run python -m evaluation.harness')
    with open(reports[-1]) as f:
        return json.load(f)


# ---------- Phase 3: enforcement ----------

@app.get('/api/enforcement/protected')
def enforcement_protected(principal: dict = Depends(require_viewer)):
    from enforcement import protected
    return protected.summary()


@app.get('/api/devices/identity')
def devices_identity(principal: dict = Depends(require_viewer)):
    from enforcement import identity
    return identity.get_registry().list()


def _fleet(principal, action, fn, *args, **kwargs):
    try:
        return fn(*args, by=principal.get('username'), **kwargs)
    except ValueError as exc:
        audit_event(principal, action, outcome='rejected', details={'error': str(exc)[:300]})
        raise HTTPException(status_code=400, detail=str(exc))


@app.get('/api/fleet')
def fleet_overview(principal: dict = Depends(require_viewer)):
    """Fleet server view: sites with their latest reports, groups with rollout progress, templates."""
    from fleet import manage
    return manage.overview()


@app.get('/api/fleet/sites/{site_id}/history')
def fleet_site_history(site_id: str, principal: dict = Depends(require_viewer)):
    from fleet.store import FleetStore
    return {'site_id': site_id, 'reports': FleetStore().history(site_id, limit=288)}


@app.post('/api/fleet/codes')
def fleet_code(payload: dict = {}, principal: dict = Depends(require_admin)):
    """A one-time enrolment code for a new site (valid for an hour)."""
    from fleet import manage
    return _fleet(principal, 'fleet_code', manage.enrolment_code, (payload or {}).get('group') or 'default')


@app.post('/api/fleet/sites/{site_id}/revoke')
def fleet_revoke(site_id: str, principal: dict = Depends(require_admin)):
    from fleet.store import FleetStore
    if not FleetStore().revoke_site(site_id):
        raise HTTPException(status_code=404, detail='no such site')
    audit_event(principal, 'fleet_revoke', target=site_id)
    return {'revoked': site_id}


@app.post('/api/fleet/sites/{site_id}/group')
def fleet_site_group(site_id: str, payload: dict, principal: dict = Depends(require_admin)):
    from fleet.store import FleetStore
    try:
        ok = FleetStore().set_site_group(site_id, str((payload or {}).get('group', '')))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    if not ok:
        raise HTTPException(status_code=404, detail='no such site')
    audit_event(principal, 'fleet_site_group', target=site_id, details={'group': payload.get('group')})
    return {'site_id': site_id, 'group': payload.get('group')}


@app.post('/api/fleet/templates')
def fleet_template(payload: dict, principal: dict = Depends(require_admin)):
    """Store a configuration template: response policy YAML, or one of the presets."""
    from fleet import manage
    p = payload or {}
    return {'version': _fleet(principal, 'fleet_template_put', manage.put_template, str(p.get('name', '')),
                              p.get('yaml'), p.get('preset'))}


@app.post('/api/fleet/groups')
def fleet_group(payload: dict, principal: dict = Depends(require_admin)):
    """Create or update a group: its template, target version and rollout stages."""
    from fleet import manage
    p = payload or {}
    return _fleet(principal, 'fleet_group_put', manage.put_group, str(p.get('name', '')), p.get('template'),
                  p.get('target_version'), p.get('stages'))


@app.post('/api/fleet/groups/{name}/rollout')
def fleet_rollout(name: str, payload: dict, principal: dict = Depends(require_admin)):
    """Pause or resume a group's rollout."""
    from fleet import manage
    return _fleet(principal, 'fleet_rollout', manage.set_rollout, name, str((payload or {}).get('action', '')))


@app.get('/api/fleet/agent')
def fleet_agent_status(principal: dict = Depends(require_viewer)):
    """This site's own fleet status: enrolment, last report, applied template, pending version."""
    from fleet import agent
    return agent.status()


@app.get('/api/trust')
def trust_scores(principal: dict = Depends(require_viewer)):
    """Trust score (0-100), level, reasons and recommended response for every known device, least trusted first."""
    from enforcement import trust
    return {'devices': trust.scores()}


@app.get('/api/devices/{ip}/peers')
def device_peers(ip: str, principal: dict = Depends(require_viewer)):
    """The learned peer profile containment would restrict this device to."""
    from detection.peers import PeerStore, learned
    store = PeerStore()
    try:
        profile = store.profile(ip)
    finally:
        store.close()
    if not profile:
        raise HTTPException(status_code=404, detail='no peer profile for this device')
    return {'ip': ip, 'learned': learned(profile), 'first_seen': profile['first_seen'],
            'internal': [{'ip': d, 'proto': p, 'port': n} for d, p, n in profile['internal']],
            'internet': [{'proto': p, 'port': n} for p, n in profile['external']]}


@app.get('/api/ot/assets')
def ot_assets(principal: dict = Depends(require_viewer)):
    """Industrial controllers seen on the network, the hosts that command them and the functions they use."""
    from detection.ot import OTStore
    store = OTStore()
    try:
        return {'assets': store.assets()}
    finally:
        store.close()


@app.get('/api/ot/segmentation')
def ot_segmentation(principal: dict = Depends(require_viewer)):
    from enforcement import segmentation
    return segmentation.status()


def _segmentation_call(principal, action, fn, *args):
    try:
        return fn(*args, by=principal.get('username'))
    except (ValueError, RuntimeError) as exc:
        audit_event(principal, action, outcome='rejected', details={'error': str(exc)[:300]})
        raise HTTPException(status_code=400, detail=str(exc))


@app.post('/api/ot/segmentation')
def ot_segmentation_mode(payload: dict, principal: dict = Depends(require_admin)):
    """Set OT segmentation to off, monitor or enforce (enforce needs inline placement)."""
    from enforcement import segmentation
    return _segmentation_call(principal, 'ot_segmentation', segmentation.set_mode, (payload or {}).get('mode'))


@app.post('/api/ot/segmentation/allow')
def ot_segmentation_allow(payload: dict, principal: dict = Depends(require_admin)):
    """Let `src` command controller `dst` over `protocol` (an exception to the learned allow-list)."""
    from enforcement import segmentation
    p = payload or {}
    return _segmentation_call(principal, 'ot_segmentation_allow', segmentation.allow,
                              str(p.get('src', '')), str(p.get('dst', '')), str(p.get('protocol', '')))


@app.post('/api/ot/segmentation/refresh')
def ot_segmentation_refresh(payload: dict = {}, principal: dict = Depends(require_admin)):
    """While enforcing, take a new snapshot of the learned allow-lists."""
    from enforcement import segmentation
    return _segmentation_call(principal, 'ot_segmentation_refresh', segmentation.refresh)


@app.get('/api/firewall/restrictions')
def firewall_restrictions(principal: dict = Depends(require_viewer)):
    return firewall.list_restrictions()


def _restrict(kind, payload, principal):
    ip = (payload or {}).get('ip')
    if not ip:
        raise HTTPException(status_code=400, detail='missing ip')
    try:
        res = firewall.add_restriction(kind, ip, ttl=(payload or {}).get('ttl'),
                                       reason=(payload or {}).get('reason', ''))
    except ValueError as exc:
        audit_event(principal, f'firewall_{kind}', target=ip, outcome='rejected', details={'error': str(exc)})
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, f'firewall_{kind}', target=res['ip'], details={'ttl': (payload or {}).get('ttl')})
    return res


@app.post('/api/firewall/quarantine')
def firewall_quarantine(payload: dict, principal: dict = Depends(require_operator)):
    return _restrict('quarantine', payload, principal)


@app.post('/api/firewall/ratelimit')
def firewall_ratelimit(payload: dict, principal: dict = Depends(require_operator)):
    return _restrict('ratelimit', payload, principal)


@app.post('/api/firewall/contain')
def firewall_contain(payload: dict, principal: dict = Depends(require_operator)):
    """Restrict an IPv4 device to the peers and ports of its learned profile (DNS and DHCP stay open)."""
    return _restrict('contain', payload, principal)


@app.post('/api/firewall/release')
def firewall_release(payload: dict, principal: dict = Depends(require_operator)):
    payload = payload or {}
    try:
        res = firewall.remove_restriction(payload.get('kind'), payload.get('ip', ''))
    except (ValueError, KeyError) as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, f"firewall_{payload.get('kind')}_release", target=payload.get('ip'))
    return res


@app.get('/api/playbook/pending')
def playbook_pending(status: str = 'pending', principal: dict = Depends(require_viewer)):
    from enforcement.playbook import get_playbook
    return get_playbook().pending(status)


def _decide(pending_id, approve, principal):
    from enforcement.playbook import get_playbook
    try:
        res = get_playbook().decide(pending_id, approve, principal.get('username'))
    except KeyError:
        raise HTTPException(status_code=404, detail='pending action not found')
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    audit_event(principal, 'playbook_approve' if approve else 'playbook_deny', target=res['ip'],
                details={'id': pending_id, 'action': res['action'], 'status': res['status']})
    return res


@app.post('/api/playbook/pending/{pending_id}/approve')
def playbook_approve(pending_id: int, principal: dict = Depends(require_operator)):
    return _decide(pending_id, True, principal)


@app.post('/api/playbook/pending/{pending_id}/deny')
def playbook_deny(pending_id: int, principal: dict = Depends(require_operator)):
    return _decide(pending_id, False, principal)


@app.get('/api/policy')
def policy_get(principal: dict = Depends(require_viewer)):
    from enforcement import policy
    return {'policy': policy.current(), 'yaml': policy.export()}


@app.post('/api/policy/diff')
def policy_diff(payload: dict, principal: dict = Depends(require_admin)):
    from enforcement import policy
    try:
        new, errors, warnings = policy.validate(policy.parse((payload or {}).get('yaml', '')))
    except ValueError as exc:
        return {'valid': False, 'errors': [str(exc)], 'warnings': [], 'changes': []}
    return {'valid': not errors, 'errors': errors, 'warnings': warnings,
            'changes': [{'key': k, 'old': o, 'new': n} for k, o, n in policy.diff(new)]}


@app.post('/api/policy/apply')
def policy_apply(payload: dict, principal: dict = Depends(require_admin)):
    from enforcement import policy
    try:
        result = policy.apply(policy.parse((payload or {}).get('yaml', '')), by=principal.get('username'))
    except ValueError as exc:
        audit_event(principal, 'policy_apply', outcome='rejected', details={'error': str(exc)[:500]})
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'policy_apply', details={'changed': [c[0] for c in result['changes']]})
    return {'changes': [{'key': k, 'old': o, 'new': n} for k, o, n in result['changes']],
            'warnings': result['warnings']}


QUARANTINE_PAGE = """<!doctype html><html><head><meta charset="utf-8"><title>Device quarantined</title>
<meta name="viewport" content="width=device-width, initial-scale=1"><link rel="stylesheet" href="/quarantined.css">
</head><body><main><h1>This device has been quarantined</h1>
<p>SentinelEdgeAI detected suspicious activity from this device and limited its network access to
protect the rest of the network. Only name resolution and address assignment still work.</p>
<p>Please contact your IT or network administrator. Mention the time you saw this page.</p></main></body></html>"""
QUARANTINE_CSS = ('body{font-family:system-ui,sans-serif;background:#0b1020;color:#e2e8f0;display:grid;'
                  'place-items:center;min-height:100vh;margin:0}main{max-width:560px;padding:32px}'
                  'h1{color:#f59e0b}')


@app.get('/quarantined', include_in_schema=False)
def quarantined_page():
    return Response(QUARANTINE_PAGE, media_type='text/html')


@app.get('/quarantined.css', include_in_schema=False)
def quarantined_css():
    return Response(QUARANTINE_CSS, media_type='text/css')


# ---------- two-node mode: brain side ----------

def _brain():
    from brain import keys as brain_keys, manage as brain_manage
    if not brain_keys.initialised():
        raise HTTPException(status_code=409, detail='this device is not a brain; choose the Brain role in Setup')
    return brain_keys, brain_manage


@app.get('/api/brain/sensors')
def brain_sensors(principal: dict = Depends(require_viewer)):
    _, m = _brain()
    return m.store().list_sensors()


@app.post('/api/brain/codes')
def brain_create_code(payload: dict, request: Request, principal: dict = Depends(require_admin)):
    _, m = _brain()
    url = (payload or {}).get('brain_url') or f"https://{request.url.hostname}:{os.environ.get('SENTINEL_BRAIN_PORT', '9443')}"
    code = m.store().create_code(int((payload or {}).get('ttl') or 3600))
    audit_event(principal, 'sensor_code_create')
    return m.enrolment_instructions(code, url)


@app.post('/api/brain/sensors/{sensor_id}/revoke')
def brain_revoke(sensor_id: str, principal: dict = Depends(require_admin)):
    _, m = _brain()
    try:
        m.store().revoke_sensor(sensor_id)
    except KeyError:
        raise HTTPException(status_code=404, detail='sensor not found')
    audit_event(principal, 'sensor_revoke', target=sensor_id)
    return {'status': 'revoked'}


@app.post('/api/brain/sensors/{sensor_id}/commands')
def brain_command(sensor_id: str, payload: dict, principal: dict = Depends(require_operator)):
    _, m = _brain()
    payload = payload or {}
    try:
        env = m.issue_command(sensor_id, payload.get('action'), payload.get('ip'), payload.get('ttl'),
                              payload.get('reason') or principal.get('username'))
    except KeyError:
        raise HTTPException(status_code=404, detail='sensor not found')
    except ValueError as exc:
        audit_event(principal, 'sensor_command_issue', target=sensor_id, outcome='rejected',
                    details={'error': str(exc)})
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'sensor_command_issue', target=sensor_id,
                details={k: env['payload'][k] for k in ('seq', 'action', 'ip')})
    return env['payload']


@app.get('/api/brain/upgrade')
def brain_upgrade_status(principal: dict = Depends(require_viewer)):
    """The release staged for this brain's sensors, and the version each sensor runs."""
    _, m = _brain()
    from brain import upgrades
    return {'staged': upgrades.target(),
            'sensors': [{'id': s['id'], 'name': s['name'], 'version': (s['health'] or {}).get('version')}
                        for s in m.store().list_sensors() if not s['revoked']]}


@app.post('/api/brain/upgrade')
def brain_upgrade_stage(payload: dict, principal: dict = Depends(require_admin)):
    """Download a published release (checksum verified) and offer it to every sensor of this brain."""
    _brain()
    from brain import upgrades
    try:
        t = upgrades.stage_release(str((payload or {}).get('version', '')), by=principal.get('username'))
    except (ValueError, OSError) as exc:
        audit_event(principal, 'sensor_upgrade_stage', outcome='rejected', details={'error': str(exc)[:300]})
        raise HTTPException(status_code=400, detail=str(exc))
    return t


@app.post('/api/brain/upgrade/clear')
def brain_upgrade_clear(principal: dict = Depends(require_admin)):
    _brain()
    from brain import upgrades
    upgrades.clear(by=principal.get('username'))
    return {'staged': None}


@app.get('/api/brain/commands')
def brain_commands(sensor_id: Optional[str] = None, principal: dict = Depends(require_viewer)):
    _, m = _brain()
    return m.store().list_commands(sensor_id)


@app.get('/api/brain/flows')
def brain_flows(limit: int = 100, sensor_id: Optional[str] = None, principal: dict = Depends(require_viewer)):
    _, m = _brain()
    return m.store().recent_flows(min(max(limit, 1), 1000), sensor_id)


# ---------- two-node mode: sensor side ----------

@app.get('/api/sensor/status')
def sensor_status(principal: dict = Depends(require_viewer)):
    from sensor import uplink
    from sensor.buffer import DiskBuffer
    buf = DiskBuffer()
    return {'enrolled': uplink.load_identity(), 'buffered': len(buf), 'dropped': buf.dropped()}


@app.post('/api/sensor/enroll')
def sensor_enroll(payload: dict, principal: dict = Depends(require_admin)):
    from sensor import uplink
    payload = payload or {}
    if uplink.load_identity():
        raise HTTPException(status_code=409, detail='already enrolled')
    try:
        sensor_id = uplink.enroll(payload.get('brain_url', ''), payload.get('code', ''),
                                  payload.get('ca_fingerprint', ''), payload.get('name'))
    except uplink.EnrolmentError as exc:
        audit_event(principal, 'sensor_enroll', outcome='rejected', details={'error': str(exc)})
        raise HTTPException(status_code=400, detail=str(exc))
    audit_event(principal, 'sensor_enroll', target=sensor_id, details={'brain_url': payload.get('brain_url')})
    return {'sensor_id': sensor_id}


@app.get('/api/audit/verify')
def audit_verify(principal: dict = Depends(require_admin)):
    return audit_core.get_log().verify()


@app.post('/api/demo/run')
def demo_run(payload: dict, principal: dict = Depends(require_operator)):
    """Safely start a demo attack runner. Does not allow arbitrary shell execution.
    Accepted payload: { ip: optional, simulate_type: optional }
    """
    script = os.path.join(ROOT, 'scripts', 'demo_attack.py')
    if not os.path.exists(script):
        raise HTTPException(status_code=404, detail='demo script not found')
    ip = payload.get('ip')
    sim = payload.get('simulate_type') or payload.get('simulateType') or 'portscan'
    allowed = ['portscan','ddos','dns_tunnel','http_flood','slowloris']
    if sim not in allowed:
        raise HTTPException(status_code=400, detail='invalid simulate_type')
    ip = _validate_ipv4(ip)
    # build args safely
    args = [sys.executable, script, '--simulate_type', sim]
    if ip:
        args += ['--ip', str(ip)]
    try:
        # spawn in background so API is responsive; use safe_popen to validate
        from utils.subprocess_safe import safe_popen
        p = safe_popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        logger.exception('failed to start demo process')
        raise HTTPException(status_code=500, detail=f'failed to start demo: {e}')
    # emit a lightweight event to connected websockets so UI updates immediately
    try:
        publish_event('demo', {'ip': ip, 'simulate_type': sim, 'pid': p.pid, 'started': time.time()})
    except Exception:
        logger.exception('failed to emit demo start event')
    audit_event(principal, 'demo_run', target=ip, details={'simulate_type': sim, 'pid': p.pid})
    return {'status':'started','pid': p.pid}



@app.post('/api/demo/presenter')
def demo_presenter(payload: dict = {}, principal: dict = Depends(require_operator)):
    """Start a guided presenter demo flow. This will orchestrate a sequence of demo steps
    and emit `demo_step` events into the app event queue so connected UIs can animate a demo.
    Payload can include { ip: optional, simulate_type: optional, step_delay: optional }
    """
    ip = payload.get('ip')
    sim = payload.get('simulate_type','portscan')
    try:
        step_delay = float(payload.get('step_delay', 2.5))
    except Exception:
        raise HTTPException(status_code=400, detail='invalid step_delay')
    # validate
    allowed = ['portscan','ddos','dns_tunnel','http_flood','slowloris']
    if sim not in allowed:
        raise HTTPException(status_code=400, detail='invalid simulate_type')
    ip = _validate_ipv4(ip)

    def runner():
        steps = [
            ('normal_traffic','Normal traffic (baseline) active'),
            ('simulate_attack','Simulating attack traffic'),
            ('alert_generated','Detection engine raised an alert'),
            ('apply_block','Applying AI Firewall block (dry-run)'),
            ('blocked_visual','Connection visually blocked'),
            ('demo_end','Demo complete')
        ]
        # if ip provided, include it in payloads
        for name, msg in steps:
            publish_event('demo_step', {'step': name, 'message': msg, 'ip': ip, 'simulate_type': sim, 'ts': time.time()})
            time.sleep(step_delay)

    # start runner thread
    t = threading.Thread(target=runner, daemon=True)
    t.start()

    # also kick off the demo attack script to generate real flow events
    try:
        # reuse demo_run logic but non-blocking
        script = os.path.join(ROOT, 'scripts', 'demo_attack.py')
        if os.path.exists(script):
            args = [sys.executable, script, '--simulate_type', sim]
            if ip:
                args += ['--ip', str(ip)]
            from utils.subprocess_safe import safe_popen
            try:
                safe_popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                logger.exception('failed to spawn demo presenter script')
    except Exception:
        logger.exception('failed to start demo presenter script')

    audit_event(principal, 'demo_presenter')
    return {'status':'presenter_started'}
    





@app.get("/api/alerts")
def alerts(principal: dict = Depends(require_viewer)):
    # prefer DB-backed alerts table
    try:
        from core.storage import get_storage
        s = get_storage('data/sentinel.db')
        s.connect()
        rows = s.get_alerts(limit=1000)
        return maybe_sanitize(rows)
    except Exception:
        return maybe_sanitize(read_json_file("alerts.json"))


@app.get("/api/live_stats")
def live_stats(principal: dict = Depends(require_viewer)):
    # prefer DB live_stats snapshot
    try:
        from core.storage import get_storage
        s = get_storage('data/sentinel.db')
        s.connect()
        payload = s.get_live_stats()
        if payload:
            try:
                return maybe_sanitize(json.loads(payload))
            except Exception:
                return maybe_sanitize(payload)
    except Exception:
        logger.exception('failed to load live_stats from DB; falling back to file')
    return maybe_sanitize(read_json_file("live_stats.json"))


@app.get("/api/device_profiles")
def device_profiles(principal: dict = Depends(require_viewer)):
    # Try DB first for device profiles, fall back to JSON file
    try:
        from core.storage import get_storage
        s = get_storage('data/sentinel.db')
        s.connect()
        profiles = s.get_device_profiles()
        # payloads may be JSON strings; attempt to decode
        out = {}
        for k, v in profiles.items():
            try:
                out[k] = json.loads(v)
            except Exception:
                out[k] = v
        return maybe_sanitize(out)
    except Exception:
        return maybe_sanitize(read_json_file("device_profiles.json"))


@app.get("/api/risk_timeline")
def risk_timeline(principal: dict = Depends(require_viewer)):
    # prefer DB risk timeline
    try:
        from core.storage import get_storage
        s = get_storage('data/sentinel.db')
        s.connect()
        rows = s.get_risk_timeline(limit=1000)
        # transform into expected dict per-device
        out = {}
        for r in rows:
            dev = r.get('device_id')
            if not dev:
                continue
            out.setdefault(dev, [])
            out[dev].append({"timestamp": r.get('timestamp'), "risk": r.get('risk')})
        return maybe_sanitize(out)
    except Exception:
        return maybe_sanitize(read_json_file("risk_timeline.json"))


@app.get("/api/flows")
def flows(limit: int = 500, principal: dict = Depends(require_viewer)):
    limit = max(1, min(int(limit or 500), 5000))
    # prefer DB flows table if available
    try:
        from core.storage import get_storage
        s = get_storage('data/sentinel.db')
        s.connect()
        rows = s.get_flows(limit=limit)
        return maybe_sanitize(rows)
    except Exception:
        try:
            return maybe_sanitize(read_jsonl_optional("flows_history.jsonl", limit=limit))
        except Exception:
            raise HTTPException(status_code=500, detail="failed to read flow history")


@app.get("/api/incidents/timeline")
def incident_timeline(limit: int = 100, principal: dict = Depends(require_viewer)):
    limit = max(1, min(int(limit or 100), 1000))
    alerts_data = read_json_file_optional("alerts.json", [])
    flows_data = read_jsonl_optional("flows_history.jsonl", limit=limit)
    actions_data = read_jsonl_optional(os.path.join("logs", "firewall_actions.jsonl"), limit=limit)
    return maybe_sanitize(build_incident_timeline(alerts_data, flows_data, actions_data, limit=limit))


@app.post("/api/alerts/explain")
def alert_explain(payload: dict, principal: dict = Depends(require_analyst)):
    return maybe_sanitize(explain_alert(payload or {}))


@app.get("/api/reports/security")
def security_report(principal: dict = Depends(require_viewer)):
    alerts_data = read_json_file_optional("alerts.json", [])
    profiles_data = read_json_file_optional("device_profiles.json", {})
    actions_data = read_jsonl_optional(os.path.join("logs", "firewall_actions.jsonl"), limit=1000)
    timeline_data = build_incident_timeline(
        alerts_data,
        read_jsonl_optional("flows_history.jsonl", limit=500),
        actions_data,
        limit=250,
    )
    report = build_security_report(
        alerts=alerts_data,
        timeline=timeline_data,
        firewall_actions=actions_data,
        profiles=profiles_data,
    )
    return maybe_sanitize(report)


@app.get("/api/health")
def health(principal: dict = Depends(require_viewer)):
    return maybe_sanitize(read_json_file("health.json"))


@app.get('/api/device/{device_id}/logs')
def device_logs(device_id: str, limit: int = 200, principal: dict = Depends(require_viewer)):
    # return recent alerts/flows that mention this device id (mac/ip/host)
    alerts_path = os.path.join(ROOT, 'alerts.json')
    if not os.path.exists(alerts_path):
        return []
    try:
        with open(alerts_path, 'r') as f:
            data = json.load(f)
    except Exception:
        return []
    if isinstance(data, dict):
        # maybe wrapped
        entries = data.get('alerts', [])
    else:
        entries = data
    out = []
    for e in reversed(entries):
        s = str(e.get('src','')) + ' ' + str(e.get('src_ip','')) + ' ' + str(e.get('src_mac','')) + ' ' + str(e.get('device',''))
        d = str(e.get('dst','')) + ' ' + str(e.get('dst_ip','')) + ' ' + str(e.get('dst_mac',''))
        if device_id in s or device_id in d:
            out.append(e)
        if len(out) >= limit:
            break
    return out


def _event_bus():
    """The process's event bus; created here when the app runs without its lifespan (e.g. a bare TestClient)."""
    if getattr(app.state, 'bus', None) is None:
        from core.events import EventBus
        app.state.bus = EventBus(sanitize=maybe_sanitize)
        app.state.loop = asyncio.get_running_loop()
        app.state.bus.start()
    return app.state.bus


def publish_event(kind, payload):
    """Publish to the live stream from any thread (endpoints run in a worker pool)."""
    bus, loop = getattr(app.state, 'bus', None), getattr(app.state, 'loop', None)
    if bus is None or loop is None:
        return
    try:
        loop.call_soon_threadsafe(bus.publish, kind, payload)
    except RuntimeError:
        logger.debug('event loop closed; event dropped')


@app.websocket("/ws/packets")
async def websocket_packets(ws: WebSocket):
    """Live alerts, flows and events from the event bus (core.events).

    Browsers cannot set headers on a WebSocket, so the first message must be
    {"type": "auth", "token": "<access token or API key>"} within 5 seconds. It may carry
    "epoch" and "cursor" (the last event seen) to receive exactly the events missed while
    disconnected; the server answers "resync" when that is impossible. Every event has
    "seq" and "epoch"; a "heartbeat" with the current cursor comes every 15 seconds.
    """
    await ws.accept()
    try:
        first = json.loads(await asyncio.wait_for(ws.receive_text(), timeout=5))
        token = first.get('token') if isinstance(first, dict) and first.get('type') == 'auth' else None
    except (asyncio.TimeoutError, ValueError, WebSocketDisconnect):
        token = None
        first = None
    client_host = ws.client.host if ws.client else None
    principal = resolve_principal(token, client_host) if first is not None else None
    if principal is None or pending_setup(principal):
        try:
            await ws.close(code=4401, reason='authentication required')
        except RuntimeError:
            pass
        return
    from core.events import HEARTBEAT_SECONDS
    bus = _event_bus()
    cursor = first.get('cursor') if isinstance(first.get('cursor'), int) else None
    q, backlog = bus.subscribe(first.get('epoch'), cursor)
    await ws.send_text(json.dumps({'type': 'auth_ok', 'seq': bus.seq, 'epoch': bus.epoch,
                                   'payload': {'role': principal['role']}}))
    try:
        for event in backlog:
            await ws.send_text(json.dumps(event, default=str))
        while True:
            try:
                event = await asyncio.wait_for(q.get(), timeout=HEARTBEAT_SECONDS)
            except asyncio.TimeoutError:
                if getattr(q, 'dropped', False):
                    # this client fell too far behind; tell it to reload, then follow from now
                    await ws.send_text(json.dumps({'type': 'resync', 'seq': bus.seq, 'epoch': bus.epoch,
                                                   'payload': {'reason': 'too far behind'}}))
                    bus.unsubscribe(q)
                    q, _ = bus.subscribe()
                await ws.send_text(json.dumps(bus.heartbeat()))
                continue
            await ws.send_text(json.dumps(event, default=str))
    except (WebSocketDisconnect, RuntimeError):
        return
    finally:
        bus.unsubscribe(q)


if os.path.isdir(DIST_DIR):
    # Mount static asset folder (vite usually emits assets/)
    assets_dir = os.path.join(DIST_DIR, 'assets')
    if os.path.isdir(assets_dir):
        app.mount('/assets', StaticFiles(directory=assets_dir), name='assets')


# The SPA index; registered even without a built console so the route table is the same everywhere
@app.get('/')
async def _serve_index():
    index = os.path.join(DIST_DIR, 'index.html')
    if os.path.exists(index):
        return FileResponse(index)
    raise HTTPException(status_code=404, detail='Not Found')

if __name__ == "__main__":
    # same as python -m dashboard.serve (HTTPS when SENTINEL_TLS_CERT/KEY are set)
    from dashboard.serve import main
    sys.exit(main())
