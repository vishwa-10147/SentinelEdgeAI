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
    pending_setup,
)

from contextlib import asynccontextmanager
from core.db_maintenance import start_background


@asynccontextmanager
async def lifespan(app: FastAPI):
    # provide an in-memory asyncio queue for live events
    app.state.event_queue = asyncio.Queue()
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
                    loop.call_soon_threadsafe(app.state.event_queue.put_nowait, evt)
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
}


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    resp = await call_next(request)
    for name, value in SECURITY_HEADERS.items():
        resp.headers.setdefault(name, value)
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
        return maybe_sanitize(res)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post('/api/firewall/unblock')
def firewall_unblock(payload: dict, principal: dict = Depends(require_operator)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    ip = payload.get('ip')
    if not ip:
        raise HTTPException(status_code=400, detail='missing ip')
    try:
        res = firewall.remove_block(ip)
        return maybe_sanitize(res)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


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
        return maybe_sanitize(firewall.update_policy(payload or {}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post('/api/firewall/whitelist')
def firewall_whitelist(payload: dict, principal: dict = Depends(require_operator)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    ip = payload.get('ip')
    action = payload.get('action', 'add')
    if not ip:
        raise HTTPException(status_code=400, detail='missing ip')
    try:
        if action == 'add':
            return maybe_sanitize(firewall.add_whitelist(ip))
        if action == 'remove':
            return maybe_sanitize(firewall.remove_whitelist(ip))
        raise HTTPException(status_code=400, detail='invalid whitelist action')
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post('/api/firewall/expire')
def firewall_expire(principal: dict = Depends(require_operator)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    return maybe_sanitize(firewall.expire_rules())


@app.post('/api/firewall/rollback')
def firewall_rollback(payload: dict = {}, principal: dict = Depends(require_operator)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    reason = (payload or {}).get('reason', 'operator_rollback')
    return maybe_sanitize(firewall.rollback_blocks(reason=reason))



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
        evt = {'type':'demo','payload':{'ip': ip, 'simulate_type': sim, 'pid': p.pid, 'started': time.time()}}
        if hasattr(app.state, 'event_queue'):
            try:
                app.state.event_queue.put_nowait(evt)
            except Exception:
                logger.exception('failed to enqueue event')
    except Exception:
        logger.exception('failed to emit demo start event')
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
            evt = {'type':'demo_step','payload':{'step': name, 'message': msg, 'ip': ip, 'simulate_type': sim, 'ts': time.time()}}
            try:
                if hasattr(app.state, 'event_queue'):
                    app.state.event_queue.put_nowait(evt)
            except Exception:
                logger.exception('failed to enqueue demo step event')
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


@app.websocket("/ws/packets")
async def websocket_packets(ws: WebSocket):
    # simple websocket stream: polls alerts.json and live_stats.json and pushes new items
    await ws.accept()
    # Browsers cannot set headers on a WebSocket, so the first message must be
    # {"type": "auth", "token": "<access token or API key>"} within 5 seconds.
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
    await ws.send_text(json.dumps({'type': 'auth_ok', 'payload': {'role': principal['role']}}))
    last_alert_mtime = 0
    last_stats_mtime = 0
    last_stats_payload = None
    # tail position for live events file
    last_events_pos = 0
    try:
        while True:
            # alerts
            # Alerts (from DB preferred)
            try:
                from core.storage import get_storage
                s = get_storage('data/sentinel.db')
                s.connect()
                rows = s.get_alerts(limit=10)
                for item in reversed(rows):
                    ts = item.get('timestamp', 0)
                    if ts > last_alert_mtime:
                        last_alert_mtime = ts
                        await ws.send_text(json.dumps({'type':'alert','payload': maybe_sanitize(item)}))
            except Exception:
                logger.exception('failed to stream DB alerts; falling back to file')
                # fallback to file-based alerts if compatibility mode enabled
                if ENABLE_FILE_FALLBACK:
                    a_path = os.path.join(ROOT, 'alerts.json')
                    if os.path.exists(a_path):
                        m = os.path.getmtime(a_path)
                        if m > last_alert_mtime:
                            last_alert_mtime = m
                            try:
                                with open(a_path,'r') as f:
                                    data = json.load(f)
                            except Exception:
                                logger.exception('failed to read alerts.json')
                                data = None
                            if isinstance(data, list):
                                for item in data[-10:]:
                                    await ws.send_text(json.dumps({'type':'alert','payload': maybe_sanitize(item)}))
            # live_stats (DB preferred)
            try:
                from core.storage import get_storage
                s = get_storage('data/sentinel.db')
                s.connect()
                payload = s.get_live_stats()
                try:
                    payload = s.get_live_stats()
                    if payload:
                        payload_str = payload if isinstance(payload, str) else json.dumps(payload)
                        if payload_str != last_stats_payload:
                            last_stats_payload = payload_str
                            try:
                                data = json.loads(payload_str)
                            except Exception:
                                logger.exception('failed to decode live_stats payload')
                                data = payload
                            if isinstance(data, dict) and 'flows' in data:
                                for fl in data['flows'][-20:]:
                                    await ws.send_text(json.dumps({'type':'flow','payload': maybe_sanitize(fl)}))
                except Exception:
                    logger.exception('failed to stream DB live_stats; falling back to file')
                    # fallback to file-based live_stats if compatibility mode enabled
                    if ENABLE_FILE_FALLBACK:
                        s_path = os.path.join(ROOT, 'live_stats.json')
                        if os.path.exists(s_path):
                            m = os.path.getmtime(s_path)
                            if m > last_stats_mtime:
                                last_stats_mtime = m
                                try:
                                    with open(s_path,'r') as f:
                                        data = json.load(f)
                                except Exception:
                                    logger.exception('failed to read live_stats.json')
                                    data = None
                                if isinstance(data, dict) and 'flows' in data:
                                    for fl in data['flows'][-20:]:
                                        await ws.send_text(json.dumps({'type':'flow','payload': maybe_sanitize(fl)}))
                from core.storage import get_storage
                s = get_storage('data/sentinel.db')
                s.connect()
                rows = s.get_live_events(limit=200)
                for ts, payload in rows:
                    try:
                        if ts > last_events_pos:
                            last_events_pos = ts
                            try:
                                obj = json.loads(payload)
                            except Exception:
                                logger.exception('failed to parse live event payload')
                                obj = payload
                            await ws.send_text(json.dumps({'type': obj.get('type','event') if isinstance(obj, dict) else 'event', 'payload': maybe_sanitize(obj)}))
                    except Exception:
                        logger.exception('failed to send live event websocket message')
                        continue
            except Exception:
                # fallback to file tailing if compatibility mode enabled
                if ENABLE_FILE_FALLBACK:
                    e_path = os.path.join(ROOT, 'live_events.jsonl')
                    if os.path.exists(e_path):
                        try:
                            size = os.path.getsize(e_path)
                            if size < last_events_pos:
                                # rotated/truncated file
                                last_events_pos = 0
                            if size > last_events_pos:
                                with open(e_path, 'r') as ef:
                                    ef.seek(last_events_pos)
                                    for line in ef:
                                        line = line.strip()
                                        if not line:
                                            continue
                                        try:
                                            obj = json.loads(line)
                                            await ws.send_text(json.dumps({'type': obj.get('type','event'), 'payload': maybe_sanitize(obj)}))
                                        except Exception:
                                            logger.exception('malformed live event line')
                                            continue
                                    last_events_pos = ef.tell()
                        except Exception:
                            logger.exception('failed to tail live events file')
            # drain in-process queue if present
            if hasattr(app.state, 'event_queue'):
                try:
                    while True:
                        obj = app.state.event_queue.get_nowait()
                        await ws.send_text(json.dumps({'type': obj.get('type','event'), 'payload': obj}))
                except asyncio.QueueEmpty:
                    pass
            await asyncio.sleep(1)
    except WebSocketDisconnect:
        return


if os.path.isdir(DIST_DIR):
    # Mount static asset folder (vite usually emits assets/)
    assets_dir = os.path.join(DIST_DIR, 'assets')
    if os.path.isdir(assets_dir):
        app.mount('/assets', StaticFiles(directory=assets_dir), name='assets')

    # Serve other static files and the SPA index for non-API paths
    @app.get('/')
    async def _serve_index():
        index = os.path.join(DIST_DIR, 'index.html')
        if os.path.exists(index):
            return FileResponse(index)
        raise HTTPException(status_code=404, detail='Not Found')

if __name__ == "__main__":
    import uvicorn
    # Allow configuring host/port via environment for safer defaults
    host = os.getenv("SENTINEL_HOST", "127.0.0.1")
    port = int(os.getenv("SENTINEL_PORT", "9000"))
    uvicorn.run(app, host=host, port=port)
