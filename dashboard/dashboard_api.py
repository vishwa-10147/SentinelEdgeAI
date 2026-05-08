from fastapi import FastAPI, HTTPException, Depends, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi import WebSocket, WebSocketDisconnect
import os, json, time, asyncio
import logging
from prometheus_client import generate_latest, CONTENT_TYPE_LATEST
from utils import metrics as metrics_utils
import subprocess, sys
from typing import Optional
import threading
import hashlib
import re
import ipaddress
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

API_KEY = os.environ.get('DASHBOARD_API_KEY')

def require_api_key(
    x_api_key: Optional[str] = Header(default=None, alias='X-API-Key'),
    authorization: Optional[str] = Header(default=None),
):
    # Allow missing API key in local development; if set, enforce header auth.
    if API_KEY:
        auth_value = authorization or ''
        bearer = auth_value[7:] if auth_value.lower().startswith('bearer ') else auth_value
        if x_api_key != API_KEY and bearer != API_KEY:
            raise HTTPException(status_code=401, detail='Invalid API key')
    return True

from contextlib import asynccontextmanager


@asynccontextmanager
async def lifespan(app: FastAPI):
    # provide an in-memory asyncio queue for live events
    app.state.event_queue = asyncio.Queue()
    # if CAPTURE_IN_PROCESS=1, attempt to import and run sniffer in a background thread
    if os.environ.get('CAPTURE_IN_PROCESS', '0') == '1':
        try:
            import capture.sniffer as sniffer
            loop = asyncio.get_event_loop()

            def pub(evt):
                try:
                    loop.call_soon_threadsafe(app.state.event_queue.put_nowait, evt)
                except Exception:
                    pass

            sniffer.set_event_publisher(pub)
            t = threading.Thread(target=sniffer.start_sniffing, kwargs={'interface': os.environ.get('CAPTURE_IFACE')}, daemon=True)
            t.start()
            app.state.sniffer_thread = t
            app.state.sniffer_module = sniffer
            print('started sniffer in-process')
        except Exception as e:
            print('failed to start sniffer in-process', e)
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
                    pass
        except Exception:
            pass


# ---------- logging & metrics setup ----------
logging.basicConfig(level=os.environ.get('SENTINEL_LOG_LEVEL','INFO'))
logger = logging.getLogger('sentinel')

# initialize centralized metrics
metrics_utils.init_metrics()



app = FastAPI(title="SentinelEdgeAI Dashboard API", lifespan=lifespan)


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
            pass
    return resp

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

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


@app.get('/metrics')
def metrics():
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
def firewall_rules(api_ok: bool = Depends(require_api_key)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    return maybe_sanitize(firewall.list_rules())


@app.post('/api/firewall/block')
def firewall_block(payload: dict, api_ok: bool = Depends(require_api_key)):
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
def firewall_unblock(payload: dict, api_ok: bool = Depends(require_api_key)):
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
def firewall_actions(api_ok: bool = Depends(require_api_key)):
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
def firewall_policy(api_ok: bool = Depends(require_api_key)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    try:
        return maybe_sanitize(firewall.get_policy())
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post('/api/firewall/policy')
def firewall_policy_update(payload: dict, api_ok: bool = Depends(require_api_key)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    try:
        return maybe_sanitize(firewall.update_policy(payload or {}))
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@app.post('/api/firewall/whitelist')
def firewall_whitelist(payload: dict, api_ok: bool = Depends(require_api_key)):
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
def firewall_expire(api_ok: bool = Depends(require_api_key)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    return maybe_sanitize(firewall.expire_rules())


@app.post('/api/firewall/rollback')
def firewall_rollback(payload: dict = {}, api_ok: bool = Depends(require_api_key)):
    if firewall is None:
        raise HTTPException(status_code=503, detail='firewall module not available')
    reason = (payload or {}).get('reason', 'operator_rollback')
    return maybe_sanitize(firewall.rollback_blocks(reason=reason))



@app.post('/api/demo/run')
def demo_run(payload: dict, api_ok: bool = Depends(require_api_key)):
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
        # spawn in background so API is responsive; we capture pid
        p = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f'failed to start demo: {e}')
    # emit a lightweight event to connected websockets so UI updates immediately
    try:
        evt = {'type':'demo','payload':{'ip': ip, 'simulate_type': sim, 'pid': p.pid, 'started': time.time()}}
        if hasattr(app.state, 'event_queue'):
            try:
                app.state.event_queue.put_nowait(evt)
            except Exception:
                pass
    except Exception:
        pass
    return {'status':'started','pid': p.pid}



@app.post('/api/demo/presenter')
def demo_presenter(payload: dict = {}, api_ok: bool = Depends(require_api_key)):
    """Start a guided presenter demo flow. This will orchestrate a sequence of demo steps
    and emit `demo_step` events into the app event queue so connected UIs can animate a demo.
    Payload can include { ip: optional, simulate_type: optional, step_delay: optional }
    """
    ip = payload.get('ip')
    sim = payload.get('simulate_type','portscan')
    step_delay = float(payload.get('step_delay', 2.5))
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
                pass
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
            subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:
        pass

    return {'status':'presenter_started'}
    





@app.get("/api/alerts")
def alerts(api_ok: bool = Depends(require_api_key)):
    return maybe_sanitize(read_json_file("alerts.json"))


@app.get("/api/live_stats")
def live_stats():
    return maybe_sanitize(read_json_file("live_stats.json"))


@app.get("/api/device_profiles")
def device_profiles(api_ok: bool = Depends(require_api_key)):
    return maybe_sanitize(read_json_file("device_profiles.json"))


@app.get("/api/risk_timeline")
def risk_timeline(api_ok: bool = Depends(require_api_key)):
    return maybe_sanitize(read_json_file("risk_timeline.json"))


@app.get("/api/health")
def health(api_ok: bool = Depends(require_api_key)):
    return maybe_sanitize(read_json_file("health.json"))


@app.get('/api/device/{device_id}/logs')
def device_logs(device_id: str, limit: int = 200, api_ok: bool = Depends(require_api_key)):
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
    last_alert_mtime = 0
    last_stats_mtime = 0
    # tail position for live events file
    last_events_pos = 0
    try:
        while True:
            # alerts
            a_path = os.path.join(ROOT, 'alerts.json')
            if os.path.exists(a_path):
                m = os.path.getmtime(a_path)
                if m > last_alert_mtime:
                    last_alert_mtime = m
                    try:
                        with open(a_path,'r') as f:
                            data = json.load(f)
                    except Exception:
                        data = None
                    if isinstance(data, list):
                        for item in data[-10:]:
                            await ws.send_text(json.dumps({'type':'alert','payload': maybe_sanitize(item)}))
            # live_stats flows
            s_path = os.path.join(ROOT, 'live_stats.json')
            if os.path.exists(s_path):
                m = os.path.getmtime(s_path)
                if m > last_stats_mtime:
                    last_stats_mtime = m
                    try:
                        with open(s_path,'r') as f:
                            data = json.load(f)
                    except Exception:
                        data = None
                    # if data contains flows, stream them
                    if isinstance(data, dict) and 'flows' in data:
                        for fl in data['flows'][-20:]:
                            await ws.send_text(json.dumps({'type':'flow','payload': maybe_sanitize(fl)}))
            # live events (jsonl) - tail new lines and stream as events
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
                                    # ignore malformed
                                    continue
                            last_events_pos = ef.tell()
                except Exception:
                    pass
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
    uvicorn.run(app, host="0.0.0.0", port=9000)
