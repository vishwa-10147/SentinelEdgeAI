import json
import threading
import os
import base64
from http.server import HTTPServer, BaseHTTPRequestHandler
import logging


class _HealthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/health"):
            # Optional Basic auth: set HEALTH_USER and HEALTH_PASS env vars
            user = os.environ.get("HEALTH_USER")
            pwd = os.environ.get("HEALTH_PASS")
            if user and pwd:
                auth = self.headers.get("Authorization")
                if not auth or not auth.startswith("Basic "):
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="Health"')
                    self.end_headers()
                    return
                try:
                    token = auth.split(" ", 1)[1].strip()
                    decoded = base64.b64decode(token).decode("utf-8")
                except Exception:
                    self.send_response(401)
                    self.send_header("WWW-Authenticate", 'Basic realm="Health"')
                    self.end_headers()
                    return
                if decoded != f"{user}:{pwd}":
                    self.send_response(403)
                    self.end_headers()
                    return

            status = self.server.monitor.get_status()
            payload = json.dumps(status).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Integrate with the package logger instead of printing to stderr
        logger = logging.getLogger("sentinel.health")
        logger.info(format % args)


class HealthHTTPServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, monitor):
        super().__init__(server_address, RequestHandlerClass)
        self.monitor = monitor
    
    def shutdown(self):
        """Shutdown the server and ensure the listening socket is closed."""
        try:
            super().shutdown()
        finally:
            try:
                self.server_close()
            except Exception:
                logger = logging.getLogger("sentinel.health")
                logger.debug("server_close failed during shutdown", exc_info=True)


def start_health_server(monitor, host="0.0.0.0", port=8000):  # nosec B104
    """Start a simple HTTP health endpoint in a background thread.

    Exposes `/health` which returns JSON from `monitor.get_status()`.
    """
    logger = logging.getLogger("sentinel.health")

    # Allow optional environment override to bind to localhost for extra safety
    bind_local = os.environ.get("HEALTH_BIND_LOCALHOST", "false").lower() in ("1", "true", "yes", "on")
    if bind_local:
        logger.info("HEALTH_BIND_LOCALHOST=true, binding health endpoint to 127.0.0.1")
        host = "127.0.0.1"

    server = HealthHTTPServer((host, port), _HealthHandler, monitor)

    def _run():
        logger.info(f"Health server listening on {host}:{port}")
        try:
            server.serve_forever()
        except Exception:
            logger.exception("Health server terminated")

    t = threading.Thread(target=_run, daemon=True, name="health-server")
    t.start()
    return server
