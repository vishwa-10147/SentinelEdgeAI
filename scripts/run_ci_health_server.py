#!/usr/bin/env python3
"""Run a temporary health HTTP server bound to localhost for CI/test runs.

Starts `core.health_server.start_health_server` with a simple monitor and blocks
until interrupted. Honor `HEALTH_USER` and `HEALTH_PASS` env vars for basic auth.
"""
import os
import time
import sys
import logging
from pathlib import Path

# Make repo root importable when the script is run via nohup/CI without PYTHONPATH
repo_root = Path(__file__).resolve().parents[1]
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

try:
    from core.health_server import start_health_server
except Exception as e:
    logging.basicConfig(level=logging.INFO)
    logging.error("Failed to import core.health_server: %s", e)
    logging.error("Ensure the repository root is on PYTHONPATH or run from the repo root."
                  " Added %s to sys.path and re-raised.", repo_root)
    raise


class DummyMonitor:
    def get_status(self):
        return {"status": "running", "flows_processed": 0}


def main():
    port = int(os.environ.get("CI_HEALTH_PORT", os.environ.get("HEALTH_PORT", "5000")))
    # bind to localhost for safety
    os.environ["HEALTH_BIND_LOCALHOST"] = "true"
    # configure logging so nohup captures readable startup messages
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.info("Starting CI health server (host=127.0.0.1 port=%s)", port)
    monitor = DummyMonitor()
    server = start_health_server(monitor, host="127.0.0.1", port=port)
    logging.info("Health server listening on 127.0.0.1:%s", port)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        try:
            server.shutdown()
        except Exception:
            pass


if __name__ == '__main__':
    main()
