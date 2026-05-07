#!/usr/bin/env python3
import os
import time
import requests
import sys
from core.health_server import start_health_server


class DummyMonitor:
    def get_status(self):
        return {
            "status": "running",
            "flows_processed": 0,
        }


def main():
    port = int(os.environ.get("CI_HEALTH_PORT", "5050"))
    user = os.environ.get("HEALTH_USER", "health")
    pwd = os.environ.get("HEALTH_PASS")
    if not pwd:
        print("HEALTH_PASS not set", file=sys.stderr)
        sys.exit(2)

    # Bind to localhost for CI
    os.environ["HEALTH_BIND_LOCALHOST"] = "true"

    monitor = DummyMonitor()
    server = start_health_server(monitor, host="127.0.0.1", port=port)

    # wait for server to start
    for _ in range(10):
        try:
            r = requests.get(f"http://127.0.0.1:{port}/health", auth=(user, pwd), timeout=1)
            break
        except Exception:
            time.sleep(0.2)
    else:
        print("Health server did not start", file=sys.stderr)
        sys.exit(3)

    if r.status_code != 200:
        print(f"Unexpected response: {r.status_code}", file=sys.stderr)
        print(r.text, file=sys.stderr)
        sys.exit(4)

    print(r.text)
    sys.exit(0)


if __name__ == "__main__":
    main()
