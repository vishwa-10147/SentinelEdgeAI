"""End-to-end smoke that runs basic repo checks and health endpoint.

Runs `scripts/smoke_test.py` and performs an HTTP health check using runtime creds if available.
"""
import subprocess
import os
import sys
import time
import requests

ROOT = os.path.dirname(os.path.dirname(__file__))

def run_smoke_test():
    p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'smoke_test.py')], cwd=ROOT)
    return p.returncode == 0


def health_check():
    # Try runtime file first
    env_path = '/run/sentinel/health.env'
    user = None
    pwd = None
    if os.path.exists(env_path):
        with open(env_path) as f:
            for line in f:
                if line.startswith('HEALTH_USER='):
                    user = line.strip().split('=',1)[1]
                if line.startswith('HEALTH_PASS='):
                    pwd = line.strip().split('=',1)[1]
    # fallback to /etc
    if user is None or pwd is None:
        etc = '/etc/sentinel/health.env'
        if os.path.exists(etc):
            with open(etc) as f:
                for line in f:
                    if line.startswith('HEALTH_USER='):
                        user = line.strip().split('=',1)[1]
                    if line.startswith('HEALTH_PASS='):
                        pwd = line.strip().split('=',1)[1]

    url = 'http://127.0.0.1:5000/health'
    try:
        if user and pwd:
            r = requests.get(url, auth=(user, pwd), timeout=5)
        else:
            r = requests.get(url, timeout=5)
        return r.status_code == 200
    except Exception:
        return False


if __name__ == '__main__':
    ok1 = run_smoke_test()
    print('smoke_test ->', ok1)
    ok2 = health_check()
    print('health_check ->', ok2)
    sys.exit(0 if (ok1 and ok2) else 2
)
