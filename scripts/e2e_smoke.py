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
    try:
        p = subprocess.run([sys.executable, os.path.join(ROOT, 'scripts', 'smoke_test.py')], cwd=ROOT, timeout=60)
        return p.returncode == 0
    except subprocess.TimeoutExpired:
        print('smoke_test: timed out')
        return False


def health_check():
    # Allow override for local testing
    env_override = os.environ.get('SENTINEL_HEALTH_ENV_FILE')
    if env_override:
        env_path = env_override
    else:
        # Try runtime file first
        env_path = '/run/sentinel/health.env'
    user = None
    pwd = None
    if os.path.exists(env_path):
        try:
            with open(env_path) as f:
                for line in f:
                    if line.startswith('HEALTH_USER='):
                        user = line.strip().split('=',1)[1]
                    if line.startswith('HEALTH_PASS='):
                        pwd = line.strip().split('=',1)[1]
        except PermissionError:
            print(f'Permission denied reading {env_path}')
    # fallback to /etc
    if user is None or pwd is None:
        etc = '/etc/sentinel/health.env'
        try:
            if os.path.exists(etc):
                with open(etc) as f:
                    for line in f:
                        if line.startswith('HEALTH_USER='):
                            user = line.strip().split('=',1)[1]
                        if line.startswith('HEALTH_PASS='):
                            pwd = line.strip().split('=',1)[1]
        except PermissionError:
            print(f'Permission denied reading {etc}')

    url = 'http://127.0.0.1:5000/health'
    # try a few times but do not loop forever
    attempts = 3
    for i in range(attempts):
        try:
            if user and pwd:
                r = requests.get(url, auth=(user, pwd), timeout=5)
            else:
                r = requests.get(url, timeout=5)
            if r.status_code == 200:
                return True
        except Exception as e:
            print(f'health_check attempt {i+1} failed: {e}')
        time.sleep(1)
    return False


if __name__ == '__main__':
    ok1 = run_smoke_test()
    print('smoke_test ->', ok1)
    ok2 = health_check()
    print('health_check ->', ok2)
    sys.exit(0 if (ok1 and ok2) else 2
)
