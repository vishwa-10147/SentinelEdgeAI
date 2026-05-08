#!/usr/bin/env python3
"""Simple integration test: run test alert and verify dashboard JSONs updated."""
import os
import time
import json
import subprocess


def read_json(path):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def main():
    repo = os.getcwd()
    sender = os.path.join(repo, "scripts", "send_test_alert.py")

    files = ["alerts.json", "live_stats.json", "risk_timeline.json"]
    before = {f: os.path.getmtime(f) if os.path.exists(f) else 0 for f in files}

    print("Running test alert...")
    env = os.environ.copy()
    env["PYTHONPATH"] = repo
    subprocess.check_call([os.path.join(repo, ".venv", "bin", "python"), sender], env=env)

    # give a moment for service to pick up
    time.sleep(1)

    after = {f: os.path.getmtime(f) if os.path.exists(f) else 0 for f in files}

    success = True
    for f in files:
        print(f, "before:", before[f], "after:", after[f])
        if after[f] <= before[f]:
            print("ERROR:", f, "was not updated")
            success = False

    if success:
        print("Integration test: PASS — JSON files updated")
        return 0
    else:
        print("Integration test: FAIL")
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
