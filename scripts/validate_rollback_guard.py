#!/usr/bin/env python3
"""Validate the rollback guard by creating a block, forcing health failures,
and ensuring the guard triggers rollback after the threshold.

This is a safe, local test: it uses the Python API to add/remove rules and
the repo's `scripts/firewall_rollback_guard.sh` to exercise the guard logic.
"""
import os
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core import firewall


def main():
    tmp = tempfile.TemporaryDirectory(prefix="sentinel_guard_test_")
    state_dir = tmp.name
    venv_python = os.environ.get("VENV_PYTHON", sys.executable)
    guard = os.path.join(ROOT, "scripts", "firewall_rollback_guard.sh")

    print("Using state dir:", state_dir)

    test_ip = "198.51.100.250"
    print("Adding test block:")
    firewall.add_block(test_ip, ttl=3600, reason="validate_guard_test")
    rules = firewall.list_rules()
    assert any(r.get("ip") == test_ip for r in rules), "block not recorded"
    print("Block recorded. Rules count:", len(rules))

    # Point the guard at a health URL that will fail (no server listening)
    env = os.environ.copy()
    env["ENABLE_ROLLBACK_GUARD"] = "1"
    env["VENV_PYTHON"] = venv_python
    env["STATE_DIR"] = state_dir
    env["HEALTH_URL"] = "http://127.0.0.1:59999/api/health"  # port unlikely to be open
    env["FAIL_THRESHOLD"] = "2"

    # Run the guard multiple times to reach threshold
    print("Running guard until rollback triggers (threshold=2)...")
    max_attempts = 8
    for i in range(max_attempts):
        proc = subprocess.run([guard], env=env, cwd=ROOT)
        # guard returns non-zero while failures accumulate; continue until it succeeds in rollback
        time.sleep(0.5)
        rules_after = firewall.list_rules()
        if not any(r.get("ip") == test_ip for r in rules_after):
            print("Rollback detected after", i + 1, "attempts")
            break
    else:
        print("Rollback did not trigger after max attempts", max_attempts, file=sys.stderr)
        return 3

    # Allow state to settle
    time.sleep(0.5)

    rules_after = firewall.list_rules()
    print("Rules after guard run:", rules_after)
    if any(r.get("ip") == test_ip for r in rules_after):
        print("Rollback did not clear test block", file=sys.stderr)
        return 2
    print("Rollback guard cleared test block — validation passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
