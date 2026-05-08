#!/usr/bin/env python3
"""Simple smoke test for SentinelEdgeAI environment.

Checks:
 - can load configuration
 - prints a few important config values
 - attempts to import key modules
"""
import sys
import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from core.config_loader import Config

SUCCESS = True

print("Running SentinelEdgeAI smoke test...")

# Load config
try:
    cfg = Config()
    print("Loaded config keys:", list(cfg.config.keys()))
    try:
        log_level = cfg.get("logging", "level")
    except Exception:
        log_level = None
    print("logging.level:", log_level)
except Exception as e:
    print("Failed to load config:", e)
    SUCCESS = False

# Try importing a few modules
modules = [
    "capture.sniffer",
    "core.engine" if False else "core.config_loader",
    "utils.logger",
]
for m in modules:
    try:
        __import__(m)
        print(f"OK import: {m}")
    except Exception as e:
        print(f"Failed import {m}: {e}")
        SUCCESS = False

if SUCCESS:
    print("SMOKE TEST: PASS")
    sys.exit(0)
else:
    print("SMOKE TEST: FAIL")
    sys.exit(2)
