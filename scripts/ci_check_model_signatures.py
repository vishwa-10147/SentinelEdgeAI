#!/usr/bin/env python3
"""CI helper: verify the active Isolation Forest in the Ed25519 model registry.

Exits with non-zero if no active verifiable model exists in the registry.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection import registry
from detection.registry import RegistryError


def main():
    registry_dir = os.environ.get("SENTINEL_MODEL_REGISTRY")
    if not registry_dir:
        print("SENTINEL_MODEL_REGISTRY not set; checking default data/models", file=sys.stderr)

    try:
        idx = registry.index()
    except (OSError, ValueError) as exc:
        print(f"cannot read model registry index: {exc}", file=sys.stderr)
        return 2

    entry = idx.get("isolation_forest")
    if not entry or not entry.get("active"):
        print("no active Isolation Forest in the Ed25519 model registry", file=sys.stderr)
        return 3

    version = entry["active"]
    try:
        meta = registry.verify("isolation_forest", version)
        model, _ = registry.load("isolation_forest", version)
    except (RegistryError, OSError, ValueError) as exc:
        print(f"active model v{version} failed verification: {exc}", file=sys.stderr)
        return 3

    print(f"Isolation Forest v{version} verified (Ed25519): sha256={meta['sha256'][:16]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
