#!/usr/bin/env python3
"""CI helper: check Ed25519 model signing for the Isolation Forest.

* When a registry exists (SENTINEL_MODEL_REGISTRY or data/models) with an active
  Isolation Forest, that model must verify and load.
* On a clean checkout there is no registry: devices train the Isolation Forest
  on their own traffic and sign it with their own key. The check then proves
  the signing path end to end in a temporary registry: register, verify, load,
  and refuse a tampered model file.

Exits non-zero on any failure.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from detection import registry
from detection.registry import RegistryError


def self_test():
    import shutil
    import tempfile

    import numpy as np
    from sklearn.ensemble import IsolationForest

    tmp = tempfile.mkdtemp(prefix="model-registry-")
    old = os.environ.get("SENTINEL_MODEL_REGISTRY")
    os.environ["SENTINEL_MODEL_REGISTRY"] = tmp
    try:
        model = IsolationForest(n_estimators=10, random_state=0).fit(np.random.default_rng(0).normal(size=(200, 4)))
        version = registry.register("isolation_forest", model, metrics={"ci": True})
        registry.set_stage("isolation_forest", version, "active")
        registry.verify("isolation_forest", version)
        registry.load("isolation_forest", version)
        files = [f for f in Path(tmp).rglob("*") if f.is_file() and f.suffix in (".pkl", ".joblib")]
        if not files:
            print("self-test: registered model file not found", file=sys.stderr)
            return 3
        with open(files[0], "ab") as f:
            f.write(b"tamper")
        try:
            registry.load("isolation_forest", version)
        except (RegistryError, OSError, ValueError):
            print(f"Ed25519 model registry self-test passed: v{version} signed, verified, loaded; tampering refused")
            return 0
        print("self-test: a tampered model was loaded", file=sys.stderr)
        return 3
    finally:
        if old is None:
            os.environ.pop("SENTINEL_MODEL_REGISTRY", None)
        else:
            os.environ["SENTINEL_MODEL_REGISTRY"] = old
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    if not Path(registry.registry_dir(), "index.json").exists():
        print("no model registry in this checkout (devices train and sign locally); running the signing self-test",
              file=sys.stderr)
        return self_test()
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
