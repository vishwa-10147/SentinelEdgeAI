#!/usr/bin/env python3
"""Pre-push check: verify any model artifacts staged for commit have valid signatures.

This script is intended to be called from `.git/hooks/pre-push` and will
abort the push if any `*.pkl` (or files under `model/`) are staged without a
matching and valid `.sig` file.
"""
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from security.model_signing import ModelSignatureError, verify_model_signature  # noqa: E402


def staged_files():
    res = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                         capture_output=True, text=True)
    if res.returncode != 0:
        print("failed to query git staged files", file=sys.stderr)
        sys.exit(2)
    return [Path(p) for p in res.stdout.splitlines() if p.strip()]


def main():
    files = staged_files()
    models = [p for p in files if p.suffix == ".pkl" or (p.parts and p.parts[0] == "model" and p.suffix != ".sig")]
    if not models:
        return 0
    allow_unsigned = os.environ.get("SENTINEL_ALLOW_UNSIGNED_MODELS", "0") == "1"
    errors = []
    for m in models:
        try:
            verify_model_signature(str(m))              # Ed25519, public key in security/release_model.pub
        except ModelSignatureError as exc:
            errors.append(f"{m}: {exc}")
    if errors:
        print("Model signature check failed:")
        for e in errors:
            print(" - ", e)
        if allow_unsigned:
            print("Pushing unsigned models allowed by SENTINEL_ALLOW_UNSIGNED_MODELS=1")
            return 0
        print("Aborting push. Sign models with scripts/sign_model.py before pushing.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
