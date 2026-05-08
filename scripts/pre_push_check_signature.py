#!/usr/bin/env python3
"""Pre-push check: verify any model artifacts staged for commit have valid signatures.

This script is intended to be called from `.git/hooks/pre-push` and will
abort the push if any `*.pkl` (or files under `model/`) are staged without a
matching and valid `.sig` file.
"""
import json
import os
import subprocess
import sys
from pathlib import Path

from security.model_signing import ModelSignatureError, verify_model_signature, load_signing_key, file_sha256


def staged_files():
    res = subprocess.run(["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                         capture_output=True, text=True)
    if res.returncode != 0:
        print("failed to query git staged files", file=sys.stderr)
        sys.exit(2)
    return [Path(p) for p in res.stdout.splitlines() if p.strip()]


def main():
    files = staged_files()
    models = [p for p in files if p.suffix == ".pkl" or p.parts and p.parts[0] == "model"]
    if not models:
        return 0

    allow_unsigned = os.environ.get("SENTINEL_ALLOW_UNSIGNED_MODELS", "0") == "1"

    # Attempt to load a local signing key; if not present, fall back to sha256 check
    local_key = None
    try:
        local_key = load_signing_key(required=False)
    except Exception:
        local_key = None

    errors = []
    for m in models:
        sig_path = Path(f"{m}.sig")
        if not sig_path.exists():
            errors.append(f"missing signature for model: {m} -> expected {sig_path}")
            continue
        # If we have the signing key, perform full HMAC verification
        if local_key:
            try:
                verify_model_signature(str(m), key=local_key)
            except ModelSignatureError as exc:
                errors.append(f"signature verification failed for {m}: {exc}")
            continue

        # No local key: at least ensure the signature file's sha256 matches the model file
        try:
            doc = json.loads(sig_path.read_text(encoding="utf-8"))
            expected_sha = doc.get("sha256")
            actual_sha = file_sha256(str(m))
            if expected_sha != actual_sha:
                errors.append(f"sha256 mismatch for {m}: expected {expected_sha} actual {actual_sha}")
        except Exception as exc:
            errors.append(f"failed to validate signature metadata for {m}: {exc}")

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
