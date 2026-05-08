#!/usr/bin/env python3
"""CI helper: verify signatures for all model/*.pkl using the signing key.

Exits with non-zero if any model is unsigned or verification fails.
"""
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from security.model_signing import verify_model_signature, ModelSignatureError


def main():
    key = os.environ.get("SENTINEL_MODEL_SIGNING_KEY")
    if not key:
        print("SENTINEL_MODEL_SIGNING_KEY not set; failing CI signature check", file=sys.stderr)
        return 2

    model_dir = ROOT / "model"
    if not model_dir.exists():
        print("no model directory; nothing to check")
        return 0

    failures = 0
    for pkl in sorted(model_dir.glob("*.pkl")):
        try:
            print(f"Verifying {pkl.name}...", end=" ")
            verify_model_signature(pkl, key=key.encode("utf-8"))
            print("OK")
        except ModelSignatureError as exc:
            print("FAILED")
            print(f"  {pkl}: {exc}", file=sys.stderr)
            failures += 1

    if failures:
        print(f"{failures} model signature verification failures", file=sys.stderr)
        return 3
    print("All model signatures verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
