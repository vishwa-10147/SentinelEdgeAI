#!/usr/bin/env python3
"""Sign or verify SentinelEdgeAI release model artifacts (Ed25519).

    python scripts/sign_model.py --generate-key ~/.sentinel/release_model.key   # new key pair (offline)
    SENTINEL_MODEL_SIGNING_KEY_FILE=~/.sentinel/release_model.key \\
        python scripts/sign_model.py model/isolation_forest.pkl                   # sign
    python scripts/sign_model.py model/isolation_forest.pkl --verify             # verify (public key only)
"""
import argparse
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from security.model_signing import (PUBLIC_KEY_FILE, ModelSignatureError, generate_keypair, key_id,  # noqa: E402
                                    sign_model, verify_model_signature)


def generate(path, public_path):
    path = os.path.expanduser(path)
    if os.path.exists(path):
        raise ModelSignatureError(f"refusing to overwrite an existing key: {path}")
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    private, public = generate_keypair()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(private)
    with open(public_path, "w", encoding="ascii") as f:
        f.write(public)
    return {"private_key": path, "public_key": str(public_path), "kid": key_id(public)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("model", nargs="?", help="Path to model artifact, e.g. model/isolation_forest.pkl")
    parser.add_argument("--verify", action="store_true", help="Verify instead of signing")
    parser.add_argument("--generate-key", metavar="PATH", help="Create a new Ed25519 private key at PATH and "
                                                                "write its public key to security/release_model.pub")
    parser.add_argument("--public-key", default=str(PUBLIC_KEY_FILE),
                        help="Where --generate-key writes the public key")
    parser.add_argument("--signer", default="local", help="Signer label stored in signature metadata")
    parser.add_argument("--quiet", action="store_true", help="Print only status and model path")
    parser.add_argument("--redact-signature", action="store_true", help="Redact signature value in JSON output")
    args = parser.parse_args()

    try:
        if args.generate_key:
            print(json.dumps({"status": "generated", **generate(args.generate_key, args.public_key)}, indent=2))
            return 0
        if not args.model:
            parser.error("a model path is required")
        if args.verify:
            document = verify_model_signature(args.model)
            status = "verified"
        else:
            document = sign_model(args.model, signer=args.signer)
            status = "signed"
        if args.quiet:
            print(json.dumps({"status": status, "model": args.model}, indent=2))
        else:
            if args.redact_signature:
                document = dict(document)
                document["signature"] = "<redacted>"
            print(json.dumps({"status": status, "signature": document}, indent=2))
    except ModelSignatureError as exc:
        print(f"model signature error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
