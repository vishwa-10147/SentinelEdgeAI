#!/usr/bin/env python3
"""Sign or verify SentinelEdgeAI model artifacts."""
import argparse
import json
import os
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from security.model_signing import ModelSignatureError, sign_model, verify_model_signature


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("model", help="Path to model artifact, e.g. model/isolation_forest.pkl")
    parser.add_argument("--verify", action="store_true", help="Verify instead of signing")
    parser.add_argument("--signer", default="local", help="Signer label stored in signature metadata")
    parser.add_argument("--quiet", action="store_true", help="Print only status and model path")
    parser.add_argument("--redact-signature", action="store_true", help="Redact signature value in JSON output")
    args = parser.parse_args()

    try:
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
