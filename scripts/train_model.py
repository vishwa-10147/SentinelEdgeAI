#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from security.model_signing import ModelSignatureError, sign_model


FEATURE_KEYS = ("duration", "total_bytes", "total_packets", "byte_ratio")


def parse_args():
    parser = argparse.ArgumentParser(
        description="Train the SentinelEdgeAI Isolation Forest from stored flow history."
    )
    parser.add_argument(
        "--input",
        default=str(ROOT / "flows_history.jsonl"),
        help="Path to flow history JSONL input.",
    )
    parser.add_argument(
        "--output",
        default=str(ROOT / "model" / "isolation_forest.pkl"),
        help="Path to write the trained model.",
    )
    parser.add_argument("--contamination", type=float, default=0.02)
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument(
        "--allow-unsigned",
        action="store_true",
        help="Write the model even when no signing key is configured.",
    )
    return parser.parse_args()


def to_vector(record):
    features = record.get("features") if isinstance(record.get("features"), dict) else record
    vector = []
    for key in FEATURE_KEYS:
        value = features.get(key)
        if value is None and key == "total_bytes":
            value = record.get("bytes")
        if value is None and key == "total_packets":
            value = record.get("packets")
        if value is None:
            return None
        vector.append(float(value))
    return vector


def load_vectors(path):
    vectors = []
    skipped = 0
    with open(path, "r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                skipped += 1
                continue
            vector = to_vector(record)
            if vector is None:
                skipped += 1
                continue
            vectors.append(vector)
    return vectors, skipped


def main():
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise SystemExit(f"flow history not found: {input_path}")

    vectors, skipped = load_vectors(input_path)
    if len(vectors) < args.min_samples:
        raise SystemExit(
            f"not enough training samples: {len(vectors)} found, {args.min_samples} required"
        )

    model = IsolationForest(
        n_estimators=args.n_estimators,
        contamination=args.contamination,
        random_state=42,
    )
    model.fit(np.array(vectors))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)

    signed = False
    try:
        sign_model(output_path, signer="scripts/train_model.py")
        signed = True
    except ModelSignatureError as exc:
        if not args.allow_unsigned:
            output_path.unlink(missing_ok=True)
            raise SystemExit(
                f"model signing failed: {exc}. Set SENTINEL_MODEL_SIGNING_KEY "
                "or rerun with --allow-unsigned for development only."
            )

    print(
        json.dumps(
            {
                "status": "trained",
                "input": str(input_path),
                "output": str(output_path),
                "samples": len(vectors),
                "skipped": skipped,
                "signed": signed,
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
