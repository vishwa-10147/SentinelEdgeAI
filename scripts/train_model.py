#!/usr/bin/env python3
"""Train the SentinelEdgeAI Isolation Forest and register it in the Ed25519 model registry.

    python scripts/train_model.py --input flows_history.jsonl
"""
import argparse
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

from detection import registry
from detection.registry import RegistryError


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
        help=("Path to write the trained model (kept for backward compatibility; "
              "the signed model is stored in the Ed25519 registry)."),
    )
    parser.add_argument("--contamination", type=float, default=0.02)
    parser.add_argument("--n-estimators", type=int, default=100)
    parser.add_argument("--min-samples", type=int, default=100)
    parser.add_argument(
        "--registry-dir",
        default=os.environ.get("SENTINEL_MODEL_REGISTRY"),
        help="Model registry directory (defaults to SENTINEL_MODEL_REGISTRY or data/models).",
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

    # Register through the Ed25519-signed registry (starts in 'shadow'), then activate.
    version = registry.register(
        'isolation_forest', model,
        metrics={'contamination': args.contamination, 'n_estimators': args.n_estimators,
                 'samples': len(vectors), 'skipped': skipped},
        features=list(FEATURE_KEYS),
        notes='trained by scripts/train_model.py',
    )
    registry.set_stage('isolation_forest', version, 'active')

    # Also write a copy to --output for backward compatibility with any callers
    # that expect a model file on disk.
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, output_path)

    print(
        json.dumps(
            {
                "status": "trained",
                "input": str(input_path),
                "output": str(output_path),
                "registry_version": version,
                "samples": len(vectors),
                "skipped": skipped,
                "signed": True,
                "algorithm": "ed25519",
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
