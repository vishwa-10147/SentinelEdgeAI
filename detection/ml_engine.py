"""Isolation Forest ML engine backed by the Ed25519-signed model registry.

The release Isolation Forest is registered through ``detection.registry``
(Ed25519 signatures, shadow -> canary -> active) so devices hold only the
public key and every released model is verifiable.

    python -m detection.ml_engine train flows.jsonl   # registers + activates
    python -m detection.ml_engine predict '{"duration":1,"total_bytes":100,...}'
"""
import json
import os
import sys
from typing import Optional

import numpy as np
from sklearn.ensemble import IsolationForest
import joblib

from detection import registry
from detection.registry import RegistryError
from utils import metrics as metrics_utils


NAME = 'isolation_forest'
FEATURES = ['duration', 'total_bytes', 'total_packets', 'byte_ratio']


class MLEngine:

    def __init__(self, contamination=0.02, model_path: Optional[str] = None):
        # model_path is kept for backward compatibility; the model now lives
        # in the Ed25519 registry (name 'isolation_forest').
        self.contamination = contamination
        self.model_path = model_path or 'model/isolation_forest.pkl'
        self.training_data = []
        self.trained = False
        self.allow_unsigned_models = os.environ.get("SENTINEL_ALLOW_UNSIGNED_MODELS", "0") == "1"
        self._model = None
        self._load_active()

    # ---------- registry-backed load / store ----------

    def _load_active(self):
        """Load the active Isolation Forest from the Ed25519 registry, or create a new one."""
        try:
            idx = registry.index()
            entry = idx.get(NAME)
            if entry and entry.get('active'):
                model, _meta = registry.load(NAME, entry['active'])
                self._model = model
                self.trained = True
                self._report_metrics(1)
                return
        except (RegistryError, OSError, ValueError) as exc:
            if self.allow_unsigned_models:
                print(f"Warning: no verifiable Isolation Forest in registry ({exc}); starting untrained.")
            else:
                print(f"Warning: no verifiable Isolation Forest in registry ({exc}); starting untrained.")
        self._model = IsolationForest(
            n_estimators=100,
            contamination=self.contamination,
            random_state=42
        )
        self.trained = False
        try:
            if metrics_utils.ML_MODEL_LOADED is not None:
                metrics_utils.ML_MODEL_LOADED.set(0)
        except Exception:
            pass

    def _report_metrics(self, status: int):
        try:
            if metrics_utils.ML_MODEL_LOADED is not None:
                metrics_utils.ML_MODEL_LOADED.set(1)
            if metrics_utils.ML_SIGNATURE_STATUS is not None:
                metrics_utils.ML_SIGNATURE_STATUS.set(status)
        except Exception:
            pass

    # ---------- training ----------

    def add_training_sample(self, features):
        self.training_data.append(self._to_vector(features))

    def train(self):
        if len(self.training_data) < 100:
            return False

        X = np.array(self.training_data)
        if self._model is None or not self.trained:
            self._model = IsolationForest(
                n_estimators=100,
                contamination=self.contamination,
                random_state=42
            )
        self._model.fit(X)
        self.trained = True

        # Register through the Ed25519-signed registry (starts in 'shadow').
        version = registry.register(
            NAME, self._model,
            metrics={'contamination': self.contamination, 'samples': len(self.training_data)},
            features=list(FEATURES),
            notes='trained by MLEngine.train',
        )
        # Promote straight to active (the release model; canary/shadow used by the autoencoder path).
        registry.set_stage(NAME, version, 'active')
        self._report_metrics(1)
        print(f'Isolation Forest trained, saved, signed (Ed25519) and activated as v{version}.')
        return True

    # ---------- inference ----------

    def predict(self, features):
        if not self.trained or self._model is None:
            return 0

        vector = self._to_vector(features)
        fast = self._fast_scorer()
        if fast is not None:
            label = fast.predict_one(vector)
        else:
            label = self._model.predict([vector])[0]

        # -1 = anomaly
        #  1 = normal
        return 1 if label == -1 else 0

    def _fast_scorer(self):
        """Compiled scorer for the current model (same results, ~100x faster for one flow)."""
        model = self._model
        if model is None:
            return None
        if getattr(self, '_fast_for', None) is not model:
            self._fast_for = model
            try:
                from detection.fast_iforest import FastIsolationForest
                self._fast = FastIsolationForest(model)
            except Exception:
                self._fast = None   # verified mismatch or unexpected model: use sklearn
        return self._fast

    def _to_vector(self, features):
        return [
            features["duration"],
            features["total_bytes"],
            features["total_packets"],
            features["byte_ratio"],
        ]


def main(argv=None):
    parser = __import__('argparse').ArgumentParser(prog='python -m detection.ml_engine')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('train')
    p.add_argument('samples', help='JSONL file with one feature object per line')
    p = sub.add_parser('predict')
    p.add_argument('features', help='JSON feature object, or "-" to read from stdin')
    args = parser.parse_args(argv)

    if args.command == 'train':
        engine = MLEngine()
        with open(args.samples, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if line:
                    engine.add_training_sample(json.loads(line))
        engine.train()
        return 0

    if args.command == 'predict':
        engine = MLEngine()
        if args.features == '-':
            payload = sys.stdin.read()
        else:
            payload = args.features
        features = json.loads(payload)
        label = engine.predict(features)
        print(json.dumps({'anomaly': label == 1}))
        return 0

    return 1


if __name__ == '__main__':
    raise SystemExit(main())