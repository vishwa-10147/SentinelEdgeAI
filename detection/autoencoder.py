"""Flow autoencoder: learns what normal flows look like; large reconstruction error = anomaly.

Runs on CPU with scikit-learn (an MLP trained to reproduce its input). The
GPU/TensorRT build for the Jetson exports the same network; until a Jetson
is available this is the reference implementation.

    python -m detection.autoencoder train flows.jsonl [--feedback]   # registers a new shadow version
"""
import argparse
import json
import sys

import numpy as np
from sklearn.neural_network import MLPRegressor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from detection import registry
from detection.detectors import Finding

NAME = 'autoencoder'


class FlowAutoencoder:
    def __init__(self, features, hidden=(16, 6, 16), seed=0):
        self.features = list(features)
        self.model = make_pipeline(StandardScaler(),
                                   MLPRegressor(hidden_layer_sizes=hidden, max_iter=300, random_state=seed,
                                                early_stopping=True))
        self.threshold = None

    def _matrix(self, rows):
        x = np.array([[float(r.get(f, 0) or 0) for f in self.features] for r in rows], dtype=float)
        return np.log1p(np.clip(x, 0, None))      # flow features are heavy-tailed

    def fit(self, rows, percentile=99.5):
        x = self._matrix(rows)
        self.model.fit(x, x)
        err = self._errors(x)
        self.threshold = float(np.percentile(err, percentile))
        return self

    def _errors(self, x):
        scaled = self.model[0].transform(x)
        recon = self.model[1].predict(scaled)
        return np.mean((scaled - recon) ** 2, axis=1)

    def score(self, row):
        """Reconstruction error relative to the threshold (>1 = beyond 99.5% of normal)."""
        return float(self._errors(self._matrix([row]))[0] / max(self.threshold, 1e-9))


def finding_for(record, model, stage='active'):
    feats = record.get('features') or {}
    if not feats:
        return None
    ratio = model.score(feats)
    if ratio < 1.5:
        return None
    severity = int(min(75, 45 + 10 * ratio))
    return Finding('autoencoder_anomaly', record['src'], severity, 0.5, 'T1205',
                   f'flow unlike normal traffic (reconstruction error {ratio:.1f}x the normal limit)',
                   {'ratio': round(ratio, 2), 'stage': stage, 'target': record.get('dst')}, ts=record.get('ts'))


def train_from_jsonl(path, feature_names=None):
    rows = []
    with open(path) as f:
        for line in f:
            rec = json.loads(line)
            if rec.get('features'):
                rows.append(rec['features'])
    if len(rows) < 200:
        raise ValueError(f'need at least 200 flows with features, got {len(rows)}')
    names = feature_names or sorted({k for r in rows for k in r})
    ae = FlowAutoencoder(names).fit(rows)
    return ae, {'training_flows': len(rows), 'threshold': round(ae.threshold, 5)}


def main(argv=None):
    parser = argparse.ArgumentParser(prog='python -m detection.autoencoder')
    sub = parser.add_subparsers(dest='command', required=True)
    p = sub.add_parser('train')
    p.add_argument('jsonl', help='flow records with features, one JSON per line')
    args = parser.parse_args(argv)
    try:
        ae, metrics = train_from_jsonl(args.jsonl)
    except (OSError, ValueError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    version = registry.register(NAME, ae, metrics, ae.features)
    print(f'registered {NAME} v{version} in shadow mode: {metrics}')
    print(f'promote with: python -m detection.registry stage {NAME} {version} canary  (then promote)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
