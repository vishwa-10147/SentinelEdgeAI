"""Fast single-sample scoring for a fitted scikit-learn IsolationForest.

sklearn's predict() dispatches every call through joblib across all trees,
which costs ~15 ms for one sample on a Raspberry Pi 5. The engine scores one
flow at a time, so this compiles the fitted forest into flat arrays once and
walks the trees directly, giving the same scores (float32 comparisons, the
same path-length correction) in a fraction of the time.

Construction cross-checks against sklearn on random samples; callers fall
back to sklearn if the check fails (e.g. an unexpected sklearn version).
"""
import numpy as np


def _average_path_length(n):
    """c(n): average path length of an unsuccessful BST search (sklearn's definition)."""
    n = np.asarray(n, dtype=float)
    out = np.zeros_like(n)
    small = n <= 1
    two = n == 2
    big = ~(small | two)
    out[two] = 1.0
    out[big] = 2.0 * (np.log(n[big] - 1.0) + np.euler_gamma) - 2.0 * (n[big] - 1.0) / n[big]
    return out


class FastIsolationForest:
    def __init__(self, model, check_samples=200, seed=0):
        self.trees = []
        for idx, (est, feats) in enumerate(zip(model.estimators_, model.estimators_features_)):
            t = est.tree_
            if hasattr(model, '_decision_path_lengths') and hasattr(model, '_average_path_length_per_tree'):
                leaf_value = (np.asarray(model._decision_path_lengths[idx], dtype=float)
                              + np.asarray(model._average_path_length_per_tree[idx], dtype=float) - 1.0)
            else:
                depth = np.zeros(t.node_count)
                for node in range(t.node_count):
                    for child in (t.children_left[node], t.children_right[node]):
                        if child != -1:
                            depth[child] = depth[node] + 1
                leaf_value = depth + _average_path_length(t.n_node_samples)
            self.trees.append((t.children_left.tolist(), t.children_right.tolist(), t.feature.tolist(),
                               t.threshold.astype(np.float32).tolist(), np.asarray(feats).tolist(),
                               leaf_value.tolist()))
        self.denominator = len(model.estimators_) * float(_average_path_length([model._max_samples])[0])
        self.offset = float(model.offset_)
        self._check(model, check_samples, seed)

    def score_samples(self, x):
        """Same as sklearn's score_samples() for one sample (higher = more normal)."""
        x32 = np.asarray(x, dtype=np.float32).tolist()
        depth = 0.0
        for left, right, feature, threshold, feats, leaf_value in self.trees:
            node = 0
            while left[node] != -1:
                node = left[node] if x32[feats[feature[node]]] <= threshold[node] else right[node]
            depth += leaf_value[node]
        return -(2.0 ** (-depth / self.denominator))

    def decision_function(self, x):
        return self.score_samples(x) - self.offset

    def predict_one(self, x):
        """-1 anomaly, 1 normal (sklearn convention)."""
        return -1 if self.decision_function(x) < 0 else 1

    def _check(self, model, n, seed):
        n_features = model.n_features_in_
        rng = np.random.default_rng(seed)
        X = np.vstack([rng.normal(0, 1, (n // 2, n_features)),
                       rng.lognormal(3, 2, (n - n // 2, n_features))]).astype(np.float32)
        expected = model.score_samples(X)
        got = np.array([self.score_samples(row) for row in X])
        if not np.allclose(expected, got, rtol=1e-9, atol=1e-12):
            raise ValueError(f'fast scorer disagrees with sklearn (max diff {np.max(np.abs(expected - got)):.3g})')
