"""Federated learning for the flow autoencoder: sites share model updates, never data (Phase 7).

One round:
  1. the fleet server opens a round and hands every site the current global model (or none)
  2. each site trains locally on its own sample of normal flows (detection.samples), starting
     from the global model, and sends back only an *update*: network weights, input-scaler
     statistics and sample counts
  3. the server combines the updates: weights by FedAvg (weighted by samples), scaler
     statistics by the exact parallel mean/variance merge
  4. each site rebuilds the new global model, recalibrates the alert threshold on its own
     normal traffic and registers it as a *shadow* model: scored, never acted on, until an
     Admin promotes it

Before an update leaves a site, its change from the global model is clipped to an L2 norm
(`clip`) and, optionally, Gaussian noise (`noise`, relative to `clip`) is added, which bounds
how much any one site's traffic can shape the global model.
"""
import numpy as np

from detection.autoencoder import FlowAutoencoder

HIDDEN = (16, 6, 16)
MIN_SAMPLES = 500
FORMAT = 1


def _scaler_stats(scaler):
    return {'mean': scaler.mean_.tolist(), 'var': scaler.var_.tolist(), 'n': int(scaler.n_samples_seen_)}


def _weights(ae):
    mlp = ae.model[1]
    return [w.tolist() for w in mlp.coefs_], [b.tolist() for b in mlp.intercepts_]


def build_model(global_model):
    """A FlowAutoencoder carrying the given weights and scaler (threshold left to the caller)."""
    feats = global_model['features']
    ae = FlowAutoencoder(feats, hidden=tuple(global_model['hidden']))
    scaler, mlp = ae.model[0], ae.model[1]
    # fit on a tiny matrix so scikit-learn sets up every attribute, then put the real values in
    x = np.zeros((4, len(feats)))
    x[1:] = np.eye(3, len(feats))
    scaler.fit(x)
    mlp.set_params(max_iter=1, early_stopping=False)
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter('ignore')
        mlp.fit(scaler.transform(x), scaler.transform(x))
    s = global_model['scaler']
    scaler.mean_ = np.array(s['mean'], dtype=float)
    scaler.var_ = np.array(s['var'], dtype=float)
    scaler.scale_ = np.sqrt(np.where(scaler.var_ > 0, scaler.var_, 1.0))
    scaler.n_samples_seen_ = int(s['n'])
    mlp.coefs_ = [np.array(w, dtype=float) for w in global_model['coefs']]
    mlp.intercepts_ = [np.array(b, dtype=float) for b in global_model['intercepts']]
    ae.threshold = global_model.get('threshold')
    return ae


def calibrate(ae, rows, percentile=99.5):
    """Set the alert threshold from this site's own normal traffic."""
    ae.threshold = float(np.percentile(ae._errors(ae._matrix(rows)), percentile))
    return ae


def local_update(rows, global_model=None, features=None, epochs=20, clip=10.0, noise=0.0, seed=0):
    """Train on this site's rows; return the update to send (no rows, only parameters and counts)."""
    if len(rows) < MIN_SAMPLES:
        raise ValueError(f'need at least {MIN_SAMPLES} normal flows to train, have {len(rows)}')
    rng = np.random.default_rng(seed)
    if global_model:
        ae = build_model(global_model)
        x = ae._matrix(rows)
        xs = ae.model[0].transform(x)                    # the shared normalisation, so weights stay comparable
        mlp = ae.model[1]
        mlp.set_params(warm_start=True, early_stopping=False)
        for _ in range(epochs):
            mlp.partial_fit(xs, xs)
        local_scaler = {'mean': x.mean(axis=0).tolist(), 'var': x.var(axis=0).tolist(), 'n': len(rows)}
    else:
        names = features or sorted({k for r in rows for k in r})
        ae = FlowAutoencoder(names, hidden=HIDDEN, seed=seed).fit(rows)
        local_scaler = _scaler_stats(ae.model[0])
    coefs, intercepts = _weights(ae)
    if global_model:
        flat_new = np.concatenate([np.ravel(a) for a in coefs + intercepts])
        flat_old = np.concatenate([np.ravel(a) for a in global_model['coefs'] + global_model['intercepts']])
        delta = flat_new - flat_old
        norm = float(np.linalg.norm(delta))
        if norm > clip:
            delta *= clip / norm
        if noise:
            delta += rng.normal(0, noise * clip, size=delta.shape)
        flat = flat_old + delta
        shapes = [np.shape(a) for a in coefs + intercepts]
        parts, i = [], 0
        for sh in shapes:
            size = int(np.prod(sh))
            parts.append(flat[i:i + size].reshape(sh).tolist())
            i += size
        coefs, intercepts = parts[:len(coefs)], parts[len(coefs):]
    errors = ae._errors(ae._matrix(rows))
    return {'format': FORMAT, 'features': ae.features, 'hidden': list(global_model['hidden'] if global_model else HIDDEN),
            'coefs': coefs, 'intercepts': intercepts, 'scaler': local_scaler, 'n_samples': len(rows),
            'threshold': float(np.percentile(errors, 99.5)), 'base_round': (global_model or {}).get('round')}


def validate_update(u):
    """Raise ValueError unless `u` is a well-formed update: layer shapes, scaler lengths, finite numbers."""
    try:
        n = len(u['features'])
        dims = [n, *u['hidden'], n]
        if len(u['coefs']) != len(dims) - 1 or len(u['intercepts']) != len(dims) - 1:
            raise ValueError('wrong number of layers')
        for i, (w, b) in enumerate(zip(u['coefs'], u['intercepts'])):
            w, b = np.asarray(w, dtype=float), np.asarray(b, dtype=float)
            if w.shape != (dims[i], dims[i + 1]) or b.shape != (dims[i + 1],):
                raise ValueError(f'layer {i} has shape {w.shape}, expected {(dims[i], dims[i + 1])}')
            if not (np.isfinite(w).all() and np.isfinite(b).all()):
                raise ValueError('weights must be finite numbers')
        for key in ('mean', 'var'):
            v = np.asarray(u['scaler'][key], dtype=float)
            if v.shape != (n,) or not np.isfinite(v).all():
                raise ValueError(f'scaler {key} must be {n} finite numbers')
        if not (np.isfinite(float(u['threshold'])) and int(u['scaler']['n']) > 0):
            raise ValueError('bad threshold or sample count')
    except (KeyError, TypeError) as exc:
        raise ValueError(f'malformed update ({exc})')


def _compatible(updates):
    first = updates[0]
    for u in updates[1:]:
        if u['features'] != first['features'] or u['hidden'] != first['hidden'] or u.get('format') != FORMAT:
            raise ValueError('updates were trained on different features or network shapes')


def merge_scalers(stats):
    """Exact mean and variance of the union of the sites' data (Chan et al.)."""
    n = sum(s['n'] for s in stats)
    mean = sum(np.array(s['mean']) * s['n'] for s in stats) / n
    m2 = sum((np.array(s['var']) + (np.array(s['mean']) - mean) ** 2) * s['n'] for s in stats)
    return {'mean': mean.tolist(), 'var': (m2 / n).tolist(), 'n': int(n)}


def aggregate(updates, round_id=None, previous=None):
    """FedAvg of the sites' updates -> the new global model."""
    if not updates:
        raise ValueError('no updates to aggregate')
    _compatible(updates)
    total = sum(u['n_samples'] for u in updates)
    w = [u['n_samples'] / total for u in updates]

    def avg(key):
        return [sum(wi * np.array(u[key][layer]) for wi, u in zip(w, updates)).tolist()
                for layer in range(len(updates[0][key]))]
    scaler = merge_scalers([u['scaler'] for u in updates])
    if previous:                                          # the network was trained on the previous scaler
        scaler = previous['scaler'] if all(u.get('base_round') == previous.get('round') for u in updates) else scaler
    return {'format': FORMAT, 'round': round_id, 'features': updates[0]['features'], 'hidden': updates[0]['hidden'],
            'coefs': avg('coefs'), 'intercepts': avg('intercepts'), 'scaler': scaler,
            'threshold': float(sum(wi * u['threshold'] for wi, u in zip(w, updates))),
            'sites': len(updates), 'n_samples': int(total)}
