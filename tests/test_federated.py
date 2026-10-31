"""Federated learning: the maths, update validation, local sampling and a two-site round over mTLS (Phase 7)."""
import os

import numpy as np
import pytest
import requests

from detection import federated as fl
from detection import registry
from detection.samples import SampleStore
from fleet import agent, keys, manage
from fleet.store import FleetStore
from tests.test_fleet import live  # noqa: F401  (live fleet server fixture)

F = [f'f{i}' for i in range(6)]


def normal_rows(n, scale=1.0, seed=0):
    rng = np.random.default_rng(seed)
    x = rng.lognormal(mean=np.linspace(1, 3, 6) * scale, sigma=0.3, size=(n, 6))
    x[:, 1] = x[:, 0] * 2
    return [dict(zip(F, map(float, r))) for r in x]


# ---------- maths ----------

def test_scaler_merge_is_exact():
    rng = np.random.default_rng(3)
    parts = [rng.normal(i, 1 + i, size=(100 * (i + 1), 4)) for i in range(3)]
    merged = fl.merge_scalers([{'mean': p.mean(0).tolist(), 'var': p.var(0).tolist(), 'n': len(p)} for p in parts])
    whole = np.vstack(parts)
    assert np.allclose(merged['mean'], whole.mean(0)) and np.allclose(merged['var'], whole.var(0))
    assert merged['n'] == len(whole)


def test_fedavg_weights_by_samples():
    a = fl.local_update(normal_rows(600, seed=1), None, F)
    b = fl.local_update(normal_rows(1800, seed=2), None, F)
    g = fl.aggregate([a, b], round_id=1)
    expect = 0.25 * np.array(a['coefs'][0]) + 0.75 * np.array(b['coefs'][0])
    assert np.allclose(g['coefs'][0], expect) and g['n_samples'] == 2400 and g['sites'] == 2


def test_updates_are_clipped_around_the_global_model():
    g = fl.aggregate([fl.local_update(normal_rows(600), None, F)], round_id=1)
    u = fl.local_update(normal_rows(600, scale=2.0, seed=5), g, epochs=50, clip=0.5)
    flat = lambda m: np.concatenate([np.ravel(x) for x in m['coefs'] + m['intercepts']])  # noqa: E731
    assert np.linalg.norm(flat(u) - flat(g)) <= 0.5 + 1e-9 and u['base_round'] == 1


def test_a_global_model_scores_and_recalibrates_locally():
    g = fl.aggregate([fl.local_update(normal_rows(800, seed=i), None, F) for i in range(2)], round_id=1)
    rows = normal_rows(800, seed=9)
    m = fl.calibrate(fl.build_model(g), rows)
    assert np.mean([m.score(r) > 1.5 for r in rows]) < 0.01
    odd = dict(rows[0], f1=0.0, f4=rows[0]['f4'] * 50)
    assert m.score(odd) > 1.5


def test_too_few_samples_and_malformed_updates_are_refused():
    with pytest.raises(ValueError, match='at least'):
        fl.local_update(normal_rows(10), None, F)
    good = fl.local_update(normal_rows(600), None, F)
    fl.validate_update(good)
    for bad in (dict(good, coefs=good['coefs'][:-1]), dict(good, features=good['features'] + ['extra']),
                dict(good, threshold=float('nan')), {'n_samples': 900}):
        with pytest.raises(ValueError):
            fl.validate_update(bad)


def test_reservoir_sample_is_capped_and_survives_restarts(tmp_path):
    s = SampleStore(str(tmp_path / 's.db'), capacity=100)
    for i in range(1000):
        s.observe({'f0': i})
    s.close()
    again = SampleStore(str(tmp_path / 's.db'), capacity=100)
    assert again.stats() == {'samples': 100, 'seen': 1000, 'capacity': 100}
    values = sorted(r['f0'] for r in again.rows())
    assert values[-1] > 500                                           # later flows still get in (uniform sample)


def test_pipeline_samples_only_flows_without_findings():
    from detection.pipeline import DetectionPipeline

    class Store:
        rows = []

        def observe(self, f):
            self.rows.append(f)
    pipe = DetectionPipeline(models=False, clock=lambda: 1_800_000_000.0, samples=Store())
    ok = {'ts': 1_800_000_000.0, 'src': '192.168.1.5', 'dst': '192.168.1.9', 'dport': 443, 'proto': 'TCP',
          'duration': 1, 'forward_bytes': 500, 'backward_bytes': 900, 'features': {'f0': 1.0}}
    pipe.observe_flow(dict(ok))                                        # a new device: not sampled yet
    assert pipe.samples.rows == []
    later = 1_800_000_000.0 + 700                                      # past the 10-minute finding window
    pipe.observe_flow(dict(ok, ts=later))
    for port in range(1, 60):                                          # a port scan from another source
        pipe.observe_flow(dict(ok, src='192.168.1.66', dport=port, ts=later + port * 0.1, features={'scan': 1}))
    assert pipe.samples.rows == [{'f0': 1.0}]


# ---------- a live round over mutual TLS ----------

def as_site(monkeypatch, tmp_path, name):
    monkeypatch.setenv('SENTINEL_FLEET_AGENT_DIR', str(tmp_path / name / 'agent'))
    monkeypatch.setenv('SENTINEL_SAMPLES_DB', str(tmp_path / name / 'samples.db'))
    monkeypatch.setenv('SENTINEL_MODEL_REGISTRY', str(tmp_path / name / 'models'))


def test_two_sites_train_together_without_sharing_flows(live, tmp_path, monkeypatch):
    for i, name in enumerate(('north', 'south')):
        as_site(monkeypatch, tmp_path, name)
        agent.enroll(live, manage.enrolment_code()['code'], keys.ca_fingerprint(), name=name)
        s = SampleStore()
        for r in normal_rows(700, scale=1 + 0.1 * i, seed=i):
            s.observe(r)
        s.close()
    rnd = manage.start_round(min_sites=2)

    as_site(monkeypatch, tmp_path, 'north')
    assert agent.report_once()['federated']['submitted_round'] == rnd['id']
    assert FleetStore().latest_global() is None                        # waiting for the second site
    as_site(monkeypatch, tmp_path, 'south')
    state = agent.report_once()
    assert state['federated']['submitted_round'] == rnd['id']
    g = FleetStore().latest_global()
    assert g['round'] == rnd['id'] and g['global']['sites'] == 2 and g['global']['n_samples'] == 1400

    # the server holds parameters and counts only: no flow, no feature vector of any site
    assert all(set(u) == {'format', 'features', 'hidden', 'coefs', 'intercepts', 'scaler', 'n_samples',
                          'threshold', 'base_round'} for u in FleetStore().updates(rnd['id']))

    as_site(monkeypatch, tmp_path, 'north')
    state = agent.report_once()                                        # picks up the global model
    fed = state['federated']
    assert fed['installed_round'] == rnd['id']
    entry = registry.index()['autoencoder']['versions'][str(fed['installed_version'])]
    assert entry['stage'] == 'shadow' and entry['metrics']['federated_round'] == rnd['id']
    assert entry['metrics']['threshold_from'] == 'local traffic'
    model, meta = registry.load('autoencoder', fed['installed_version'])   # signed and loadable
    assert meta['notes'] == f"federated round {rnd['id']}" and model.score(normal_rows(1)[0]) < 5


def test_the_server_refuses_closed_rounds_and_bad_updates(live, tmp_path, monkeypatch):
    as_site(monkeypatch, tmp_path, 'east')
    agent.enroll(live, manage.enrolment_code()['code'], keys.ca_fingerprint(), name='east')
    d = agent.agent_dir()
    session = requests.Session()
    session.cert = (os.path.join(d, 'site.pem'), os.path.join(d, 'site.key'))
    session.verify = os.path.join(d, 'ca.pem')
    good = fl.local_update(normal_rows(600), None, F)
    assert session.post(f'{live}/v1/federated/update', json={'round': 99, 'update': good}, timeout=5).status_code == 409
    rnd = manage.start_round(min_sites=5)
    bad = dict(good, coefs=good['coefs'][:-1])
    r = session.post(f'{live}/v1/federated/update', json={'round': rnd['id'], 'update': bad}, timeout=5)
    assert r.status_code == 400
    small = dict(good, n_samples=10)
    assert session.post(f'{live}/v1/federated/update', json={'round': rnd['id'], 'update': small}, timeout=5).status_code == 400
    ok = session.post(f'{live}/v1/federated/update', json={'round': rnd['id'], 'update': good}, timeout=5).json()
    assert ok == {'accepted': True, 'aggregated': False, 'waiting_for': 4}
    with pytest.raises(ValueError, match='already open'):
        manage.start_round()
