"""Risk fusion, confirmation and explanation (Phase 4).

Combines the engine's score (baselines + Isolation Forest) with the findings
of the attack-specific detectors for the same source:

  risk        = strongest signal, +5 per additional distinct finding (max 100)
  confidence  = noisy-OR of the calibrated probabilities of the signals
  confirmed   = may trigger automatic enforcement: confidence >= 0.8 and either
                two independent signals, a finding repeated in two windows, or
                one finding whose calibrated precision is >= 0.9

Each result carries an explanation: the evidence of every finding plus the
flow features furthest from this protocol's baseline for this hour of day.
"""
import math
import time
from collections import defaultdict, deque

from common.bounded import BoundedDict
from detection.detectors import MAX_SOURCES

CONFIRM_CONFIDENCE = 0.8
RECENT_SECONDS = 600


class SeasonalBaseline:
    """Running mean/variance per (protocol, hour of day, feature) — Welford's method."""

    def __init__(self, warmup=50):
        self.stats = defaultdict(lambda: [0, 0.0, 0.0])   # n, mean, M2
        self.warmup = warmup

    def update(self, proto, hour, features):
        for name, value in features.items():
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                continue
            s = self.stats[(proto, hour, name)]
            s[0] += 1
            delta = value - s[1]
            s[1] += delta / s[0]
            s[2] += delta * (value - s[1])

    def zscores(self, proto, hour, features):
        out = {}
        for name, value in features.items():
            s = self.stats.get((proto, hour, name))
            if not s or s[0] < self.warmup or not isinstance(value, (int, float)):
                continue
            std = math.sqrt(s[2] / (s[0] - 1)) if s[0] > 1 else 0.0
            if std > 1e-9:
                out[name] = (value - s[1]) / std
        return out


class Fusion:
    def __init__(self, clock=time.time, calibrate=None):
        self.recent = BoundedDict(MAX_SOURCES, deque)   # src -> findings
        self.baseline = SeasonalBaseline()
        self.clock = clock
        # calibrate(kind, prior) -> probability, e.g. from analyst feedback
        self.calibrate = calibrate or (lambda kind, prior: prior)

    def add_findings(self, findings):
        for f in findings:
            q = self.recent[f.src]
            q.append(f)
            while q and q[0].ts < f.ts - RECENT_SECONDS:
                q.popleft()

    def recent_for(self, src, now=None):
        now = now or self.clock()
        return [f for f in self.recent.get(src, ()) if f.ts >= now - RECENT_SECONDS]

    def fuse(self, src, engine_risk=0, engine_confidence=0.0, proto=None, features=None, now=None):
        now = now or self.clock()
        findings = self.recent_for(src, now)
        hour = time.localtime(now).tm_hour
        z = self.baseline.zscores(proto, hour, features or {}) if proto else {}
        if proto and features:
            self.baseline.update(proto, hour, features)

        signals = []
        if engine_risk:
            # the engine's own confidence is not calibrated: count it at half weight
            signals.append(('engine', min(0.95, max(0.0, engine_confidence) * 0.5 + engine_risk / 400)))
        kinds = {}
        for f in findings:
            kinds.setdefault(f.kind, []).append(f)
        for kind, fs in kinds.items():
            signals.append((kind, self.calibrate(kind, max(x.probability for x in fs))))

        strongest = max([engine_risk] + [f.severity for f in findings]) if (findings or engine_risk) else 0
        risk = min(100, strongest + 5 * max(0, len(kinds) - 1))
        confidence = 1 - math.prod(1 - p for _, p in signals) if signals else 0.0
        independent = len({k for k, _ in signals})
        repeated = any(len(fs) >= 2 for fs in kinds.values())
        precise = any(self.calibrate(f.kind, f.probability) >= 0.9 for f in findings)
        confirmed = confidence >= CONFIRM_CONFIDENCE and (independent >= 2 or repeated or precise)

        top = sorted(z.items(), key=lambda kv: -abs(kv[1]))[:3]
        explanation = [f.evidence for f in sorted(findings, key=lambda x: -x.severity)]
        explanation += [f'{name} is {abs(v):.1f} standard deviations {"above" if v > 0 else "below"} the '
                        f'{proto} baseline for this hour' for name, v in top if abs(v) >= 3]
        lead = max(findings, key=lambda x: x.severity) if findings else None
        return {
            'risk': int(risk),
            'confidence': round(confidence, 3),
            'confirmed': bool(confirmed),
            'attack_type': lead.kind if lead else None,
            'technique': lead.technique if lead else None,
            'findings': [f.as_dict() for f in findings],
            'explanation': explanation,
            'top_features': [{'feature': n, 'zscore': round(v, 2)} for n, v in top],
        }


def alert_explanation(fused):
    """This flow's own evidence first; findings from earlier flows of the source are labelled as such."""
    if not fused:
        return []
    new = {(f['kind'], f['evidence']) for f in fused.get('new_findings', [])}
    out = [f['evidence'] for f in fused.get('findings', []) if (f['kind'], f['evidence']) in new]
    out += [e for e in fused.get('explanation', []) if 'standard deviations' in e]
    out += [f"earlier finding for this source: {f['evidence']}"
            for f in fused.get('findings', []) if (f['kind'], f['evidence']) not in new][:2]
    return out
