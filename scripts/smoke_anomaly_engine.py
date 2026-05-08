"""Smoke test for AnomalyEngine baseline handling.

Runs AnomalyEngine.analyze() with:
 - a baseline missing metric keys (should not raise)
 - a baseline with proper keys (should return score/confidence structure)

Exit code 0 indicates pass.
"""
import sys
import logging
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

from detection.anomaly_engine import AnomalyEngine

class FakeBaseline:
    def __init__(self, stats=None, count_val=100):
        self._stats = stats or {}
        self._count = count_val

    def count(self, initiator_ip, protocol):
        return self._count

    def get(self, initiator_ip, protocol):
        return self._stats


def run():
    logging.basicConfig(level=logging.DEBUG)

    # 1) Baseline missing keys -> engine should skip and return structure
    baseline1 = FakeBaseline(stats={})
    engine1 = AnomalyEngine(baseline1)
    features = {"duration": 1.0, "total_bytes": 100, "total_packets": 10, "byte_ratio": 10}
    try:
        res1 = engine1.analyze(features, "1.2.3.4", "TCP")
    except Exception as e:
        print("FAIL: exception raised for missing baseline keys:", e)
        return 2
    if not isinstance(res1, dict) or "score" not in res1:
        print("FAIL: unexpected result structure for missing baseline keys", res1)
        return 3

    # 2) Baseline with expected keys -> compute normally
    stats = {
        "duration_mean": 1.0, "duration_std": 0.1,
        "total_bytes_mean": 50, "total_bytes_std": 10,
        "total_packets_mean": 5, "total_packets_std": 1,
        "byte_ratio_mean": 10, "byte_ratio_std": 2,
    }
    baseline2 = FakeBaseline(stats=stats)
    engine2 = AnomalyEngine(baseline2)
    res2 = engine2.analyze(features, "1.2.3.4", "TCP")
    if not isinstance(res2, dict) or "score" not in res2:
        print("FAIL: unexpected result structure for full baseline", res2)
        return 4

    print("SMOKE: PASS")
    return 0

if __name__ == '__main__':
    sys.exit(run())
