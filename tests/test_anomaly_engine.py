import pytest
from detection.anomaly_engine import AnomalyEngine


class FakeBaseline:
    def __init__(self, stats=None, count_val=100):
        self._stats = stats or {}
        self._count = count_val

    def count(self, initiator_ip, protocol):
        return self._count

    def get(self, initiator_ip, protocol):
        return self._stats


def test_analyze_no_baseline_crash():
    baseline = FakeBaseline(stats={})
    engine = AnomalyEngine(baseline)
    features = {"duration": 1.0, "total_bytes": 100, "total_packets": 10, "byte_ratio": 10}
    res = engine.analyze(features, "1.2.3.4", "TCP")
    assert isinstance(res, dict)
    assert "score" in res and "confidence" in res


def test_analyze_trigger():
    stats = {
        "duration_mean": 1.0, "duration_std": 0.1,
        "total_bytes_mean": 10, "total_bytes_std": 1,
        "total_packets_mean": 1, "total_packets_std": 0.1,
        "byte_ratio_mean": 1, "byte_ratio_std": 0.1,
    }
    baseline = FakeBaseline(stats=stats)
    engine = AnomalyEngine(baseline, z_threshold=2)
    features = {"duration": 10.0, "total_bytes": 1000, "total_packets": 100, "byte_ratio": 100}
    res = engine.analyze(features, "1.2.3.4", "TCP")
    assert res["score"] >= 1
