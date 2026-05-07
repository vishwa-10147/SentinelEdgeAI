import numpy as np
from detection.adaptive_baseline import AdaptiveBaseline


def test_adaptive_baseline_keys():
    ab = AdaptiveBaseline()
    durations = [1, 2, 3]
    bytes_ = [100, 200, 300]
    packets = [1, 2, 3]
    ratios = [100, 100, 100]
    ab._compute_stats_for_key(("1.2.3.4", "TCP"), durations, bytes_, packets, ratios)
    stats = ab.stats.get(("1.2.3.4", "TCP"))
    assert stats is not None
    # compatibility keys
    assert "bytes_mean" in stats
    assert "total_bytes_mean" in stats
    assert "packets_mean" in stats
    assert "total_packets_mean" in stats
