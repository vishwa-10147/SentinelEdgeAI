import numpy as np
from detection.adaptive_baseline import AdaptiveBaseline


def test_adaptive_baseline_keys():
    ab = AdaptiveBaseline(window_size=10)
    # feed >=10 samples so stats are computed
    for i in range(12):
        features = {
            "duration": float(i + 1),
            "total_bytes": float(100 * (i + 1)),
            "total_packets": float(1 + i),
            "byte_ratio": float(100),
        }
        ab.update(features, "1.2.3.4", "TCP")
    stats = ab.get("1.2.3.4", "TCP")
    assert stats is not None
    # compatibility keys
    assert "bytes_mean" in stats
    assert "total_bytes_mean" in stats
    assert "packets_mean" in stats
    assert "total_packets_mean" in stats
