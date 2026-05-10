from datetime import UTC, datetime

from detection.behavioral_fingerprint import BehavioralFingerprint
from flow.flow_record import FlowRecord


def make_flow(dst="10.0.0.2", dst_port=443, packets=10, duration=1.0):
    now = datetime.now(UTC)
    return FlowRecord(
        initiator_ip="192.168.1.10",
        initiator_port=51514,
        responder_ip=dst,
        responder_port=dst_port,
        protocol="TCP",
        start_time=now,
        end_time=now,
        duration=duration,
        forward_bytes=1000,
        backward_bytes=500,
        forward_packets=packets,
        backward_packets=0,
        flow_state="IDLE_TIMEOUT",
    )


def test_behavior_deviation_tracks_packet_rate_destination_and_port():
    fingerprint = BehavioralFingerprint(drift_threshold=0.5)

    for index in range(30):
        fingerprint.update(
            make_flow(dst=f"10.0.0.{2 + (index % 3)}", dst_port=443 + (index % 3)),
            threat_score=0,
        )

    result = fingerprint.detect_deviation(
        make_flow(dst="203.0.113.8", dst_port=8443, packets=120, duration=1.0)
    )

    assert result["score"] == 3
    assert "PACKET_RATE_DEVIATION" in result["reasons"]
    assert "UNUSUAL_DESTINATION" in result["reasons"]
    assert "UNUSUAL_DESTINATION_PORT" in result["reasons"]


def test_profiles_include_behavior_summary():
    fingerprint = BehavioralFingerprint()
    fingerprint.update(make_flow(dst="10.0.0.2", dst_port=53), threat_score=1)

    profiles = fingerprint.get_all_profiles()

    assert profiles["192.168.1.10"]["avg_packets_per_sec"] > 0
    assert profiles["192.168.1.10"]["common_ports"][0]["value"] == "53"
    assert profiles["192.168.1.10"]["typical_destinations"][0]["value"] == "10.0.0.2"
