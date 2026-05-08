from core.product_intelligence import (
    build_incident_timeline,
    build_security_report,
    explain_alert,
    infer_device_type,
)


def test_infer_device_type_from_profile_ports():
    profile = {
        "flow_count": 10,
        "destination_port_counts": {"53": 5, "123": 4, "1883": 2},
    }

    assert infer_device_type("192.168.1.44", profile) == "iot"


def test_explain_port_scan_alert():
    explanation = explain_alert({
        "attack_type": "POSSIBLE_PORT_SCAN",
        "final_risk_score": 80,
    })

    assert "reconnaissance" in explanation["summary"]
    assert explanation["recommended_action"].startswith("Review")


def test_incident_timeline_orders_flows_alerts_and_actions():
    timeline = build_incident_timeline(
        alerts=[{"logged_at": 3, "attack_type": "POSSIBLE_PORT_SCAN", "final_risk_score": 80, "initiator_ip": "1.1.1.1"}],
        flows=[{"timestamp": 1, "risk": 0, "src": "1.1.1.1", "dst": "2.2.2.2"}],
        actions=[{"ts": 4, "action": "block", "ip": "1.1.1.1"}],
    )

    assert [event["label"] for event in timeline] == ["Normal traffic", "POSSIBLE_PORT_SCAN", "Block applied"]


def test_security_report_contains_summary_and_explanations():
    report = build_security_report(
        alerts=[{"attack_type": "TRAFFIC_FLOOD", "final_risk_score": 90}],
        timeline=[],
        firewall_actions=[{"action": "block"}],
        profiles={"192.168.1.10": {}},
    )

    assert report["summary"]["critical_alerts"] == 1
    assert report["summary"]["actions_taken"] == 1
    assert report["alerts"][0]["explanation"]["summary"]
