#!/usr/bin/env python3
"""Create a synthetic alert and update dashboard JSON files for local testing."""
import time
import json
import os
from utils.alert_logger import AlertLogger


def write_json(path, data):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def load_json(path, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def main():
    now = int(time.time())

    # Synthetic alert
    alert = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()),
        "initiator_ip": "192.0.2.55",
        "responder_ip": "198.51.100.10",
        "protocol": "TCP",
        "final_risk_score": 65,
        "severity": "HIGH",
        "attack_type": "POSSIBLE_PORT_SCAN",
        "drift": False,
        "mitre_tactic": "Reconnaissance",
        "mitre_technique_id": "T1046",
        "mitre_technique_name": "Network Service Discovery"
    }

    # Append alert via AlertLogger to keep format consistent
    logger = AlertLogger()
    logger.log(alert)

    # Update live_stats.json
    live = load_json("live_stats.json", {})
    live.setdefault("total_flows", 0)
    live.setdefault("unique_ips", [])
    live.setdefault("flow_history", [])
    live["total_flows"] += 1
    if alert["initiator_ip"] not in live["unique_ips"]:
        live["unique_ips"].append(alert["initiator_ip"])
    live["flow_history"].append({"timestamp": now, "score": alert["final_risk_score"]})
    # Trim to last 200 entries
    live["flow_history"] = live["flow_history"][-200:]
    write_json("live_stats.json", live)

    # Update risk_timeline.json
    timeline = load_json("risk_timeline.json", {})
    ip = alert["initiator_ip"]
    timeline.setdefault(ip, [])
    timeline[ip].append({"timestamp": now, "risk": alert["final_risk_score"]})
    timeline[ip] = timeline[ip][-200:]
    write_json("risk_timeline.json", timeline)

    print("Test alert written. alerts.json, live_stats.json, risk_timeline.json updated.")


if __name__ == "__main__":
    main()
