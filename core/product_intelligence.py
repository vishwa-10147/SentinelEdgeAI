from datetime import datetime, timezone


IOT_PORTS = {53, 67, 68, 80, 123, 1883, 5353, 5683, 8883}
SERVER_PORTS = {22, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3306, 5432, 6379, 8080}
ADMIN_PORTS = {22, 3389, 5900}


def infer_device_type(ip, profile=None):
    profile = profile or {}
    # The check for loopback and unspecified addresses is application-level
    # classification, not a server bind. Mark as intentional for static analysis.
    # nosec: B104
    if profile.get("type"):
        return profile["type"]
    if ip in {"0.0.0.0", "127.0.0.1"}:
        return "sensor"
    if str(ip).endswith(".1"):
        return "gateway"
    ports = _port_set(profile.get("destination_port_counts", {}))
    if len(ports & SERVER_PORTS) >= 3:
        return "server"
    if ports and ports.issubset(IOT_PORTS) and profile.get("flow_count", 0) >= 5:
        return "iot"
    if ports & ADMIN_PORTS:
        return "laptop"
    if not str(ip).startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.2", "172.30.", "172.31.", "192.168.")):
        return "external"
    return "laptop"


def behavior_summary(profile=None):
    profile = profile or {}
    avg_pps = round(float(profile.get("avg_packets_per_sec") or 0), 2)
    baseline_bytes = round(float(profile.get("baseline_avg_bytes") or 0), 2)
    current_avg_bytes = 0
    if profile.get("flow_count"):
        current_avg_bytes = round(float(profile.get("total_bytes") or 0) / max(1, profile["flow_count"]), 2)
    common_ports = _top_values(profile.get("destination_port_counts", {}), limit=5)
    destinations = _top_values(profile.get("destination_counts", {}), limit=5)
    return {
        "avg_packets_per_sec": avg_pps,
        "baseline_avg_bytes": baseline_bytes,
        "current_avg_bytes": current_avg_bytes,
        "common_ports": common_ports,
        "typical_destinations": destinations,
        "comparison": _compare_behavior(current_avg_bytes, baseline_bytes, avg_pps),
    }


def explain_alert(alert):
    attack = (alert.get("attack_type") or alert.get("type") or alert.get("reason") or "GENERIC_ANOMALY").upper()
    risk = int(alert.get("final_risk_score") or alert.get("risk_score") or alert.get("risk") or 0)
    reasons = []

    if "PORT_SCAN" in attack or "SCAN" in attack:
        summary = "Device is contacting sensitive or varied service ports rapidly, which indicates possible reconnaissance."
        reasons.append("Port scan pattern")
    elif "EXFILTRATION" in attack:
        summary = "Device is sending much more data than it receives, which can indicate data exfiltration."
        reasons.append("Outbound byte imbalance")
    elif "FLOOD" in attack or "DDOS" in attack:
        summary = "Device generated a high packet volume burst, which can indicate flooding or denial-of-service behavior."
        reasons.append("High packet volume")
    elif "LONG" in attack:
        summary = "Device maintained an unusually long session compared with expected behavior."
        reasons.append("Long session duration")
    elif alert.get("drift") or alert.get("behavior_score"):
        summary = "Device behavior diverged from its learned profile."
        reasons.append("Behavior profile deviation")
    else:
        summary = "Flow metrics exceeded the learned baseline and should be reviewed."
        reasons.append("Statistical anomaly")

    if risk >= 75:
        action = "Review immediately and keep the block if business traffic is not affected."
    elif risk >= 50:
        action = "Investigate the device and consider a temporary block."
    elif risk >= 25:
        action = "Monitor for repeated alerts from this device."
    else:
        action = "No immediate action required."

    return {
        "summary": summary,
        "reasons": reasons,
        "recommended_action": action,
    }


def build_incident_timeline(alerts=None, flows=None, actions=None, limit=100):
    events = []
    for flow in flows or []:
        risk = int(flow.get("risk") or flow.get("final_risk_score") or 0)
        if risk <= 0:
            label = "Normal traffic"
        elif risk >= 75:
            label = "Risk spike"
        else:
            label = "Suspicious flow"
        events.append(_event(flow.get("timestamp"), "flow", label, flow, risk=risk))

    for alert in alerts or []:
        explanation = explain_alert(alert)
        risk = int(alert.get("final_risk_score") or alert.get("risk_score") or alert.get("risk") or 0)
        events.append(_event(
            alert.get("logged_at") or alert.get("timestamp") or alert.get("ts"),
            "alert",
            alert.get("attack_type") or alert.get("type") or "Alert generated",
            {**alert, "explanation": explanation},
            risk=risk,
        ))

    for action in actions or []:
        label = "Block applied" if action.get("action") == "block" else action.get("action", "Firewall action")
        events.append(_event(action.get("ts") or action.get("timestamp"), "firewall", label, action))

    events.sort(key=lambda item: item["sort_ts"])
    return [{k: v for k, v in item.items() if k != "sort_ts"} for item in events[-limit:]]


def build_security_report(alerts=None, timeline=None, firewall_actions=None, profiles=None):
    alerts = alerts or []
    timeline = timeline or []
    firewall_actions = firewall_actions or []
    profiles = profiles or {}
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "alerts": len(alerts),
            "critical_alerts": sum(1 for alert in alerts if _risk(alert) >= 75),
            "high_alerts": sum(1 for alert in alerts if 50 <= _risk(alert) < 75),
            "actions_taken": len(firewall_actions),
            "devices": len(profiles),
        },
        "alerts": [
            {
                **alert,
                "explanation": explain_alert(alert),
            }
            for alert in alerts
        ],
        "mitre": [
            {
                "technique_id": alert.get("mitre_technique_id"),
                "technique_name": alert.get("mitre_technique_name"),
                "tactic": alert.get("mitre_tactic"),
                "src": alert.get("initiator_ip") or alert.get("src_ip") or alert.get("src"),
            }
            for alert in alerts
            if alert.get("mitre_technique_id")
        ],
        "actions_taken": firewall_actions,
        "incident_timeline": timeline,
    }


def _risk(alert):
    return int(alert.get("final_risk_score") or alert.get("risk_score") or alert.get("risk") or 0)


def _port_set(counts):
    ports = set()
    for value in counts.keys() if isinstance(counts, dict) else []:
        try:
            ports.add(int(value))
        except (TypeError, ValueError):
            continue
    return ports


def _top_values(counts, limit=5):
    if isinstance(counts, list):
        return counts[:limit]
    return [
        {"value": value, "count": count}
        for value, count in sorted((counts or {}).items(), key=lambda item: item[1], reverse=True)[:limit]
    ]


def _compare_behavior(current_avg_bytes, baseline_avg_bytes, avg_pps):
    if baseline_avg_bytes and current_avg_bytes > baseline_avg_bytes * 1.5:
        return "Current traffic is above normal byte volume."
    if baseline_avg_bytes and current_avg_bytes < baseline_avg_bytes * 0.5:
        return "Current traffic is below normal byte volume."
    if avg_pps > 100:
        return "Current packet rate is elevated."
    return "Current behavior is close to the learned baseline."


def _event(timestamp, event_type, label, payload, risk=0):
    sort_ts = _parse_ts(timestamp)
    return {
        "timestamp": datetime.fromtimestamp(sort_ts, tz=timezone.utc).isoformat(),
        "type": event_type,
        "label": label,
        "risk": risk,
        "src": payload.get("initiator_ip") or payload.get("src_ip") or payload.get("src") or payload.get("ip"),
        "dst": payload.get("responder_ip") or payload.get("dst_ip") or payload.get("dst"),
        "details": payload,
        "sort_ts": sort_ts,
    }


def _parse_ts(value):
    if value is None:
        return datetime.now(timezone.utc).timestamp()
    if isinstance(value, (int, float)):
        return float(value)
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00")).timestamp()
    except ValueError:
        try:
            return float(value)
        except (TypeError, ValueError):
            return datetime.now(timezone.utc).timestamp()
