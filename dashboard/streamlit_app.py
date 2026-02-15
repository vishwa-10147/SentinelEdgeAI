import streamlit as st
import pandas as pd
import json
import os
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="SentinelEdge SOC", layout="wide")
st_autorefresh(interval=3000, key="refresh")

ALERT_FILE = "alerts.json"
LIVE_FILE = "live_stats.json"
PROFILE_FILE = "device_profiles.json"
RISK_FILE = "risk_timeline.json"

st.title("🚨 SentinelEdge AI - Advanced SOC Dashboard")

# ---------- Load Data ----------
def load_json_safe(path, default):
    """Load JSON files safely with exception handling."""
    try:
        if not os.path.exists(path):
            return default
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default

def load_live_stats():
    """Load live stats with backward compatibility for missing keys."""
    if not os.path.exists(LIVE_FILE):
        return {
            "total_flows": 0,
            "unique_ips": [],
            "flow_history": []
        }

    try:
        with open(LIVE_FILE, "r") as f:
            data = json.load(f)

        # Ensure missing keys are initialized
        data.setdefault("total_flows", 0)
        data.setdefault("unique_ips", [])
        data.setdefault("flow_history", [])

        return data
    except Exception:
        return {
            "total_flows": 0,
            "unique_ips": [],
            "flow_history": []
        }

def load_profiles():
    if not os.path.exists(PROFILE_FILE):
        return pd.DataFrame()

    try:
        with open(PROFILE_FILE, "r") as f:
            data = json.load(f)

        if not data:
            return pd.DataFrame()

        df = pd.DataFrame.from_dict(data, orient="index")
        df.index.name = "Device IP"
        return df.reset_index()
    except Exception:
        return pd.DataFrame()

def load_risk_timeline():
    if not os.path.exists(RISK_FILE):
        return {}
    try:
        with open(RISK_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

alerts = load_json_safe(ALERT_FILE, [])
live = load_live_stats()

df_alerts = pd.DataFrame(alerts)

# ---------- Top Metrics ----------
col1, col2, col3 = st.columns(3)
col1.metric("📦 Total Flows", live["total_flows"])
col2.metric("🌐 Active Devices", len(live["unique_ips"]))
col3.metric("🚨 Total Alerts", len(df_alerts))

st.divider()

# ---------- Engine Health Status ----------
st.subheader("🩺 Engine Health Status")

HEALTH_FILE = "health.json"
health = load_json_safe(HEALTH_FILE, {})

if health:
    st.json(health)
else:
    st.info("Health data not available yet.")

st.divider()

# ---------- Flow Trend ----------
flow_history = live.get("flow_history", [])

if flow_history:
    df_live = pd.DataFrame(flow_history)
    st.subheader("📈 Traffic & Threat Trend")
    st.line_chart(df_live["score"])

# ---------- Severity Breakdown ----------
if not df_alerts.empty:
    st.subheader("🔥 Alert Severity Breakdown")
    st.bar_chart(df_alerts["severity"].value_counts())

    st.subheader("🕒 Recent Alerts")
    st.dataframe(df_alerts.sort_values("timestamp", ascending=False))

st.divider()
st.subheader("🧠 Device Risk Leaderboard")

df_profiles = load_profiles()

if not df_profiles.empty:
    df_profiles = df_profiles.sort_values(
        "avg_risk_score",
        ascending=False
    )

    st.dataframe(df_profiles)

    st.bar_chart(df_profiles.set_index("Device IP")["avg_risk_score"])
else:
    st.info("No device profiles yet.")

st.divider()
st.subheader("📈 Device Risk Timeline")

risk_data = load_risk_timeline()

if risk_data:

    selected_ip = st.selectbox(
        "Select Device IP",
        list(risk_data.keys())
    )

    df_risk = pd.DataFrame(risk_data[selected_ip])

    if not df_risk.empty:
        st.line_chart(df_risk["risk"])
else:
    st.info("No risk timeline data yet.")

if df_alerts.empty:
    st.success("System monitoring normally. No active threats.")

st.divider()
st.subheader("🎯 MITRE ATT&CK Mapping")

required_columns = [
    "initiator_ip",
    "severity",
    "attack_type",
    "mitre_tactic",
    "mitre_technique_id",
    "mitre_technique_name"
]

available_columns = [
    col for col in required_columns
    if col in df_alerts.columns
]

if not df_alerts.empty and available_columns:
    st.dataframe(df_alerts[available_columns])
else:
    st.info("No MITRE mapping data available yet.")
