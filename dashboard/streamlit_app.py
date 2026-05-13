import streamlit as st
import pandas as pd
import json
import os
import time
import datetime
from core.storage import get_storage
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
    # If a DB is configured, pull latest live_stats from DB
    if os.environ.get('DATABASE_URL'):
        try:
            s = get_storage('data/sentinel.db')
            s.connect()
            payload = s.get_live_stats()
            if payload:
                return json.loads(payload) if isinstance(payload, str) else payload
            return {"total_flows": 0, "unique_ips": [], "flow_history": []}
        except Exception:
            pass

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
    # Prefer DB device profiles when available
    if os.environ.get('DATABASE_URL'):
        try:
            s = get_storage('data/sentinel.db')
            s.connect()
            profiles = s.get_device_profiles()
            if not profiles:
                return pd.DataFrame()
            df = pd.DataFrame.from_dict(profiles, orient="index")
            df.index.name = "Device IP"
            return df.reset_index()
        except Exception:
            pass

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
    # Prefer DB risk timeline when available
    if os.environ.get('DATABASE_URL'):
        try:
            s = get_storage('data/sentinel.db')
            s.connect()
            rows = s.get_risk_timeline(limit=1000)
            out = {}
            for r in rows:
                dev = r.get('device_id')
                if not dev:
                    continue
                out.setdefault(dev, [])
                out[dev].append({"timestamp": r.get('timestamp'), "risk": r.get('risk')})
            return out
        except Exception:
            pass

    if not os.path.exists(RISK_FILE):
        return {}
    try:
        with open(RISK_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}

alerts = load_json_safe(ALERT_FILE, [])
live = load_live_stats()

# Prefer DB alerts when available
def load_alerts():
    # Try DB first
    if os.environ.get('DATABASE_URL'):
        try:
            s = get_storage('data/sentinel.db')
            s.connect()
            rows = s.get_alerts(limit=2000)
            return rows
        except Exception:
            pass
    return load_json_safe(ALERT_FILE, [])

alerts = load_alerts()
live = load_live_stats()

df_alerts = pd.DataFrame(alerts)

# ---------- Sidebar controls ----------
st.sidebar.header("Filters & View")
time_range = st.sidebar.selectbox("Time range", ["1h", "6h", "24h", "7d", "30d", "All"], index=2)
agg_choice = st.sidebar.selectbox("Aggregation", ["1Min", "5Min", "1H"], index=0)
top_n = st.sidebar.slider("Top N for leaderboards", min_value=5, max_value=50, value=10)
ip_filter = st.sidebar.text_input("IP contains (src/dst)", value="")

# Build device/IP options from DB (preferred) then fall back to alerts
device_options = []
try:
    if os.environ.get('DATABASE_URL'):
        s_tmp = get_storage('data/sentinel.db')
        s_tmp.connect()
        dev_profiles = s_tmp.get_device_profiles()
        if isinstance(dev_profiles, dict):
            device_options = sorted(list(dev_profiles.keys()))
except Exception:
    device_options = []

if not device_options:
    try:
        tmp_alerts = load_alerts()
        ips = set()
        for a in tmp_alerts:
            if isinstance(a, dict):
                if a.get('src_ip'):
                    ips.add(a.get('src_ip'))
                if a.get('dst_ip'):
                    ips.add(a.get('dst_ip'))
        device_options = sorted(list(ips))
    except Exception:
        device_options = []

device_selection = st.sidebar.multiselect("Devices/IPs", device_options, default=[])

def time_range_to_cutoff(tr):
    if tr == 'All':
        return None
    mapping = {'1h':3600, '6h':3600*6, '24h':3600*24, '7d':3600*24*7, '30d':3600*24*30}
    secs = mapping.get(tr)
    return int(time.time()) - secs if secs else None

cutoff_ts = time_range_to_cutoff(time_range)

# apply basic filters to alerts dataframe
if not df_alerts.empty and 'timestamp' in df_alerts.columns:
    if cutoff_ts:
        df_alerts = df_alerts[df_alerts['timestamp'] >= cutoff_ts]
    if ip_filter:
        df_alerts = df_alerts[df_alerts.get('src_ip', '').astype(str).str.contains(ip_filter) | df_alerts.get('dst_ip', '').astype(str).str.contains(ip_filter)]
    if device_selection:
        df_alerts = df_alerts[df_alerts.get('src_ip', '').isin(device_selection) | df_alerts.get('dst_ip', '').isin(device_selection)]

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
    # show threat score trend and flows per timeseries if available
    cols = st.columns(2)
    with cols[0]:
        if 'score' in df_live.columns:
            st.line_chart(df_live['score'])
        else:
            st.info('No score timeseries available')
    with cols[1]:
        if 'flows' in df_live.columns:
            st.line_chart(df_live['flows'])
        else:
            st.info('No flows timeseries available')

# ----- Additional Visualizations -----
st.divider()
st.subheader("📊 Alert & Flow Insights")

if not df_alerts.empty:
    # Alerts by protocol
    if 'protocol' in df_alerts.columns:
        st.markdown('**Alerts by Protocol**')
        st.bar_chart(df_alerts['protocol'].value_counts())

    # Alerts by severity if available
    if 'severity' in df_alerts.columns:
        st.markdown('**Alerts by Severity**')
        st.bar_chart(df_alerts['severity'].value_counts())

    # Top talkers (src_ip)
    if 'src_ip' in df_alerts.columns:
        st.markdown('**Top Alerting Source IPs**')
        st.bar_chart(df_alerts['src_ip'].value_counts().head(10))

    # Recent alerts table (already present below)
else:
    st.info('No alerts available yet.')

# Top talkers across flows (if available via DB)
try:
    s = None
    if os.environ.get('DATABASE_URL'):
        s = get_storage('data/sentinel.db')
        s.connect()
        flows = s.get_flows(limit=2000)
    else:
        flows = []
except Exception:
    flows = []

if flows:
    df_flows = pd.DataFrame(flows)
    # apply same filters to flows
    if not df_flows.empty:
        if 'timestamp' in df_flows.columns and cutoff_ts:
            df_flows = df_flows[df_flows['timestamp'] >= cutoff_ts]
        if ip_filter:
            df_flows = df_flows[df_flows.get('src_ip', '').astype(str).str.contains(ip_filter) | df_flows.get('dst_ip', '').astype(str).str.contains(ip_filter)]
    if not df_flows.empty and 'src_ip' in df_flows.columns:
        st.markdown('**Top Talkers (by flow count)**')
        st.bar_chart(df_flows['src_ip'].value_counts().head(top_n))
    # flows over time (if timestamps exist)
    if not df_flows.empty and 'timestamp' in df_flows.columns:
        try:
            df_flows['ts_dt'] = pd.to_datetime(df_flows['timestamp'], unit='s')
            # use aggregation choice from sidebar
            rule = agg_choice
            # map human-friendly '1H' to pandas alias
            if rule == '1H':
                rule = '1H'
            series = df_flows.set_index('ts_dt').resample(rule).size()
            st.markdown(f'**Flows Over Time ({rule} buckets)**')
            st.line_chart(series)
        except Exception:
            pass

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
    # Only sort/plot if the expected column exists
    if "avg_risk_score" in df_profiles.columns:
        df_profiles = df_profiles.sort_values("avg_risk_score", ascending=False)
        st.dataframe(df_profiles)
        st.bar_chart(df_profiles.set_index("Device IP")["avg_risk_score"])
    else:
        st.dataframe(df_profiles)
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
