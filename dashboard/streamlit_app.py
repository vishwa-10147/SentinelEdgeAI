import streamlit as st
import pandas as pd
import json
import os
import time

ALERT_FILE = "alerts/alerts.json"

st.set_page_config(page_title="SentinelEdge IDS", layout="wide")

st.title("🚨 SentinelEdge AI Intrusion Detection System")

def load_alerts():
    if not os.path.exists(ALERT_FILE):
        return pd.DataFrame()

    with open(ALERT_FILE, "r") as f:
        data = json.load(f)

    if not data:
        return pd.DataFrame()

    return pd.DataFrame(data)


# Auto refresh every 5 seconds
refresh_rate = st.sidebar.slider("Refresh rate (seconds)", 2, 30, 5)

placeholder = st.empty()

while True:
    with placeholder.container():

        df = load_alerts()

        if df.empty:
            st.info("No alerts yet. System is monitoring...")
        else:
            st.metric("Total Alerts", len(df))

            col1, col2 = st.columns(2)

            with col1:
                st.subheader("Alerts by Protocol")
                st.bar_chart(df["protocol"].value_counts())

            with col2:
                st.subheader("Top Source IPs")
                st.bar_chart(df["initiator_ip"].value_counts().head(10))

            st.subheader("Recent Alerts")
            st.dataframe(df.sort_values("timestamp", ascending=False))

    time.sleep(refresh_rate)
