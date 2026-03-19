import streamlit as st
import pandas as pd
import sqlite3
import plotly.express as px
import os

# Configuration
st.set_page_config(page_title="Mirage-Sentinel CTI", layout="wide")

# Custom CSS for Cyberpunk aesthetic
st.markdown("""
<style>
/* Base background */
.stApp {
    background-color: #07070b;
    background-image:
        radial-gradient(circle at 50% 0%, rgba(0, 255, 204, 0.05) 0%, transparent 50%),
        linear-gradient(rgba(255, 255, 255, 0.01) 1px, transparent 1px),
        linear-gradient(90deg, rgba(255, 255, 255, 0.01) 1px, transparent 1px);
    background-size: 100% 100%, 40px 40px, 40px 40px;
}

/* Typography */
h1, h2, h3, p, span {
    color: #e0e0e0 !important;
    font-family: 'Inter', 'Segoe UI', sans-serif;
}

/* Metric cards styling */
div[data-testid="metric-container"] {
    background: linear-gradient(145deg, rgba(15, 20, 25, 0.9), rgba(5, 10, 15, 0.9)) !important;
    border-left: 3px solid #00ffcc !important;
    border-radius: 6px !important;
    padding: 1rem !important;
    box-shadow: 0 4px 15px rgba(0, 0, 0, 0.5) !important;
    transition: transform 0.2s ease, box-shadow 0.2s ease;
}
div[data-testid="metric-container"]:hover {
    transform: translateY(-3px);
    box-shadow: 0 6px 20px rgba(0, 255, 204, 0.15) !important;
}
div[data-testid="metric-container"] > div > div > div {
    color: #00ffcc !important;
    font-family: 'Fira Code', monospace !important;
    font-weight: 600 !important;
    letter-spacing: -0.5px;
}

/* Tabs styling */
button[role="tab"] {
    font-size: 16px !important;
    letter-spacing: 1px;
    color: #666677 !important;
    background: transparent !important;
    border: none !important;
    padding-bottom: 10px !important;
}
button[role="tab"][aria-selected="true"] {
    color: #ff3366 !important;
    border-bottom: 2px solid #ff3366 !important;
    text-shadow: 0 0 12px rgba(255, 51, 102, 0.4) !important;
}

/* Dataframe styling */
.stDataFrame {
    border: 1px solid #1f1f2e !important;
    border-radius: 6px;
    overflow: hidden;
}

/* Live indicator */
@keyframes pulse {
    0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(255, 51, 102, 0.7); }
    70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(255, 51, 102, 0); }
    100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(255, 51, 102, 0); }
}
.live-dot {
    height: 10px;
    width: 10px;
    background-color: #ff3366;
    border-radius: 50%;
    display: inline-block;
    margin-right: 8px;
    animation: pulse 2s infinite;
}

/* Custom Refresh Button */
div.stButton > button:first-child {
    background-color: transparent;
    color: #666677;
    border: 1px solid #1f1f2e;
    transition: all 0.3s ease;
}
div.stButton > button:first-child:hover {
    color: #00ffcc;
    border-color: #00ffcc;
    background-color: rgba(0, 255, 204, 0.05);
}
</style>
""", unsafe_allow_html=True)

# Header section
col_title, col_status = st.columns([0.8, 0.2])
with col_title:
    st.markdown("<h1 style='font-weight: 800; letter-spacing: 1px;'>MIRAGE-SENTINEL</h1>", unsafe_allow_html=True)
    st.markdown("<p style='color: #888899; font-size: 14px;'>Threat Intelligence & Dynamic Defense Console</p>", unsafe_allow_html=True)
with col_status:
    st.markdown("<div style='text-align: right; margin-top: 1.5rem;'><span class='live-dot'></span><span style='color: #ff3366; font-size: 14px; font-family: monospace; letter-spacing: 1px;'>SYSTEM ACTIVE</span></div>", unsafe_allow_html=True)

st.markdown("<hr style='border-color: #1f1f2e; margin-top: 0;'>", unsafe_allow_html=True)

# Database operations
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(CURRENT_DIR, "sqlite_memory.db")

@st.cache_data(ttl=2)
def load_data():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        # Simplified query focusing on the specific deception logs
        df = pd.read_sql_query("SELECT * FROM deception_logs", conn)
        conn.close()
        
        # Data normalization
        if 'risk_score' in df.columns and 'risk_level' not in df.columns:
            df['risk_level'] = df['risk_score']
        if 'client_ip' in df.columns and 'attacker_ip' not in df.columns:
            df['attacker_ip'] = df['client_ip']
        for col in ['last_seen', 'created_at']:
            if col in df.columns:
                df[col] = pd.to_datetime(df[col])
        return df
    except Exception:
        return pd.DataFrame()

df = load_data()

# UI Rendering
if df.empty:
    st.info("System Standby. Awaiting incoming threat data.")
else:
    tab_summary, tab_analysis, tab_logs = st.tabs([
        "Executive Summary",
        "Behavioral Analysis",
        "Interception Logs"
    ])
    
    # Dashboard layout
    with tab_summary:
        st.markdown("<br>", unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            st.metric("Total Hits", len(df))
        with c2:
            high_risk = len(df[df['risk_level'] >= 80]) if 'risk_level' in df.columns else 0
            st.metric("Critical Threats", high_risk)
        with c3:
            unique_ips = df['attacker_ip'].nunique() if 'attacker_ip' in df.columns else 0
            st.metric("Unique Attackers", unique_ips)
        with c4:
            st.metric("Defense Engine", "Active")

    with tab_analysis:
        st.markdown("<br>", unsafe_allow_html=True)
        # Unified Plotly styling
        chart_config = {
            "template": "plotly_dark",
            "paper_bgcolor": "rgba(0,0,0,0)",
            "plot_bgcolor": "rgba(0,0,0,0)"
        }
        
        col_chart1, col_chart2 = st.columns(2)
        
        with col_chart1:
            if 'attack_vector' in df.columns:
                st.markdown("<p style='color: #888899; font-size: 14px;'>Attack Vectors</p>", unsafe_allow_html=True)
                vec_df = df['attack_vector'].value_counts().reset_index()
                fig1 = px.bar(vec_df, x='count', y='attack_vector', orientation='h', color_discrete_sequence=['#ff3366'])
                fig1.update_layout(**chart_config, margin=dict(l=0, r=0, t=30, b=0))
                st.plotly_chart(fig1, use_container_width=True)

        with col_chart2:
            if 'attacker_ip' in df.columns:
                st.markdown("<p style='color: #888899; font-size: 14px;'>Top Threat Sources</p>", unsafe_allow_html=True)
                ip_df = df['attacker_ip'].value_counts().head(5).reset_index()
                fig2 = px.bar(ip_df, x='attacker_ip', y='count', color_discrete_sequence=['#00ffcc'])
                fig2.update_layout(**chart_config, margin=dict(l=0, r=0, t=30, b=0))
                st.plotly_chart(fig2, use_container_width=True)

    with tab_logs:
        st.markdown("<br>", unsafe_allow_html=True)
        display_cols = ['last_seen', 'attacker_ip', 'attack_vector', 'risk_level', 'raw_payload']
        cols_to_show = [c for c in display_cols if c in df.columns]
        if cols_to_show:
            st.dataframe(df[cols_to_show], use_container_width=True, hide_index=True)

# Footer controls
st.markdown("<br><br>", unsafe_allow_html=True)
if st.button("Refresh System"):
    st.cache_data.clear()
    st.rerun()