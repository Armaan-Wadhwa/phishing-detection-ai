import streamlit as st
import subprocess
import threading
import time
import sys
import pandas as pd
import os
from streamlit_autorefresh import st_autorefresh

from ui.db_utils import get_latest_scan_domains, get_latest_evidence
if "scan_running" in st.session_state:
    st_autorefresh(interval=3000, key="scan_refresh")

# ---------------- PAGE CONFIG ---------------- #
st.set_page_config(
    page_title="Phishing Detection Dashboard",
    layout="wide"
)

# ---------------- HEADER ---------------- #
st.markdown("""
<h1 style="text-align:center;">🛡️ Phishing Detection Dashboard</h1>
<p style="text-align:center; color:gray;">
Crawler • ML Analysis • Evidence Collection
</p>
<hr>
""", unsafe_allow_html=True)

# ---------------- SIDEBAR ---------------- #
st.sidebar.header("⚙️ Pipeline Control")

cse_name = st.sidebar.text_input("CSE Name", placeholder="HDFC Bank")
cse_domain = st.sidebar.text_input("CSE Domain", placeholder="hdfcbank.com")
keywords = st.sidebar.text_input("Keywords (comma-separated)", placeholder="hdfc,netbanking")

run_full = st.sidebar.button("🚀 Run Full Pipeline")

# ---------------- PIPELINE EXECUTION ---------------- #
if run_full and cse_domain:
    st.sidebar.success("Pipeline started")

    status = st.empty()
    progress = st.progress(0)

    status.text("Initializing scan...")
    progress.progress(10)
    time.sleep(0.5)

    # Build command safely (USE VENV PYTHON)
    cmd = [
        sys.executable,
        "main.py",
        "scan",
        "--name", cse_name,
        "--domain", cse_domain
    ]

    if keywords.strip():
        clean_keywords = ",".join(
            [k.strip() for k in keywords.split(",")]
        )
        cmd.extend(["--keywords", clean_keywords])

    status.text("Running crawler + ML + evidence...")

    def run_pipeline_background(command):
        subprocess.Popen(
            command,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    threading.Thread(
        target=run_pipeline_background,
        args=(cmd,),
        daemon=True
    ).start()

    progress.progress(100)
    status.success("✅ Pipeline started in background")

# ---------------- TABS ---------------- #
tab1, tab2, tab3 = st.tabs([
    "🕸️ Crawled Domains",
    "📊 Classification",
    "📸 Evidence"
])

# ---------------- TAB 1 ---------------- #
with tab1:
    st.subheader("Latest Scan – Crawled Domains")

    df = get_latest_scan_domains()
    if df.empty:
        st.info("No domains found for latest scan.")
    else:
        st.dataframe(
            df[[
                "domain_name",
                "target_cse_name",
                "source_of_detection",
                "discovery_date"
            ]],
            use_container_width=True
        )

# ---------------- TAB 2 ---------------- #
with tab2:
    st.subheader("ML Classification Results")

    df = get_latest_scan_domains()
    if df.empty:
        st.info("No classification data available.")
    else:
        col1, col2, col3 = st.columns(3)
        col1.metric("Phishing", len(df[df["classification"] == "Phishing"]))
        col2.metric("Suspected", len(df[df["classification"] == "Suspected"]))
        col3.metric("Benign", len(df[df["classification"] == "Benign"]))

        st.dataframe(
            df[[
                "domain_name",
                "classification",
                "confidence_score",
                "source_of_detection"
            ]],
            use_container_width=True
        )

# ---------------- TAB 3 ---------------- #
with tab3:
    st.subheader("Evidence Files")

    ev_df = get_latest_evidence()
    if ev_df.empty:
        st.info("No evidence available yet.")
    else:
        selected = st.selectbox(
            "Select domain",
            ev_df["domain_name"]
        )

        path = ev_df[ev_df["domain_name"] == selected]["screenshot_path"].values[0]
        st.markdown(f"**File:** `{path}`")

        with open(path, "rb") as f:
            st.download_button(
                "⬇ Download Evidence",
                f,
                file_name=path.split("/")[-1]
            )
from datetime import datetime
from streamlit_autorefresh import st_autorefresh

st.subheader("📜 Live Pipeline Logs")

# auto refresh every 2 seconds
st_autorefresh(interval=2000, key="pipeline_logs")

today = datetime.now().strftime("%Y%m%d")
log_file = os.path.join("logs", f"system_{today}.log")

log_placeholder = st.empty()

if os.path.exists(log_file):
    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        lines = f.readlines()
        log_placeholder.code("".join(lines[-40:]))
else:
    log_placeholder.info("Waiting for pipeline logs...")

# ---------------- FOOTER ---------------- #
st.markdown("""
<hr>
<p style="text-align:center; color:gray;">
PostgreSQL-backed | Production-style Pipeline | PS-02 Ready
</p>
""", unsafe_allow_html=True)
