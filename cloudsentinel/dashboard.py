"""CloudSentinel — futuristic Streamlit security console.

Run with:
    streamlit run cloudsentinel/dashboard.py
"""

from __future__ import annotations

import html
import json
import os
import sys
from datetime import timedelta
from pathlib import Path

import pandas as pd
import plotly.graph_objects as go
import streamlit as st

_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:  # allow `streamlit run cloudsentinel/dashboard.py`
    sys.path.insert(0, str(_ROOT))

from cloudsentinel.accounts import AccountStore  # noqa: E402
from cloudsentinel.auth import ADMIN, TRIAGE, Principal, open_principal  # noqa: E402
from cloudsentinel.config import Config  # noqa: E402
from cloudsentinel.db import AlertStore  # noqa: E402
from cloudsentinel.notify import notify_alerts  # noqa: E402
from cloudsentinel.paths import DEFAULT_DB_PATH, RAW_DIR, SUPPORTED_SUFFIXES  # noqa: E402
from cloudsentinel.pipeline import scan_files  # noqa: E402
from cloudsentinel.report import (  # noqa: E402
    alerts_dataframe,
    render_html,
    render_pdf_bytes,
    report_payload,
    summary,
)
from cloudsentinel.severity import Severity  # noqa: E402
from cloudsentinel.triage import STATUSES, TriageError  # noqa: E402
from cloudsentinel.utils import truncate, utcnow  # noqa: E402

SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]
DETECTORS = [
    "brute_force",
    "impossible_travel",
    "public_storage",
    "iam_permissions",
    "mfa_changes",
    "root_usage",
    "access_key_creation",
    "security_group_open",
    "cloudtrail_tampering",
]
DETECTOR_LABELS = {
    "brute_force": "BRUTE FORCE",
    "impossible_travel": "IMPOSSIBLE TRAVEL",
    "public_storage": "PUBLIC STORAGE",
    "iam_permissions": "IAM PERMISSIONS",
    "mfa_changes": "MFA CHANGES",
    "root_usage": "ROOT USAGE",
    "access_key_creation": "ACCESS KEYS",
    "security_group_open": "OPEN SECURITY GROUP",
    "cloudtrail_tampering": "CLOUDTRAIL TAMPERING",
}
WINDOWS = {
    "Last 24 hours": timedelta(hours=24),
    "Last 7 days": timedelta(days=7),
    "Last 30 days": timedelta(days=30),
    "All time": None,
}

st.set_page_config(
    page_title="CloudSentinel — Threat Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@500;700;900&family=Share+Tech+Mono&family=Inter:wght@400;500;600&display=swap');

:root {
    --cyan: #00e5ff;
    --violet: #7c4dff;
    --green: #30d158;
    --amber: #ff9f0a;
    --red: #ff2d55;
    --text: #e6f1ff;
    --muted: #7d93ad;
    --panel: rgba(11, 20, 36, 0.72);
    --border: rgba(0, 229, 255, 0.16);
}

html, body, [class*="css"], .stApp { font-family: 'Inter', system-ui, sans-serif; }

.login-hint {
    font-family: 'Share Tech Mono', monospace;
    color: var(--muted);
    padding: 0.4rem 0 1rem 0;
    letter-spacing: 0.04em;
}

.stApp {
    background:
        radial-gradient(1100px 560px at 82% -8%, rgba(124, 77, 255, 0.20), transparent 62%),
        radial-gradient(900px 480px at -5% 8%, rgba(0, 229, 255, 0.13), transparent 58%),
        linear-gradient(180deg, #050810 0%, #060c18 55%, #04070e 100%);
    color: var(--text);
}

.stApp::before {
    content: "";
    position: fixed;
    inset: 0;
    pointer-events: none;
    background-image:
        linear-gradient(rgba(0, 229, 255, 0.045) 1px, transparent 1px),
        linear-gradient(90deg, rgba(0, 229, 255, 0.045) 1px, transparent 1px);
    background-size: 48px 48px;
    mask-image: radial-gradient(circle at 50% 20%, rgba(0,0,0,0.85), transparent 78%);
    z-index: 0;
}

.block-container { padding-top: 1.2rem; padding-bottom: 3rem; position: relative; z-index: 1; }

#MainMenu, footer { visibility: hidden; }

/* ---------------------------------------------------------------- header */
.cs-header {
    display: flex; align-items: center; gap: 1.1rem;
    padding: 1.1rem 1.4rem;
    border-radius: 18px;
    border: 1px solid var(--border);
    background: linear-gradient(120deg, rgba(0,229,255,0.08), rgba(124,77,255,0.10));
    box-shadow: 0 0 40px rgba(0, 229, 255, 0.10), inset 0 0 30px rgba(0, 229, 255, 0.03);
    backdrop-filter: blur(14px);
    margin-bottom: 1.2rem;
}
.cs-logo {
    width: 54px; height: 54px; border-radius: 14px;
    display: grid; place-items: center;
    font-family: 'Orbitron', sans-serif; font-size: 1.7rem; color: var(--cyan);
    border: 1px solid rgba(0, 229, 255, 0.5);
    background: rgba(0, 229, 255, 0.07);
    box-shadow: 0 0 22px rgba(0, 229, 255, 0.35), inset 0 0 18px rgba(0, 229, 255, 0.18);
    animation: pulse-logo 3.2s ease-in-out infinite;
}
@keyframes pulse-logo {
    0%, 100% { box-shadow: 0 0 18px rgba(0, 229, 255, 0.25), inset 0 0 14px rgba(0, 229, 255, 0.12); }
    50% { box-shadow: 0 0 34px rgba(0, 229, 255, 0.55), inset 0 0 24px rgba(0, 229, 255, 0.28); }
}
.cs-title {
    font-family: 'Orbitron', sans-serif; font-size: 1.55rem; font-weight: 900;
    letter-spacing: 0.22em;
    background: linear-gradient(90deg, #00e5ff 10%, #8be9ff 45%, #b39dff 90%);
    -webkit-background-clip: text; background-clip: text; color: transparent;
}
.cs-subtitle {
    font-family: 'Share Tech Mono', monospace; font-size: 0.78rem;
    letter-spacing: 0.28em; color: var(--muted); margin-top: 0.15rem;
}
.cs-status {
    margin-left: auto; display: flex; align-items: center; gap: 0.55rem;
    font-family: 'Share Tech Mono', monospace; font-size: 0.76rem;
    letter-spacing: 0.16em; color: var(--green);
    border: 1px solid rgba(48, 209, 88, 0.35);
    background: rgba(48, 209, 88, 0.08);
    padding: 0.5rem 0.85rem; border-radius: 999px;
}
.cs-dot {
    width: 9px; height: 9px; border-radius: 50%; background: var(--green);
    box-shadow: 0 0 12px var(--green);
    animation: blink 1.6s ease-in-out infinite;
}
@keyframes blink { 0%, 100% { opacity: 1; } 50% { opacity: 0.35; } }

/* ---------------------------------------------------------------- metrics */
.metric-grid {
    display: grid; grid-template-columns: repeat(4, minmax(0, 1fr));
    gap: 1rem; margin-bottom: 1.4rem;
}
.glass-card {
    position: relative; overflow: hidden;
    padding: 1.05rem 1.2rem;
    border-radius: 16px;
    border: 1px solid var(--border);
    background: var(--panel);
    backdrop-filter: blur(12px);
    box-shadow: 0 10px 32px rgba(0, 0, 0, 0.38);
    transition: transform 0.2s ease, border-color 0.2s ease, box-shadow 0.2s ease;
}
.glass-card:hover {
    transform: translateY(-3px);
    border-color: rgba(0, 229, 255, 0.4);
    box-shadow: 0 14px 38px rgba(0, 229, 255, 0.12);
}
.glass-card::after {
    content: ""; position: absolute; left: 0; right: 0; top: 0; height: 2px;
    background: linear-gradient(90deg, transparent, var(--cyan), transparent);
    opacity: 0.55;
}
.glass-card.crit::after { background: linear-gradient(90deg, transparent, var(--red), transparent); }
.glass-card.high::after { background: linear-gradient(90deg, transparent, var(--amber), transparent); }
.glass-card.violet::after { background: linear-gradient(90deg, transparent, var(--violet), transparent); }

.metric-label {
    font-family: 'Share Tech Mono', monospace; font-size: 0.7rem;
    letter-spacing: 0.22em; color: var(--muted); margin-bottom: 0.5rem;
}
.metric-value {
    font-family: 'Orbitron', sans-serif; font-size: 2.05rem; font-weight: 700;
    line-height: 1; color: var(--text);
}
.metric-value.crit { color: var(--red); text-shadow: 0 0 20px rgba(255, 45, 85, 0.4); }
.metric-value.high { color: var(--amber); text-shadow: 0 0 20px rgba(255, 159, 10, 0.35); }
.metric-value.violet { color: #b39dff; text-shadow: 0 0 20px rgba(124, 77, 255, 0.4); }
.metric-note {
    font-family: 'Share Tech Mono', monospace; font-size: 0.68rem;
    color: var(--muted); margin-top: 0.45rem; letter-spacing: 0.08em;
}

/* ---------------------------------------------------------------- sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, rgba(7, 13, 26, 0.96), rgba(5, 9, 18, 0.98));
    border-right: 1px solid var(--border);
}
section[data-testid="stSidebar"] .block-container { padding-top: 1.4rem; }
.side-brand {
    font-family: 'Orbitron', sans-serif; font-size: 0.95rem; font-weight: 700;
    letter-spacing: 0.18em; color: var(--cyan); margin-bottom: 0.1rem;
}
.side-sub {
    font-family: 'Share Tech Mono', monospace; font-size: 0.68rem;
    letter-spacing: 0.2em; color: var(--muted); margin-bottom: 1.2rem;
}
.side-section {
    font-family: 'Share Tech Mono', monospace; font-size: 0.68rem;
    letter-spacing: 0.24em; color: var(--muted);
    border-top: 1px solid rgba(0, 229, 255, 0.12);
    padding-top: 0.9rem; margin: 0.6rem 0 0.4rem;
}
.sys-card {
    border: 1px solid rgba(0, 229, 255, 0.12);
    border-radius: 12px; padding: 0.75rem 0.85rem;
    background: rgba(0, 229, 255, 0.035);
    font-family: 'Share Tech Mono', monospace; font-size: 0.66rem;
    color: var(--muted); line-height: 1.7; letter-spacing: 0.05em;
    word-break: break-all;
}
.sys-card b { color: var(--text); font-weight: 500; }

/* ---------------------------------------------------------------- buttons */
.stButton > button, .stDownloadButton > button {
    width: 100%;
    font-family: 'Share Tech Mono', monospace !important;
    letter-spacing: 0.14em; font-size: 0.74rem !important;
    border-radius: 10px !important;
    border: 1px solid rgba(0, 229, 255, 0.4) !important;
    background: linear-gradient(120deg, rgba(0, 229, 255, 0.16), rgba(124, 77, 255, 0.16)) !important;
    color: #dffaff !important;
    transition: all 0.2s ease;
}
.stButton > button:hover, .stDownloadButton > button:hover {
    border-color: var(--cyan) !important;
    box-shadow: 0 0 22px rgba(0, 229, 255, 0.35);
    transform: translateY(-1px);
}
.stButton > button[kind="primary"] {
    background: linear-gradient(120deg, rgba(0, 229, 255, 0.28), rgba(124, 77, 255, 0.32)) !important;
    border-color: var(--cyan) !important;
}

/* ---------------------------------------------------------------- tabs */
.stTabs [data-baseweb="tab-list"] {
    gap: 0.4rem; border-bottom: 1px solid rgba(0, 229, 255, 0.14);
}
.stTabs [data-baseweb="tab"] {
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 0.16em; font-size: 0.76rem;
    color: var(--muted);
    background: transparent;
    padding: 0.6rem 1.1rem;
}
.stTabs [aria-selected="true"] {
    color: var(--cyan) !important;
    border-bottom: 2px solid var(--cyan) !important;
    text-shadow: 0 0 14px rgba(0, 229, 255, 0.4);
}

/* ---------------------------------------------------------------- charts */
.chart-card {
    border: 1px solid var(--border); border-radius: 16px;
    background: var(--panel); padding: 0.4rem 0.8rem 0.2rem;
    box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
}
.chart-title {
    font-family: 'Share Tech Mono', monospace; font-size: 0.7rem;
    letter-spacing: 0.22em; color: var(--muted); padding: 0.6rem 0.4rem 0;
}

/* ---------------------------------------------------------------- feed */
.table-wrap {
    border: 1px solid var(--border); border-radius: 16px; overflow: hidden;
    background: var(--panel); box-shadow: 0 12px 34px rgba(0, 0, 0, 0.35);
}
.alert-table { width: 100%; border-collapse: collapse; font-size: 0.82rem; }
.alert-table thead th {
    font-family: 'Share Tech Mono', monospace; font-size: 0.66rem;
    letter-spacing: 0.2em; color: var(--muted); text-align: left;
    padding: 0.85rem 1rem; border-bottom: 1px solid rgba(0, 229, 255, 0.16);
    background: rgba(0, 229, 255, 0.03); white-space: nowrap;
}
.alert-table tbody td {
    padding: 0.8rem 1rem; border-bottom: 1px solid rgba(255, 255, 255, 0.045);
    vertical-align: top;
}
.alert-table tbody tr:hover { background: rgba(0, 229, 255, 0.045); }
.alert-title { font-weight: 600; color: var(--text); margin-bottom: 0.18rem; }
.alert-desc { color: var(--muted); font-size: 0.75rem; line-height: 1.45; max-width: 640px; }
.entity { font-family: 'Share Tech Mono', monospace; color: #bfe9ff; font-size: 0.78rem; }
.mono { font-family: 'Share Tech Mono', monospace; color: var(--muted); font-size: 0.74rem; white-space: nowrap; }

.badge {
    display: inline-block; padding: 0.24rem 0.62rem; border-radius: 999px;
    font-family: 'Share Tech Mono', monospace; font-size: 0.64rem;
    letter-spacing: 0.14em; white-space: nowrap;
}
.badge.critical { color: #ff9db2; background: rgba(255, 45, 85, 0.13); border: 1px solid rgba(255, 45, 85, 0.55); box-shadow: 0 0 14px rgba(255, 45, 85, 0.28); animation: crit-pulse 2.4s ease-in-out infinite; }
.badge.high { color: #ffd39c; background: rgba(255, 159, 10, 0.12); border: 1px solid rgba(255, 159, 10, 0.5); }
.badge.medium { color: #ffe89c; background: rgba(255, 214, 10, 0.1); border: 1px solid rgba(255, 214, 10, 0.45); }
.badge.low { color: #a9f0bd; background: rgba(48, 209, 88, 0.1); border: 1px solid rgba(48, 209, 88, 0.4); }
.badge.info { color: #b6e9ff; background: rgba(100, 210, 255, 0.1); border: 1px solid rgba(100, 210, 255, 0.4); }
@keyframes crit-pulse { 0%, 100% { box-shadow: 0 0 8px rgba(255,45,85,0.2); } 50% { box-shadow: 0 0 18px rgba(255,45,85,0.55); } }

.pill {
    display: inline-block; padding: 0.2rem 0.55rem; border-radius: 8px;
    font-family: 'Share Tech Mono', monospace; font-size: 0.62rem;
    letter-spacing: 0.1em; color: #bfe9ff;
    border: 1px solid rgba(0, 229, 255, 0.24); background: rgba(0, 229, 255, 0.05);
    white-space: nowrap;
}
.pill.status-open { color: #8be9ff; border-color: rgba(0, 229, 255, 0.4); background: rgba(0, 229, 255, 0.07); }
.pill.status-acknowledged { color: #ffd39c; border-color: rgba(255, 159, 10, 0.42); background: rgba(255, 159, 10, 0.08); }
.pill.status-closed { color: #a9f0bd; border-color: rgba(48, 209, 88, 0.4); background: rgba(48, 209, 88, 0.08); }

/* ---------------------------------------------------------------- risk list */
.risk-row { display: flex; align-items: center; gap: 0.8rem; padding: 0.55rem 0; border-bottom: 1px solid rgba(255,255,255,0.05); }
.risk-entity { font-family: 'Share Tech Mono', monospace; font-size: 0.78rem; color: #d8f4ff; width: 190px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.risk-bar { flex: 1; height: 7px; border-radius: 999px; background: rgba(255,255,255,0.07); overflow: hidden; }
.risk-fill { height: 100%; border-radius: 999px; background: linear-gradient(90deg, #00e5ff, #7c4dff); box-shadow: 0 0 12px rgba(0,229,255,0.5); }
.risk-score { font-family: 'Share Tech Mono', monospace; font-size: 0.72rem; color: var(--muted); width: 62px; text-align: right; }

/* ---------------------------------------------------------------- empty */
.empty-state {
    text-align: center; padding: 3.2rem 1rem;
    border: 1px dashed rgba(0, 229, 255, 0.25); border-radius: 18px;
    background: rgba(0, 229, 255, 0.025);
}
.empty-icon { font-size: 2.6rem; filter: drop-shadow(0 0 18px rgba(0,229,255,0.45)); }
.empty-title { font-family: 'Orbitron', sans-serif; letter-spacing: 0.2em; font-size: 1rem; color: var(--cyan); margin: 0.7rem 0 0.35rem; }
.empty-copy { color: var(--muted); font-size: 0.82rem; max-width: 520px; margin: 0 auto; }

.cs-footer {
    margin-top: 2.4rem; padding-top: 1rem; border-top: 1px solid rgba(0, 229, 255, 0.1);
    font-family: 'Share Tech Mono', monospace; font-size: 0.66rem;
    letter-spacing: 0.16em; color: #54687f; display: flex; justify-content: space-between;
}

@media (max-width: 980px) {
    .metric-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
    .cs-status { display: none; }
}
</style>
"""

_CHART_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(family="Inter, sans-serif", color="#9fb3c8", size=12),
    margin=dict(l=10, r=16, t=18, b=10),
    hoverlabel=dict(
        bgcolor="#0b1424",
        bordercolor="rgba(0,229,255,0.4)",
        font=dict(family="Share Tech Mono, monospace", color="#e6f1ff"),
    ),
)


def inject_css() -> None:
    st.markdown(CSS, unsafe_allow_html=True)


def _store_path() -> Path:
    """Resolve the alert database at run time so tests can redirect it."""

    return Path(os.environ.get("CLOUDSENTINEL_DB") or DEFAULT_DB_PATH)


# ------------------------------------------------------------------- accounts


def _console_principal() -> Principal:
    """Resolve the signed-in console user, rendering the login gate if needed.

    Consistent with the API's opt-in posture: when no console accounts have
    been created the console stays open and reports the gap in the sidebar.
    """

    accounts = AccountStore()
    if accounts.count() == 0:
        return open_principal()

    stored = st.session_state.get("principal")
    if isinstance(stored, Principal):
        return stored

    _render_login(accounts)
    st.stop()


def _render_login(accounts: AccountStore) -> None:
    """Full-screen sign-in gate marking the end of the script run."""

    st.markdown(
        '<div class="side-brand">CLOUDSENTINEL</div>'
        '<div class="side-sub">// ACCESS CONTROL</div>',
        unsafe_allow_html=True,
    )
    st.markdown(
        '<div class="login-hint">Sign in to the security console. Accounts are'
        " managed with <code>python -m cloudsentinel users add</code>.</div>",
        unsafe_allow_html=True,
    )

    with st.form("console_login"):
        username = st.text_input("Username", autocomplete="username")
        password = st.text_input("Password", type="password")
        submitted = st.form_submit_button("SIGN IN", type="primary")

    if not submitted:
        return
    if not username.strip() or not password:
        st.error("Enter a username and a password.")
        return

    account = None
    try:
        account = accounts.authenticate(username.strip(), password)
    except Exception:  # noqa: BLE001 - never leak store internals to the UI
        account = None
    if account is None:
        st.error("Invalid username or password.")
        return

    st.session_state["principal"] = Principal(
        account.username, account.role, source="account"
    )
    st.rerun()


def _render_session(principal: Principal) -> None:
    """Signed-in card plus sign-out in the sidebar (before the actions)."""

    if principal.source == "open":
        st.markdown(
            '<div class="sys-card">CONSOLE <b>OPEN</b><br>'
            "no accounts configured - run<br>"
            "<code>users add NAME --role admin</code> to lock it.</div>",
            unsafe_allow_html=True,
        )
        return
    if st.button("SIGN OUT"):
        st.session_state.pop("principal", None)
        st.rerun()
    st.markdown(
        '<div class="sys-card">SIGNED IN <b>'
        + html.escape(principal.name)
        + "</b><br>ROLE <b>"
        + principal.role.upper()
        + "</b></div>",
        unsafe_allow_html=True,
    )


def main() -> None:
    inject_css()
    principal = _console_principal()
    store = AlertStore(_store_path()).init()

    with st.sidebar:
        st.markdown(
            '<div class="side-brand">CLOUDSENTINEL</div>'
            '<div class="side-sub">// SECURITY OPERATIONS</div>',
            unsafe_allow_html=True,
        )
        _render_session(principal)

        if principal.can(ADMIN):
            if st.button("⚡ RUN DETECTION SCAN", type="primary"):
                _run_scan(store)

            if st.button("◈ LOAD DEMO TELEMETRY"):
                _load_demo(store)

            if st.button("✉ SEND ALERTS"):
                _send_notifications(store)
        else:
            st.markdown(
                '<div class="sys-card">READ-ONLY SESSION<br>'
                "scanning and alert delivery need the admin role.</div>",
                unsafe_allow_html=True,
            )

        st.markdown('<div class="side-section">FILTERS</div>', unsafe_allow_html=True)
        severities = st.multiselect(
            "Severity",
            options=[severity.value for severity in SEVERITY_ORDER],
            default=[severity.value for severity in SEVERITY_ORDER],
            format_func=lambda value: value.upper(),
            label_visibility="collapsed",
            placeholder="Severity filter",
        )
        detectors = st.multiselect(
            "Detector",
            options=DETECTORS,
            default=DETECTORS,
            format_func=lambda value: DETECTOR_LABELS.get(value, value),
            label_visibility="collapsed",
            placeholder="Detector filter",
        )
        statuses = st.multiselect(
            "Status",
            options=list(STATUSES),
            default=list(STATUSES),
            format_func=lambda value: value.upper(),
            label_visibility="collapsed",
            placeholder="Triage status filter",
        )
        window_label = st.selectbox(
            "Time window", list(WINDOWS), index=1, label_visibility="collapsed"
        )
        search = st.text_input(
            "Search", placeholder="Search entity / text…", label_visibility="collapsed"
        )

        st.markdown('<div class="side-section">SYSTEM</div>', unsafe_allow_html=True)
        raw_files = _count_raw_files()
        last_scan = store.last_scan_time() or "never"
        triage_stats = store.stats()
        st.markdown(
            f'<div class="sys-card">DB <b>{html.escape(_store_path().name)}</b><br>'
            f'RAW FILES <b>{raw_files}</b><br>'
            f'LAST SCAN <b>{html.escape(last_scan)}</b><br>'
            f'ALERTS <b>{store.count()}</b><br>'
            f'OPEN <b>{triage_stats["by_status"].get("open", 0)}</b></div>',
            unsafe_allow_html=True,
        )

    alerts = store.fetch_alerts(
        severity=severities or None,
        detector=detectors or None,
        status=statuses or None,
    )
    frame = alerts_dataframe(alerts)
    frame = _apply_filters(frame, window_label, search)

    st.markdown(_header_html(store), unsafe_allow_html=True)
    _render_metrics(frame)

    if frame.empty and store.count() == 0:
        _render_empty_state()
        _footer()
        return
    if frame.empty:
        st.markdown(
            '<div class="empty-state"><div class="empty-icon">🔍</div>'
            '<div class="empty-title">NO MATCHING SIGNALS</div>'
            '<div class="empty-copy">Adjust the severity, detector, time window or'
            " search filters to widen the view.</div></div>",
            unsafe_allow_html=True,
        )
        _footer()
        return

    overview_tab, feed_tab, export_tab = st.tabs(
        ["◈ OVERVIEW", "▣ ALERT FEED", "⤓ EXPORTS"]
    )

    with overview_tab:
        _render_overview(frame)

    with feed_tab:
        _render_feed(frame, store, can_triage=principal.can(TRIAGE))

    with export_tab:
        _render_exports(frame)

    _footer()


# --------------------------------------------------------------------- actions


def _run_scan(store: AlertStore) -> None:
    try:
        config = Config.load()
    except Exception as exc:  # pragma: no cover - config is user supplied
        st.error(f"Configuration error: {exc}")
        return

    with st.spinner("Scanning raw audit logs…"):
        result = scan_files(RAW_DIR, store.path, config)

    if result.events_scanned == 0:
        st.warning("No raw events found. Generate demo telemetry or drop logs in data/raw.")
        return

    st.toast(
        f"Scan complete — {len(result.alerts)} alerts"
        f" ({result.inserted} new, {result.merged} merged)"
    )
    st.rerun()


def _load_demo(store: AlertStore) -> None:
    from cloudsentinel.sampledata import write_sample_data

    with st.spinner("Generating demo telemetry…"):
        write_sample_data()
        result = scan_files(RAW_DIR, store.path, Config(), reset=True)
    st.toast(f"Demo loaded — {len(result.alerts)} alerts across 2 log sources")
    st.rerun()


def _send_notifications(store: AlertStore) -> None:
    try:
        config = Config.load()
    except Exception as exc:  # pragma: no cover - user supplied config
        st.error(f"Configuration error: {exc}")
        return

    results = notify_alerts(store.fetch_alerts(), config.notifications)
    if not results:
        st.info("Notifications are disabled. Configure them in cloudsentinel.toml.")
        return

    summary_text = " · ".join(
        f"{result.channel}: {'sent' if result.sent else 'failed'}" for result in results
    )
    st.toast(summary_text)


def _count_raw_files() -> int:
    if not RAW_DIR.exists():
        return 0
    return sum(
        1
        for path in RAW_DIR.rglob("*")
        if path.is_file() and path.suffix.lower() in SUPPORTED_SUFFIXES
    )


# --------------------------------------------------------------------- render


def _header_html(store: AlertStore) -> str:
    return f"""
    <div class="cs-header">
        <div class="cs-logo">◈</div>
        <div>
            <div class="cs-title">CLOUDSENTINEL</div>
            <div class="cs-subtitle">// CLOUD THREAT DETECTION CONSOLE</div>
        </div>
        <div class="cs-status"><span class="cs-dot"></span> MONITORING ACTIVE</div>
    </div>
    """


def _render_metrics(frame: pd.DataFrame) -> None:
    counts = frame["severity"].value_counts().to_dict() if not frame.empty else {}
    critical = int(counts.get("critical", 0))
    high = int(counts.get("high", 0))
    entities = int(frame["entity"].nunique()) if not frame.empty else 0
    total = int(len(frame))

    st.markdown(
        f"""
        <div class="metric-grid">
            <div class="glass-card">
                <div class="metric-label">TOTAL ALERTS</div>
                <div class="metric-value">{total}</div>
                <div class="metric-note">active findings in view</div>
            </div>
            <div class="glass-card crit">
                <div class="metric-label">CRITICAL</div>
                <div class="metric-value crit">{critical}</div>
                <div class="metric-note">immediate response required</div>
            </div>
            <div class="glass-card high">
                <div class="metric-label">HIGH</div>
                <div class="metric-value high">{high}</div>
                <div class="metric-note">triage within 24 hours</div>
            </div>
            <div class="glass-card violet">
                <div class="metric-label">ENTITIES AT RISK</div>
                <div class="metric-value violet">{entities}</div>
                <div class="metric-note">users · buckets · principals</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _render_overview(frame: pd.DataFrame) -> None:
    left, right = st.columns([1, 1.35])

    with left:
        st.markdown('<div class="chart-title">SEVERITY DISTRIBUTION</div>', unsafe_allow_html=True)
        st.plotly_chart(
            _severity_donut(frame),
            width="stretch",
            config={"displayModeBar": False},
        )

    with right:
        st.markdown('<div class="chart-title">ALERT TIMELINE</div>', unsafe_allow_html=True)
        st.plotly_chart(
            _timeline_chart(frame),
            width="stretch",
            config={"displayModeBar": False},
        )

    left, right = st.columns([1, 1])

    with left:
        st.markdown('<div class="chart-title">DETECTIONS BY ENGINE</div>', unsafe_allow_html=True)
        st.plotly_chart(
            _detector_chart(frame),
            width="stretch",
            config={"displayModeBar": False},
        )

    with right:
        st.markdown('<div class="chart-title">TOP RISK ENTITIES</div>', unsafe_allow_html=True)
        st.markdown(_risk_list_html(frame), unsafe_allow_html=True)


def _render_feed(
    frame: pd.DataFrame, store: AlertStore, *, can_triage: bool = False
) -> None:
    subtitle = (
        f"{len(frame)} finding(s) — newest first · "
        f"showing up to 200 rows"
    )
    st.markdown(
        f'<div class="chart-title" style="padding-bottom:0.5rem">{html.escape(subtitle)}</div>',
        unsafe_allow_html=True,
    )
    st.markdown(_feed_html(frame), unsafe_allow_html=True)
    if can_triage:
        _render_triage_console(frame, store)


def _render_triage_console(frame: pd.DataFrame, store: AlertStore) -> None:
    visible = list(frame.head(200).itertuples(index=False))
    if not visible:
        return

    choices = {f"#{int(row.id)} — {row.title}": int(row.id) for row in visible}
    current = {
        int(row.id): str(getattr(row, "status", "open") or "open")
        for row in visible
    }

    st.markdown('<div class="chart-title">TRIAGE CONSOLE</div>', unsafe_allow_html=True)
    with st.form("triage_form"):
        selected = st.selectbox("Alert", list(choices), key="triage_alert")
        status = st.selectbox(
            "New status",
            list(STATUSES),
            index=list(STATUSES).index(current.get(choices[selected], "open")),
            format_func=lambda value: value.upper(),
            key="triage_status",
        )
        assignee = st.text_input(
            "Assignee",
            placeholder="analyst@example.com",
            key="triage_assignee",
        )
        clear_assignee = st.checkbox(
            "Clear assignee", value=False, key="triage_clear_assignee"
        )
        submitted = st.form_submit_button("APPLY TRIAGE")

    if not submitted:
        return

    try:
        alert = store.set_triage(
            choices[selected],
            status=status,
            assignee=assignee or None,
            update_assignee=bool(assignee.strip()) or clear_assignee,
        )
    except TriageError as exc:
        st.error(str(exc))
        return

    if alert is None:
        st.error("Alert no longer exists — refresh the feed.")
        return

    owner = f" · {alert.assignee}" if alert.assignee else ""
    st.toast(f"Alert #{alert.id} → {alert.status}{owner}")
    st.rerun()


def _render_exports(frame: pd.DataFrame) -> None:
    info = summary(frame)
    stamp = utcnow().strftime("%Y%m%d_%H%M%S")

    left, right = st.columns(2)
    with left:
        st.markdown('<div class="chart-title">CSV REPORT</div>', unsafe_allow_html=True)
        csv_data = frame.copy()
        csv_data["evidence"] = csv_data["evidence"].map(
            lambda value: json.dumps(value, default=str, sort_keys=True)
            if isinstance(value, (dict, list))
            else value
        )
        st.download_button(
            "⤓ DOWNLOAD CSV",
            data=csv_data.to_csv(index=False).encode("utf-8"),
            file_name=f"cloudsentinel_alerts_{stamp}.csv",
            mime="text/csv",
        )
    with right:
        st.markdown('<div class="chart-title">JSON REPORT</div>', unsafe_allow_html=True)
        st.download_button(
            "⤓ DOWNLOAD JSON",
            data=json.dumps(report_payload(frame), indent=2, default=str).encode("utf-8"),
            file_name=f"cloudsentinel_alerts_{stamp}.json",
            mime="application/json",
        )

    st.markdown('<div class="chart-title">REPORT SUMMARY</div>', unsafe_allow_html=True)
    st.code(json.dumps(info, indent=2), language="json")

    st.markdown('<div class="chart-title">PRINTABLE REPORTS</div>', unsafe_allow_html=True)
    html_col, pdf_col = st.columns(2)
    with html_col:
        st.download_button(
            "⤓ DOWNLOAD HTML",
            data=render_html(frame).encode("utf-8"),
            file_name=f"cloudsentinel_report_{stamp}.html",
            mime="text/html",
        )
    with pdf_col:
        try:
            pdf_bytes = render_pdf_bytes(frame)
        except RuntimeError as exc:
            st.info(str(exc))
        else:
            st.download_button(
                "⤓ DOWNLOAD PDF",
                data=pdf_bytes,
                file_name=f"cloudsentinel_report_{stamp}.pdf",
                mime="application/pdf",
            )


def _render_empty_state() -> None:
    st.markdown(
        """
        <div class="empty-state">
            <div class="empty-icon">🛡️</div>
            <div class="empty-title">NO TELEMETRY INDEXED</div>
            <div class="empty-copy">
                Drop generic JSON/JSONL audit logs (or an AWS CloudTrail dump) into
                <b>data/raw</b>, then run a detection scan — or load the built-in
                demo dataset to explore the console immediately.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def _footer() -> None:
    st.markdown(
        '<div class="cs-footer"><span>CLOUDSENTINEL v0.1.0</span>'
        "<span>SQLITE · PANDAS ENGINE · STREAMLIT</span></div>",
        unsafe_allow_html=True,
    )


# --------------------------------------------------------------------- charts


def _severity_donut(frame: pd.DataFrame) -> go.Figure:
    counts = frame["severity"].value_counts()
    labels, values, colors = [], [], []
    for severity in SEVERITY_ORDER:
        count = int(counts.get(severity.value, 0))
        if count:
            labels.append(severity.label)
            values.append(count)
            colors.append(severity.color)

    if not values:
        labels, values, colors = ["NO DATA"], [1], ["#1c2b40"]

    figure = go.Figure(
        go.Pie(
            labels=labels,
            values=values,
            hole=0.68,
            marker=dict(colors=colors, line=dict(color="#050810", width=2)),
            textinfo="percent",
            textfont=dict(family="Share Tech Mono, monospace", size=11),
            hovertemplate="%{label}: %{value} alerts<extra></extra>",
            sort=False,
        )
    )
    figure.update_layout(
        **_CHART_LAYOUT,
        height=290,
        showlegend=True,
        legend=dict(
            orientation="h", yanchor="bottom", y=-0.18, x=0.5, xanchor="center",
            font=dict(size=10),
        ),
    )
    figure.add_annotation(
        text=f"<b>{len(frame)}</b><br><span style='font-size:10px'>ALERTS</span>",
        x=0.5, y=0.5, showarrow=False,
        font=dict(family="Orbitron, sans-serif", size=22, color="#e6f1ff"),
    )
    return figure


def _timeline_chart(frame: pd.DataFrame) -> go.Figure:
    timeline = frame.copy()
    timeline["day"] = pd.to_datetime(timeline["last_seen"], utc=True).dt.date
    pivot = (
        timeline.groupby(["day", "severity"]).size().unstack(fill_value=0).sort_index()
    )

    figure = go.Figure()
    for severity in reversed(SEVERITY_ORDER):
        if severity.value not in pivot.columns:
            continue
        figure.add_bar(
            x=[str(day) for day in pivot.index],
            y=pivot[severity.value],
            name=severity.label,
            marker=dict(color=severity.color, line=dict(width=0)),
            hovertemplate=f"{severity.label}: %{{y}}<extra></extra>",
        )

    figure.update_layout(
        **_CHART_LAYOUT,
        height=290,
        barmode="stack",
        bargap=0.35,
        showlegend=True,
        legend=dict(orientation="h", yanchor="bottom", y=1.02, x=0, font=dict(size=10)),
        xaxis=dict(showgrid=False, tickfont=dict(size=10)),
        yaxis=dict(gridcolor="rgba(255,255,255,0.05)", zeroline=False, tickfont=dict(size=10)),
    )
    return figure


def _detector_chart(frame: pd.DataFrame) -> go.Figure:
    counts = frame["detector"].value_counts()
    names = [DETECTOR_LABELS.get(name, name) for name in counts.index][::-1]
    values = [int(value) for value in counts.values][::-1]

    figure = go.Figure(
        go.Bar(
            x=values,
            y=names,
            orientation="h",
            marker=dict(
                color=values,
                colorscale=[[0, "#123a52"], [0.5, "#00a8c8"], [1, "#00e5ff"]],
                line=dict(width=0),
            ),
            hovertemplate="%{y}: %{x} alerts<extra></extra>",
        )
    )
    figure.update_layout(
        **_CHART_LAYOUT,
        height=290,
        showlegend=False,
        xaxis=dict(gridcolor="rgba(255,255,255,0.05)", zeroline=False, dtick=1),
        yaxis=dict(showgrid=False, tickfont=dict(family="Share Tech Mono, monospace", size=10)),
    )
    return figure


# ------------------------------------------------------------------- fragments


def _apply_filters(frame: pd.DataFrame, window_label: str, search: str) -> pd.DataFrame:
    if frame.empty:
        return frame

    window = WINDOWS.get(window_label)
    if window is not None:
        cutoff = utcnow() - window
        frame = frame[frame["last_seen"] >= cutoff]

    if search and search.strip():
        needle = search.strip().lower()
        mask = (
            frame["entity"].astype(str).str.lower().str.contains(needle, regex=False)
            | frame["title"].astype(str).str.lower().str.contains(needle, regex=False)
            | frame["description"]
            .astype(str)
            .str.lower()
            .str.contains(needle, regex=False)
            | frame["detector"].astype(str).str.lower().str.contains(needle, regex=False)
        )
        frame = frame[mask]

    return frame


def _feed_html(frame: pd.DataFrame, limit: int = 200) -> str:
    rows = []
    for record in frame.head(limit).itertuples(index=False):
        severity = Severity.parse(record.severity)
        last_seen = record.last_seen
        timestamp = (
            last_seen.strftime("%d %b %Y · %H:%M UTC")
            if pd.notna(last_seen)
            else "—"
        )
        status = str(getattr(record, "status", "open") or "open").lower()
        rows.append(
            f"""
            <tr>
                <td><span class="badge {severity.value}">{severity.label}</span></td>
                <td><span class="pill status-{html.escape(status)}">{html.escape(status.upper())}</span></td>
                <td>
                    <div class="alert-title">{html.escape(str(record.title))}</div>
                    <div class="alert-desc">{html.escape(truncate(str(record.description), 220))}</div>
                </td>
                <td><span class="pill">{html.escape(DETECTOR_LABELS.get(str(record.detector), str(record.detector)))}</span></td>
                <td class="entity">{html.escape(str(record.entity))}</td>
                <td class="mono">{int(record.event_count)}</td>
                <td class="mono">{html.escape(timestamp)}</td>
            </tr>
            """
        )

    return f"""
    <div class="table-wrap">
        <table class="alert-table">
            <thead>
                <tr>
                    <th>SEVERITY</th><th>STATUS</th><th>FINDING</th>
                    <th>DETECTOR</th><th>ENTITY</th><th>EVENTS</th>
                    <th>LAST SEEN</th>
                </tr>
            </thead>
            <tbody>{''.join(rows)}</tbody>
        </table>
    </div>
    """


def _risk_list_html(frame: pd.DataFrame) -> str:
    scored = frame.copy()
    scored["_score"] = scored["severity"].map(
        lambda value: Severity.parse(value).score
    )
    grouped = (
        scored.groupby("entity")
        .agg(score=("_score", "sum"), alerts=("severity", "size"))
        .sort_values(["score", "alerts"], ascending=False)
        .head(6)
    )
    if grouped.empty:
        return '<div class="sys-card">No risk data.</div>'

    peak = max(1, int(grouped["score"].max()))
    rows = []
    for entity, row in grouped.iterrows():
        width = max(6, int(round(100 * row["score"] / peak)))
        rows.append(
            f'<div class="risk-row">'
            f'<div class="risk-entity" title="{html.escape(str(entity))}">{html.escape(str(entity))}</div>'
            f'<div class="risk-bar"><div class="risk-fill" style="width:{width}%"></div></div>'
            f'<div class="risk-score">{int(row["score"])} pts</div>'
            f"</div>"
        )
    return "".join(rows)


if __name__ == "__main__":
    main()
