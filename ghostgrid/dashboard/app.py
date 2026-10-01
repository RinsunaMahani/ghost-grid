"""GhostGrid SOC Screen - Real-Time OT Deception Dashboard.

Displays adversary sessions, early-warning alerts, MITRE ATT&CK for ICS mappings,
the critical 'Time Gained for SOC' metric, and live physical SCADA process telemetry.
Synchronizes with active decoy identity and live process state JSON.
Secured with operator password barrier.
"""
import json
import os
import sys
import time
from datetime import datetime
from typing import Optional
import pandas as pd
import streamlit as st

# Ensure repository root is on sys.path
current_dir = os.path.abspath(os.path.dirname(__file__))
ghostgrid_dir = os.path.dirname(current_dir)
repo_root = os.path.dirname(ghostgrid_dir)
for p in (repo_root, ghostgrid_dir):
    if p not in sys.path:
        sys.path.insert(0, p)

from ghostgrid.config import load_config
from ghostgrid.core.logger import EventLogger
from ghostgrid.core.identity import load_identity, SiteIdentity

# Page configuration
st.set_page_config(
    page_title="GhostGrid | OT SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Custom CSS for dark industrial SOC aesthetic
st.markdown("""
<style>
    .main { background-color: #0b0f19; }
    .kpi-card {
        background-color: #151c2c;
        border: 1px solid #23314d;
        border-radius: 8px;
        padding: 16px;
        margin-bottom: 12px;
    }
    .kpi-title { font-size: 0.85rem; color: #8fa0c0; text-transform: uppercase; letter-spacing: 0.05em; }
    .kpi-value { font-size: 1.8rem; font-weight: 700; color: #ffffff; }
    .kpi-sub { font-size: 0.75rem; color: #4ade80; }
    .alert-critical { color: #f87171; font-weight: bold; }
    .alert-high { color: #fb923c; font-weight: bold; }
    .alert-medium { color: #facc15; }
    .stTabs [data-baseweb="tab-list"] { gap: 12px; }
    .stTabs [data-baseweb="tab"] {
        background-color: #151c2c;
        border-radius: 4px;
        padding: 8px 16px;
        color: #94a3b8;
    }
    .stTabs [aria-selected="true"] {
        background-color: #1e293b !important;
        color: #38bdf8 !important;
        border-bottom: 2px solid #38bdf8 !important;
    }
</style>
""", unsafe_allow_html=True)


def check_auth() -> bool:
    """Operator password barrier to secure SOC screen from unauthorized network access."""
    configured_pwd = os.environ.get("GHOSTGRID_ADMIN_PASSWORD")
    if not configured_pwd:
        st.markdown("## 🔒 **GhostGrid Management Console - Access Denied**")
        st.error(
            "Security Configuration Error: `GHOSTGRID_ADMIN_PASSWORD` is not configured in the environment. "
            "For security reasons, access to the SOC console is disabled until an administrator password is set."
        )
        return False

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    if st.session_state.authenticated:
        return True

    st.markdown("## 🔒 **GhostGrid Management Console - Access Required**")
    st.info("Enter the SOC operator password to access telemetry, alerts, and forensics logs.")
    col1, col2 = st.columns([2, 1])
    with col1:
        pwd_input = st.text_input("Operator Password / Key", type="password")
        if st.button("Authenticate"):
            if pwd_input == configured_pwd:
                st.session_state.authenticated = True
                st.rerun()
            else:
                st.error("Invalid credentials.")
    return False


def get_live_identity() -> Optional[SiteIdentity]:
    """Load the exact active decoy identity from disk to match the running decoy."""
    id_path = os.environ.get("GHOSTGRID_IDENTITY_PATH", "ghostgrid_identity.json")
    return load_identity(id_path)


def get_live_state() -> dict:
    """Load latest telemetry exported by the decoy state engine."""
    state_path = os.environ.get("GHOSTGRID_STATE_PATH", "ghostgrid_state.json")
    if os.path.exists(state_path):
        try:
            with open(state_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {}


@st.cache_resource
def get_logger():
    cfg = load_config()
    db_path = os.environ.get("GHOSTGRID_DB_PATH", cfg.logging.db_path)
    # Open in read-only mode, without background worker or session cleanup
    return EventLogger(db_path=db_path, read_only=True, cleanup_stale_sessions=False)


def format_seconds(seconds: float) -> str:
    s = int(seconds)
    hours = s // 3600
    minutes = (s % 3600) // 60
    secs = s % 60
    if hours > 0:
        return f"{hours}h {minutes}m {secs}s"
    elif minutes > 0:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def main():
    if not check_auth():
        return

    identity = get_live_identity()
    if identity is None:
        st.title("🛡️ OT SOC Incident Detection & Deception Monitor")
        st.warning(
            "⚠️ **Decoy Not Running**: No active decoy identity file found at `ghostgrid_identity.json` "
            "(or `$GHOSTGRID_IDENTITY_PATH`). Please start the GhostGrid decoy process first."
        )
        if st.button("Retry Connection"):
            st.rerun()
        return

    logger = get_logger()
    live_state = get_live_state()

    # Sidebar
    with st.sidebar:
        st.markdown("### 🛡️ **GhostGrid Decoy Console**")
        st.markdown(f"**Facility:** `{identity.site_name}`")
        st.markdown(f"**Sector Profile:** `{identity.sector.upper()}`")
        st.markdown(f"**Emulated Device:** `{identity.vendor} {identity.model}`")
        st.markdown(f"**Firmware:** `{identity.firmware_version}`")
        st.markdown(f"**Serial / MAC:** `{identity.serial_number}` | `{identity.mac_address}`")
        st.markdown(f"**Security Zone:** `{identity.security_zone}`")
        st.markdown("---")

        auto_refresh = st.checkbox("Auto-refresh (2s)", value=True)
        if st.button("Refresh Telemetry"):
            st.rerun()

        st.markdown("---")
        st.caption("GhostGrid OT Deception Platform v1.2")

    # Header & Time Gained Banner
    st.title("🛡️ OT SOC Incident Detection & Deception Monitor")

    # Fetch SOC Metrics
    metrics = logger.get_soc_metrics()

    # Metric Cards Row
    c1, c2, c3, c4 = st.columns(4)

    with c1:
        time_gained = metrics.get("total_time_gained_seconds", 0.0)
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title">⏱️ Time Gained for SOC</div>
            <div class="kpi-value" style="color: #38bdf8;">{format_seconds(time_gained)}</div>
            <div class="kpi-sub">Adversary dwell time in decoy</div>
        </div>
        """, unsafe_allow_html=True)

    with c2:
        active_sess = metrics.get("active_sessions", 0)
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title">⚡ Active Adversary Sessions</div>
            <div class="kpi-value" style="color: {'#f87171' if active_sess > 0 else '#4ade80'};">{active_sess}</div>
            <div class="kpi-sub">Total logged: {metrics.get('total_sessions', 0)}</div>
        </div>
        """, unsafe_allow_html=True)

    with c3:
        total_reqs = metrics.get("total_requests", 0)
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title">🔍 Modbus Requests Logged</div>
            <div class="kpi-value">{total_reqs}</div>
            <div class="kpi-sub">PDU commands executed</div>
        </div>
        """, unsafe_allow_html=True)

    with c4:
        writes = metrics.get("total_writes", 0)
        st.markdown(f"""
        <div class="kpi-card">
            <div class="kpi-title">⚠️ Unauthorized Writes / Trips</div>
            <div class="kpi-value" style="color: {'#fb923c' if writes > 0 else '#8fa0c0'};">{writes}</div>
            <div class="kpi-sub">Coil / Register tamper events</div>
        </div>
        """, unsafe_allow_html=True)

    # Narrative Banner
    storyline = logger.get_latest_storyline()
    if storyline:
        st.markdown(f"""
        > 🤖 **Active Operational Narrative (Director):** **{storyline['title']}**  
        > *{storyline['narrative']}*
        """)

    # Main Tabs
    tab1, tab2, tab3, tab4 = st.tabs([
        "🚨 Incident Alerts & ATT&CK",
        "📡 Live Connection Sessions",
        "🎛️ Live SCADA Process Mimic",
        "🍯 Honeytoken Traps",
    ])

    # Tab 1: Alerts & ATT&CK
    with tab1:
        col_alerts, col_mitre = st.columns([3, 2])

        with col_alerts:
            st.subheader("Early-Warning Alarm Stream")
            alerts = logger.get_recent_alerts(limit=50)
            if alerts:
                alert_rows = []
                for a in alerts:
                    t_str = datetime.fromtimestamp(a["timestamp"]).strftime("%H:%M:%S")
                    alert_rows.append({
                        "Time": t_str,
                        "Severity": a["severity"],
                        "Alarm Type": a["alert_type"],
                        "Source IP": a.get("ip_address", "N/A"),
                        "Details": a["details"],
                        "ATT&CK Technique": a.get("mitre_technique", "N/A"),
                    })
                st.dataframe(pd.DataFrame(alert_rows), use_container_width=True, hide_index=True)
            else:
                st.success("No security alarms triggered. Perimeter quiet.")

        with col_mitre:
            st.subheader("MITRE ATT&CK for ICS Mappings")
            st.markdown("""
            | Detected Activity | ICS ATT&CK ID | Technique Name |
            | :--- | :--- | :--- |
            | Modbus Function Scanning | **T0846** | Remote System Discovery |
            | Register Probing & Brute-force | **T0842** | Point Discovery |
            | Honeytoken Access Trap | **T0886** | Remote Service Discovery |
            | Unauthorized Coil/Register Write | **T0836** | Modify Parameter / State |
            | High Frequency Burst Polling | **T0814** | Denial of Service |
            """)

    # Tab 2: Sessions
    with tab2:
        st.subheader("Active & Historic Modbus TCP Adversary Sessions")
        sessions = logger.get_recent_sessions(limit=50)
        if sessions:
            sess_rows = []
            for s in sessions:
                start_t = datetime.fromtimestamp(s["start_time"]).strftime("%Y-%m-%d %H:%M:%S")
                duration = s.get("duration_seconds", 0.0)
                status = "🔴 ACTIVE" if s.get("is_active") else "⚪ Closed"
                sess_rows.append({
                    "Session ID": s["session_id"][:8],
                    "Source IP": s["ip_address"],
                    "Port": s["port"],
                    "Status": status,
                    "Start Time": start_t,
                    "Duration": format_seconds(duration),
                    "Requests": s["request_count"],
                    "Writes": s["write_count"],
                    "Honeytokens": s["honeytoken_count"],
                })
            st.dataframe(pd.DataFrame(sess_rows), use_container_width=True, hide_index=True)
        else:
            st.info("No Modbus client sessions recorded yet.")

    # Tab 3: Process Mimic
    with tab3:
        st.subheader(f"Substation Process Telemetry Mimic: {identity.site_name}")
        col_m1, col_m2, col_m3 = st.columns(3)

        if identity.sector == "water":
            level = live_state.get("RESERVOIR_LEVEL_PCT", 745) / 10.0
            inflow = live_state.get("INFLOW_RATE_M3_HR", 1820)
            outflow = live_state.get("OUTFLOW_RATE_M3_HR", 1750)
            p1_stat = "RUNNING" if live_state.get("PUMP_1_RUNNING", 1) else "STOPPED"
            p2_stat = "BOOSTER ACTIVE" if live_state.get("PUMP_2_RUNNING", 0) else "STANDBY"
            press = live_state.get("DISCHARGE_PRESSURE_BAR", 620) / 100.0
            chlor = live_state.get("CHLORINE_RESIDUAL_PPM", 180) / 100.0
            turb = live_state.get("TURBIDITY_NTU", 45) / 100.0
            ph = live_state.get("WATER_PH", 740) / 100.0

            with col_m1:
                st.markdown("### 💧 Reservoir & Storage")
                st.metric("Reservoir Level", f"{level:.1f} %", delta=f"{inflow - outflow:+d} m³/h net")
                st.progress(min(max(level / 100.0, 0.0), 1.0))
                st.metric("Discharge Pressure", f"{press:.2f} bar")

            with col_m2:
                st.markdown("### ⚙️ Intake & Booster Pumps")
                st.metric("Pump 1 (Main)", p1_stat)
                st.metric("Pump 2 (Booster)", p2_stat)
                st.metric("Raw Inflow Rate", f"{inflow} m³/h")
                st.metric("Treated Outflow Rate", f"{outflow} m³/h")

            with col_m3:
                st.markdown("### 🧪 Water Quality (SANS 241)")
                st.metric("Chlorine Residual", f"{chlor:.2f} mg/L", delta="Compliant (0.5 - 2.0)")
                st.metric("Turbidity", f"{turb:.2f} NTU", delta="Target: < 1.0 NTU")
                st.metric("Water pH", f"{ph:.2f} pH")

        else: # Power
            freq = live_state.get("GRID_FREQUENCY_HZ", 5002) / 100.0
            v_bus = live_state.get("BUS_VOLTAGE_KV", 883) / 10.0
            i1 = live_state.get("FEEDER_1_CURRENT_A", 175)
            i2 = live_state.get("FEEDER_2_CURRENT_A", 155)
            p_mw = live_state.get("ACTIVE_POWER_MW", 462) / 10.0
            q_mvar = live_state.get("REACTIVE_POWER_MVAR", 124) / 10.0
            tx_temp = live_state.get("TRANSFORMER_TEMP_C", 584) / 10.0
            tap = live_state.get("VOLTAGE_REGULATOR_TAP", 8)
            sync = "IN SYNCHRONISM" if live_state.get("GRID_SYNC_CHECK", 1) else "OUT OF SYNC"

            with col_m1:
                st.markdown("### ⚡ Grid Frequency (SA Grid Code)")
                st.metric("System Frequency", f"{freq:.2f} Hz", delta="Nominal 50.00 Hz")
                st.metric("NERSA Lower Reserve Limit", "49.85 Hz")
                st.metric("Synchro-Check Status", sync)

            with col_m2:
                st.markdown("### 🔌 88kV Bus & Feeders")
                st.metric("Bus Voltage", f"{v_bus:.1f} kV")
                st.metric("Feeder 1 Current", f"{i1} A")
                st.metric("Feeder 2 Current", f"{i2} A")
                st.metric("Tap Changer Position", f"Tap {tap}")

            with col_m3:
                st.markdown("### 📈 Power & Transformers")
                st.metric("Active Power (P)", f"{p_mw:.1f} MW")
                st.metric("Reactive Power (Q)", f"{q_mvar:.1f} MVAr")
                st.metric("Tx Winding Temp", f"{tx_temp:.1f} °C", delta="Normal (< 85°C)")

    # Tab 4: Honeytoken Traps
    with tab4:
        st.subheader("Active Reconnaissance Honeytokens")
        ht_tags = [t for t in identity.tags.values() if t.is_honeytoken]
        ht_data = []
        for t in ht_tags:
            ht_data.append({
                "Tag Name": t.name,
                "Type": t.reg_type.value,
                "Modbus Offset": t.address,
                "Default Value": hex(t.default_value) if isinstance(t.default_value, int) else t.default_value,
                "Trap Description": t.description,
            })
        st.dataframe(pd.DataFrame(ht_data), use_container_width=True, hide_index=True)

    if auto_refresh:
        time.sleep(2)
        st.rerun()


if __name__ == "__main__":
    main()
