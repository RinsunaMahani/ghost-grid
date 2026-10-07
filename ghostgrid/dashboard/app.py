"""GhostGrid SOC Screen - Real-Time OT Deception Dashboard.

Displays adversary sessions, early-warning alerts, MITRE ATT&CK for ICS mappings,
the critical 'Time Gained for SOC' metric, and live physical SCADA process telemetry.
Synchronizes with active decoy identity and live process state JSON.
Secured with operator password barrier.
"""
import hmac
import json
import os
import sys
import threading
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

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
from ghostgrid.dashboard.export import evidence_csv

# Live values older than this mean the decoy's physics loop has stopped writing them.
STALE_AFTER_SECONDS = 15.0
REFRESH_SECONDS = 2
# Login throttling: after this many wrong passwords in the window, refuse attempts until it passes.
MAX_FAILED_LOGINS = 5
FAILED_LOGIN_WINDOW_SECONDS = 60.0
FAILED_LOGIN_DELAY_SECONDS = 1.0
# Evidence exports hold every record, not just the rows a table shows (in practice: all of them).
EXPORT_ROW_LIMIT = 100_000

st.set_page_config(
    page_title="GhostGrid | OT SOC Console",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

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
</style>
""", unsafe_allow_html=True)


# ------------------------------------------------------------------------------
# Data access
# ------------------------------------------------------------------------------

def check_auth() -> bool:
    """Operator password barrier; refuses to open at all when no password is configured."""
    configured_pwd = os.environ.get("GHOSTGRID_ADMIN_PASSWORD")
    if not configured_pwd:
        st.markdown("## 🔒 **GhostGrid Management Console - Access Denied**")
        st.error(
            "`GHOSTGRID_ADMIN_PASSWORD` is not set. The SOC console stays locked until an "
            "operator password is configured in the environment."
        )
        return False

    if st.session_state.get("authenticated"):
        return True

    st.markdown("## 🔒 **GhostGrid Management Console - Access Required**")
    st.info("Enter the SOC operator password to access telemetry, alerts and forensics logs.")
    guard = login_guard()
    col1, _ = st.columns([2, 1])
    with col1:
        pwd_input = st.text_input("Operator password", type="password")
        if st.button("Authenticate"):
            wait = guard.locked_for()
            if wait > 0:
                st.error(f"Too many failed attempts. Try again in {wait:.0f} s.")
            elif hmac.compare_digest(pwd_input.encode("utf-8"), configured_pwd.encode("utf-8")):
                st.session_state.authenticated = True
                st.rerun()
            else:
                guard.record_failure()
                time.sleep(FAILED_LOGIN_DELAY_SECONDS)     # slows guessing even below the lockout
                st.error("Invalid credentials.")
    return False


class LoginGuard:
    """Failed logins shared by every browser session, so reloading the page doesn't reset the count."""

    def __init__(self, max_failures: int, window_s: float):
        self.max_failures = max_failures
        self.window_s = window_s
        self._failures: list = []
        self._lock = threading.Lock()

    def _recent(self, now: float) -> list:
        self._failures = [t for t in self._failures if now - t < self.window_s]
        return self._failures

    def record_failure(self) -> None:
        with self._lock:
            self._recent(time.time()).append(time.time())

    def locked_for(self) -> float:
        """Seconds until the next attempt is allowed; 0 when not locked."""
        with self._lock:
            now = time.time()
            recent = self._recent(now)
            if len(recent) < self.max_failures:
                return 0.0
            return max(0.0, self.window_s - (now - recent[-self.max_failures]))


@st.cache_resource
def login_guard() -> LoginGuard:
    return LoginGuard(MAX_FAILED_LOGINS, FAILED_LOGIN_WINDOW_SECONDS)


def get_live_identity() -> Optional[SiteIdentity]:
    """The identity the running decoy saved; None if the decoy has never started here."""
    return load_identity(os.environ.get("GHOSTGRID_IDENTITY_PATH", "ghostgrid_identity.json"))


def get_live_state() -> Tuple[Dict[str, Any], Optional[float]]:
    """Latest raw register values exported by the decoy, and their age in seconds."""
    state_path = os.environ.get("GHOSTGRID_STATE_PATH", "ghostgrid_state.json")
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            state = json.load(f)
    except (OSError, ValueError):
        return {}, None
    ts = state.get("_timestamp")
    age = (time.time() - float(ts)) if isinstance(ts, (int, float)) else None
    return state, age


@st.cache_resource
def _open_logger(db_path: str) -> EventLogger:
    # Read-only: the dashboard never writes, never runs session clean-up, never starts a writer thread.
    return EventLogger(db_path=db_path, read_only=True, cleanup_stale_sessions=False)


def get_logger() -> EventLogger:
    db_path = os.environ.get("GHOSTGRID_DB_PATH") or load_config().logging.db_path
    return _open_logger(db_path)


# ------------------------------------------------------------------------------
# Formatting helpers
# ------------------------------------------------------------------------------

def format_seconds(seconds: float) -> str:
    s = int(seconds or 0)
    hours, minutes, secs = s // 3600, (s % 3600) // 60, s % 60
    if hours:
        return f"{hours}h {minutes}m {secs}s"
    if minutes:
        return f"{minutes}m {secs}s"
    return f"{secs}s"


def format_time(ts: Optional[float], with_date: bool = False) -> str:
    if not ts:
        return "-"
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S" if with_date else "%H:%M:%S")


class TagReader:
    """Turns raw register values into engineering values using each tag's own scale and unit."""

    def __init__(self, identity: SiteIdentity, state: Dict[str, Any]):
        self.identity = identity
        self.state = state

    def raw(self, name: str) -> Optional[int]:
        val = self.state.get(name)
        return int(val) if isinstance(val, (int, float)) else None

    def value(self, name: str) -> Optional[float]:
        raw = self.raw(name)
        tag = self.identity.tags.get(name)
        if raw is None or tag is None:
            return None
        return raw * tag.scale_factor

    def text(self, name: str) -> str:
        """'1,787 m3/h', '79.7 %', '6.00 bar' or 'n/a' when the decoy hasn't reported it."""
        val = self.value(name)
        tag = self.identity.tags.get(name)
        if val is None or tag is None:
            return "n/a"
        decimals = 0 if tag.scale_factor >= 1 else (1 if tag.scale_factor >= 0.1 else 2)
        unit = f" {tag.engineering_unit}" if tag.engineering_unit else ""
        return f"{val:,.{decimals}f}{unit}"

    def flag(self, name: str, on: str, off: str) -> str:
        raw = self.raw(name)
        return "n/a" if raw is None else (on if raw else off)


# ------------------------------------------------------------------------------
# Page sections
# ------------------------------------------------------------------------------

def render_kpis(metrics: Dict[str, Any]):
    c1, c2, c3, c4 = st.columns(4)
    active = metrics.get("active_sessions", 0)
    writes = metrics.get("total_writes", 0)
    cards = [
        (c1, "⏱️ Time Gained for SOC", format_seconds(metrics.get("total_time_gained_seconds", 0.0)),
         "#38bdf8", "Attacker time spent in the decoy"),
        (c2, "⚡ Active Adversary Sessions", f"{active}", "#f87171" if active else "#4ade80",
         f"Total logged: {metrics.get('total_sessions', 0)}"),
        (c3, "🔍 Modbus Requests Logged", f"{metrics.get('total_requests', 0):,}", "#ffffff",
         "Including rejected probes"),
        (c4, "⚠️ Unauthorized Writes", f"{writes:,}", "#fb923c" if writes else "#8fa0c0",
         "Coil / register tamper attempts"),
    ]
    for col, title, value, colour, sub in cards:
        with col:
            st.markdown(f"""
            <div class="kpi-card">
                <div class="kpi-title">{title}</div>
                <div class="kpi-value" style="color: {colour};">{value}</div>
                <div class="kpi-sub">{sub}</div>
            </div>
            """, unsafe_allow_html=True)


def render_alerts(logger: EventLogger):
    col_alerts, col_mitre = st.columns([3, 2])
    with col_alerts:
        st.subheader("Early-Warning Alarm Stream")
        alerts = logger.get_recent_alerts(limit=50)
        if alerts:
            st.dataframe(pd.DataFrame([{
                "Time": format_time(a.get("timestamp")),
                "Severity": a.get("severity"),
                "Alarm Type": a.get("alert_type"),
                "Source IP": a.get("client_ip", "n/a"),
                "Details": a.get("description", ""),
                "ATT&CK Technique": a.get("mitre_technique", "n/a"),
            } for a in alerts]), width="stretch", hide_index=True)
            export_button("Export all alerts (CSV)", lambda: logger.get_recent_alerts(limit=EXPORT_ROW_LIMIT),
                          "alerts")
        else:
            st.success("No security alarms triggered. Perimeter quiet.")

    with col_mitre:
        st.subheader("MITRE ATT&CK for ICS Mappings")
        st.markdown("""
        | Detected Activity | ICS ATT&CK ID | Technique Name |
        | :--- | :--- | :--- |
        | First connection / scanning | **T0846** | Remote System Discovery |
        | Honeytoken read | **T0861** | Point & Tag Identification |
        | Honeytoken write | **T0836** | Modify Parameter |
        | Unauthorized coil / register write | **T0855** | Unauthorized Command Message |
        """)


def render_sessions(logger: EventLogger):
    st.subheader("Modbus TCP Sessions")
    sessions = logger.get_all_sessions(limit=50)
    if not sessions:
        st.info("No Modbus client sessions recorded yet.")
        return
    now = time.time()
    st.dataframe(pd.DataFrame([{
        "Session": s["session_id"][:8],
        "Source IP": s.get("client_ip"),
        "Port": s.get("client_port"),
        "Status": "ACTIVE" if s.get("is_active") else "Closed",
        "Started": format_time(s.get("started_at"), with_date=True),
        "Duration": format_seconds((now - s["started_at"]) if s.get("is_active") else s.get("duration_seconds", 0.0)),
        "Requests": s.get("total_requests", 0),
        "Writes": s.get("total_writes", 0),
        "Honeytoken hits": s.get("honeytoken_hits", 0),
    } for s in sessions]), width="stretch", hide_index=True)
    export_button("Export all sessions (CSV)", lambda: logger.get_all_sessions(limit=EXPORT_ROW_LIMIT), "sessions")

    st.subheader("Latest Attacker Commands")
    requests_ = logger.get_recent_requests(limit=100)
    if requests_:
        st.dataframe(pd.DataFrame([{
            "Time": format_time(r.get("timestamp")),
            "Source IP": r.get("client_ip"),
            "Function": r.get("function_name"),
            "Address": r.get("address"),
            "Count": r.get("count"),
            "Tag": r.get("tag_name") or "",
            "Values": r.get("values_json"),
            "Result": r.get("response_status"),
            "Honeytoken": "YES" if r.get("is_honeytoken") else "",
        } for r in requests_]), width="stretch", hide_index=True)
        export_button("Export all commands (CSV)", lambda: logger.get_recent_requests(limit=EXPORT_ROW_LIMIT),
                      "commands")


def export_button(label: str, fetch: Callable[[], List[Dict[str, Any]]], name: str) -> None:
    """A download of the full records behind a table. The CSV is only built when clicked."""
    st.download_button(label, data=lambda: evidence_csv(fetch()),
                       file_name=f"ghostgrid-{name}-{datetime.now():%Y%m%d}.csv", mime="text/csv",
                       icon=":material/download:", on_click="ignore", key=f"export-{name}")


def render_process(identity: SiteIdentity, state: Dict[str, Any], age: Optional[float]):
    st.subheader(f"Process Telemetry: {identity.site_name}")
    if not state:
        st.warning("No live values yet: the decoy hasn't written its state file.")
        return
    if age is not None and age > STALE_AFTER_SECONDS:
        st.warning(f"Live values are stale: last update {format_seconds(age)} ago. "
                   "The decoy's physics loop may have stopped.")

    t = TagReader(identity, state)
    col1, col2, col3 = st.columns(3)
    if identity.sector == "water":
        inflow, outflow = t.raw("INFLOW_RATE_M3H"), t.raw("OUTFLOW_RATE_M3H")
        net = f"{inflow - outflow:+,d} m3/h net" if inflow is not None and outflow is not None else None
        with col1:
            st.markdown("### 💧 Reservoir")
            st.metric("Reservoir level", t.text("RESERVOIR_LEVEL_PCT"), delta=net)
            level = t.value("RESERVOIR_LEVEL_PCT")
            if level is not None:
                st.progress(min(max(level / 100.0, 0.0), 1.0))
            st.metric("Level setpoint", t.text("LEVEL_SETPOINT_PCT"))
            st.metric("Alarm limits (low / high)",
                      f"{t.text('LOW_LEVEL_ALARM_LIMIT')} / {t.text('HIGH_LEVEL_ALARM_LIMIT')}")
        with col2:
            st.markdown("### ⚙️ Pumps & Flow")
            st.metric("Pump 1 (main)", t.flag("PUMP_1_TRIP", "TRIPPED", t.flag("PUMP_1_RUNNING", "RUNNING", "STOPPED")))
            st.metric("Pump 2 (booster)", t.flag("PUMP_2_RUNNING", "RUNNING", "STANDBY"))
            st.metric("Inflow", t.text("INFLOW_RATE_M3H"))
            st.metric("Outflow", t.text("OUTFLOW_RATE_M3H"))
            st.metric("Discharge pressure", t.text("DISCHARGE_PRESSURE_BAR"),
                      delta=f"setpoint {t.text('PRESSURE_SETPOINT_BAR')}", delta_color="off")
        with col3:
            st.markdown("### 🧪 Water Quality (SANS 241)")
            st.metric("Chlorine residual", t.text("CHLORINE_RESIDUAL_PPM"), delta="Target 0.5 - 2.0 mg/L", delta_color="off")
            st.metric("Turbidity", t.text("TURBIDITY_NTU"), delta="Target < 1.0 NTU", delta_color="off")
            st.metric("pH", t.text("WATER_PH"))
            st.metric("Emergency shutdown", t.flag("EMERGENCY_SHUTDOWN_CMD", "ACTIVE", "Normal"))
    else:
        with col1:
            st.markdown("### ⚡ Grid Frequency")
            st.metric("System frequency", t.text("GRID_FREQUENCY_HZ"), delta="Nominal 50.00 Hz", delta_color="off")
            st.metric("Under-frequency load shed (stage 1)", t.text("UNDERFREQ_LOADSHED_STAGE1_HZ"))
            st.metric("Synchro-check", t.flag("GRID_SYNC_CHECK", "IN SYNC", "OUT OF SYNC"))
        with col2:
            st.markdown("### 🔌 Bus & Feeders")
            st.metric("Bus voltage", t.text("BUS_VOLTAGE_KV"))
            st.metric("Feeder 1", f"{t.text('FEEDER_1_CURRENT_A')} ({t.flag('FEEDER_1_CB_STATUS', 'closed', 'OPEN')})")
            st.metric("Feeder 2", f"{t.text('FEEDER_2_CURRENT_A')} ({t.flag('FEEDER_2_CB_STATUS', 'closed', 'OPEN')})")
            st.metric("Tap changer", t.text("VOLTAGE_REGULATOR_TAP"))
        with col3:
            st.markdown("### 📈 Power & Transformer")
            st.metric("Active power", t.text("ACTIVE_POWER_MW"))
            st.metric("Reactive power", t.text("REACTIVE_POWER_MVAR"))
            st.metric("Transformer winding temp", t.text("TRANSFORMER_TEMP_C"), delta="Alarm > 85 °C", delta_color="off")
            st.metric("Buchholz / earth fault",
                      f"{t.flag('TRANSFORMER_BUCHHOLZ_ALARM', 'GAS ALARM', 'ok')} / {t.flag('EARTH_FAULT_ALARM', 'FAULT', 'ok')}")

    with st.expander("All registers as the attacker sees them"):
        st.dataframe(pd.DataFrame([{
            "Tag": tag.name,
            "Type": tag.reg_type.value,
            "Address": tag.address,
            "Raw": t.raw(tag.name),
            "Value": t.text(tag.name),
            "Honeytoken": "YES" if tag.is_honeytoken else "",
        } for tag in sorted(identity.tags.values(), key=lambda x: (x.reg_type.value, x.address))]),
            width="stretch", hide_index=True)


def render_honeytokens(identity: SiteIdentity):
    st.subheader("Armed Honeytokens")
    st.dataframe(pd.DataFrame([{
        "Tag": t.name,
        "Type": t.reg_type.value,
        "Modbus address": t.address,
        "Bait value": hex(t.default_value) if isinstance(t.default_value, int) else t.default_value,
        "Description": t.description,
    } for t in identity.tags.values() if t.is_honeytoken]), width="stretch", hide_index=True)


def render_live(identity: SiteIdentity):
    """Everything that refreshes: metrics, alerts, sessions and process values."""
    logger = get_logger()
    state, age = get_live_state()

    render_kpis(logger.get_soc_metrics())

    storyline = logger.get_latest_storyline()
    if storyline:
        st.markdown(f"> 🤖 **Operational narrative (director):** **{storyline['title']}**  \n"
                    f"> *{storyline['narrative']}*")

    tab1, tab2, tab3, tab4 = st.tabs([
        "🚨 Alerts & ATT&CK", "📡 Sessions & Commands", "🎛️ Process View", "🍯 Honeytokens",
    ])
    with tab1:
        render_alerts(logger)
    with tab2:
        render_sessions(logger)
    with tab3:
        render_process(identity, state, age)
    with tab4:
        render_honeytokens(identity)


def main():
    if not check_auth():
        return

    st.title("🛡️ OT SOC Incident Detection & Deception Monitor")

    identity = get_live_identity()
    if identity is None:
        st.warning(
            "⚠️ Decoy not running: no decoy identity file at `ghostgrid_identity.json` "
            "(or `$GHOSTGRID_IDENTITY_PATH`). Start the GhostGrid decoy first."
        )
        if st.button("Check again"):
            st.rerun()
        return

    with st.sidebar:
        st.markdown("### 🛡️ **GhostGrid Decoy Console**")
        st.markdown(f"**Facility:** `{identity.site_name}`")
        st.markdown(f"**Sector:** `{identity.sector.upper()}`")
        st.markdown(f"**Emulated device:** `{identity.vendor} {identity.model}`")
        st.markdown(f"**Firmware:** `{identity.firmware_version}`")
        st.markdown(f"**Serial / MAC:** `{identity.serial_number}` | `{identity.mac_address}`")
        st.markdown(f"**Security zone:** `{identity.security_zone}`")
        st.markdown("---")
        auto_refresh = st.checkbox(f"Auto-refresh ({REFRESH_SECONDS}s)", value=True, key="auto_refresh")
        st.markdown("---")
        st.caption("GhostGrid OT Deception Platform")

    # A fragment refreshes only the live section, instead of sleeping and rerunning the whole page.
    st.fragment(run_every=REFRESH_SECONDS if auto_refresh else None)(render_live)(identity)


if __name__ == "__main__":
    main()
