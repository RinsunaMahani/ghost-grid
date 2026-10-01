"""Live view of the sealed data box simulation.

    python -m streamlit run databox/dashboard/app.py --server.address 127.0.0.1

A link like http://localhost:8501/?start=ransomware&fault=3 starts a scenario as
soon as the page opens.
"""
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

import streamlit as st

from databox.dashboard.views import alarm_lines, timing_chart, track_html
from databox.simulation import SCENARIOS, Simulation

st.set_page_config(page_title="Data box live view", page_icon=":material/lock:", layout="wide")

if "sim" not in st.session_state:
    st.session_state.sim = None
if "fault_at" not in st.session_state:
    st.session_state.fault_at = 7     # set here rather than as the slider's default, so a link can change it


def start_run(scenario: str, fault_at: float, length: float) -> None:
    if st.session_state.sim is not None:
        st.session_state.sim.stop()
    st.session_state.sim = Simulation(scenario, fault_at_s=fault_at, out=lambda line: None,
                                      auto_stop_s=length).start()


def stop_run() -> None:
    if st.session_state.sim is not None:
        st.session_state.sim.stop()


if st.session_state.sim is None and st.query_params.get("start") in SCENARIOS:
    try:
        link_fault_at = min(20, max(3, round(float(st.query_params.get("fault", 7)))))   # the slider's range
    except (ValueError, OverflowError):
        link_fault_at = 7
    start_run(st.query_params["start"], link_fault_at, 120)
    st.session_state.scenario = st.query_params["start"]          # keep the sidebar in step with the link
    st.session_state.fault_at = link_fault_at

with st.sidebar:
    st.header("Run a scenario")
    scenario = st.selectbox("Scenario", list(SCENARIOS), key="scenario")
    st.caption(SCENARIOS[scenario])
    fault_at = st.slider("Fault starts after (seconds)", 3, 20, key="fault_at")
    length = st.slider("Run for (seconds)", 20, 300, 90, step=10, key="length")
    with st.container(horizontal=True):
        st.button("Start", type="primary", icon=":material/play_arrow:", key="start",
                  on_click=start_run, args=(scenario, fault_at, length))
        st.button("Stop", icon=":material/stop:", key="stop", on_click=stop_run)
    st.caption("The box holds the private signing key. The monitoring room holds only the public key, "
               "so it can check every frame but never forge or send one.")

st.title("Sealed data box: live view")


@st.fragment(run_every=1.0)
def live_view() -> None:
    sim = st.session_state.sim
    if sim is None:
        st.info("Pick a scenario in the sidebar and press Start.", icon=":material/play_circle:")
        return

    s = sim.status()
    dark = st.context.theme.type == "dark"

    state = (":green-badge[:material/play_circle: Running]" if s["running"]
             else ":gray-badge[:material/stop_circle: Stopped]")
    if sim.scenario == "normal":
        phase = ":blue-badge[:material/check_circle: No fault in this scenario]"
    elif s["fault_active"]:
        phase = f":orange-badge[:material/bolt: Fault active since {sim.fault_at_s:.0f} s]"
    else:
        phase = f":blue-badge[:material/school: Learning normal lap times, fault at {sim.fault_at_s:.0f} s]"
    st.markdown(f"{state} {phase} **{sim.scenario}** · {s['elapsed']:.0f} s elapsed")
    st.caption(SCENARIOS[sim.scenario])

    if s["shutdown_announced"]:
        monitor_state = "announced"
    elif s["monitor_silent"]:
        monitor_state = "silent"
    elif any(source == "monitor" for source, _ in s["alarm_counts"]):
        monitor_state = "alarm"
    else:
        monitor_state = "ok"
    tap = sim.scenario if s["fault_active"] and sim.scenario in ("delay", "drop", "alter") else None

    with st.container(border=True):
        st.html(track_html(
            dark=dark, running=s["running"], tap=tap, box_state=s["box_state"],
            vault_frozen=s["vault_frozen"], canary_opened=s["canary_trips"] > 0,
            monitor_state=monitor_state, battery_bucket=int(round(s["battery_pct"], -1)),
        ))
        st.caption("Each dot is a signed frame lapping the fibre loop. The box checks that every frame comes back "
                   "unchanged and on time; the monitoring room's passive tap verifies and times each one as it passes.")

    with st.container(horizontal=True):
        st.metric("Frames sent", f"{s['frames_sent']:,}", border=True)
        st.metric("Verified by the monitor", f"{s['frames_verified']:,}", border=True)
        lap = s["lap_median_ms"]
        st.metric("Box lap time (median)", "learning" if lap is None else f"{lap:.2f} ms", border=True)
        st.metric("Vault", "Frozen" if s["vault_frozen"] else f"{s['vault_files']} files", border=True)
        st.metric("Battery", f"{s['battery_pct']:.0f}%", border=True)
        st.metric("Alarms", f"{sum(s['alarm_counts'].values()):,}", border=True)

    chart_col, feed_col = st.columns([3, 2])
    with chart_col, st.container(border=True):
        st.markdown("**Lap and delivery times**")
        limit = s["lap_limit_ms"] or s["delivery_limit_ms"]
        fault_at_s = sim.fault_at_s if sim.scenario != "normal" else None
        st.altair_chart(timing_chart(sim.lap_times(), sim.delivery_times(), limit, fault_at_s, dark))
    with feed_col, st.container(border=True, height=372):
        st.markdown("**Alarm feed**")
        lines = alarm_lines(sim.alarms())
        if lines:
            st.markdown("  \n".join(lines))
        else:
            st.caption("No alarms.")
        if s["vault_frozen"]:
            st.caption(f"Vault frozen: {s['freeze_reason']}. In a real box the operator now reviews "
                       "and rolls back with the restore tool.")


live_view()
