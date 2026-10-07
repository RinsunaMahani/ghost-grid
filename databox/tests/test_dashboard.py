"""Smoke test for the live view: load the page, start a run, let the fault happen, stop it."""
import time
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

APP = str(Path(__file__).resolve().parents[1] / "dashboard" / "app.py")


def test_live_view_runs_a_scenario_end_to_end():
    at = AppTest.from_file(APP, default_timeout=15).run()
    assert not at.exception
    assert at.info, "an empty page should ask the user to start a run"

    at.selectbox(key="scenario").set_value("alter")
    at.slider(key="fault_at").set_value(3)
    at.run()
    at.button(key="start").click().run()
    assert not at.exception

    time.sleep(4.5)   # past the 3 s fault start, so altered frames have been caught
    at.run()
    assert not at.exception
    labels = {m.label: m.value for m in at.metric}
    assert int(labels["Frames sent"].replace(",", "")) > 0
    assert int(labels["Alarms"].replace(",", "")) > 0
    assert any("Fault active" in md.value for md in at.markdown)

    at.button(key="stop").click().run()
    assert not at.exception
    assert any("Stopped" in md.value for md in at.markdown)


def test_after_a_ransomware_freeze_the_operator_rolls_back_from_the_page():
    at = AppTest.from_file(APP, default_timeout=15).run()
    at.selectbox(key="scenario").set_value("ransomware")
    at.slider(key="fault_at").set_value(3)
    at.run()
    at.button(key="start").click().run()
    sim = at.session_state["sim"]
    try:
        deadline = time.monotonic() + 15
        while not sim.vault.frozen and time.monotonic() < deadline:
            time.sleep(0.1)
        assert sim.vault.frozen
        at.run()
        assert any("Recovery opens when the run stops" in c.value for c in at.caption)

        at.button(key="stop").click().run()
        assert not at.exception
        at.button(key="recover").click().run()
        assert not at.exception
        assert any("Rolled back" in s.value for s in at.success)
        assert not sim.vault.frozen
    finally:
        sim.close()


def test_a_link_starts_its_scenario_and_the_sidebar_follows():
    at = AppTest.from_file(APP, default_timeout=15)
    at.query_params["start"] = "ransomware"
    at.query_params["fault"] = "1"        # below the slider's range: the run and the sidebar both use 3
    at.query_params["length"] = "44"      # snapped to the slider's 10-second steps: 40
    at.run()
    try:
        assert not at.exception
        assert at.selectbox(key="scenario").value == "ransomware"
        assert at.slider(key="fault_at").value == 3
        assert at.session_state["sim"].fault_at_s == 3
        assert at.slider(key="length").value == 40
        assert at.session_state["sim"].auto_stop_s == 40
        assert any("Running" in md.value for md in at.markdown)
    finally:
        at.button(key="stop").click().run()
