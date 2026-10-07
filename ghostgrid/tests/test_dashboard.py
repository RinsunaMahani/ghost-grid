"""Smoke tests for the SOC dashboard, run against a decoy database with real activity in it."""
import json
import time
from pathlib import Path

import pytest

pytest.importorskip("streamlit")
from streamlit.testing.v1 import AppTest

from ghostgrid.core.identity import generate_site_identity, save_identity
from ghostgrid.core.logger import EventLogger
from ghostgrid.profiles import create_profile

APP = str(Path(__file__).resolve().parents[1] / "dashboard" / "app.py")
PASSWORD = "test-operator-pass"


def _write_state(path, identity, age_seconds=0.0):
    profile = create_profile(identity.sector, identity, noise_amplitude=0.0)
    state = profile.step(1.0, profile.initialize_state())
    state["_sector"] = identity.sector
    state["_site_name"] = identity.site_name
    state["_timestamp"] = time.time() - age_seconds
    with open(path, "w", encoding="utf-8") as f:
        json.dump(state, f)
    return state


def _populate_db(db_path, identity):
    """One attacker visit: a read, a setpoint write and a honeytoken read."""
    logger = EventLogger(db_path, alert_threshold_writes=1, alert_threshold_scans=2)
    ip = "10.20.30.40"
    sid = logger.start_session(ip, 50111, 1)
    sp = identity.tags["LEVEL_SETPOINT_PCT"] if identity.sector == "water" else identity.tags["VOLTAGE_REGULATOR_TAP"]
    ht = next(t for t in identity.tags.values() if t.is_honeytoken and t.reg_type.value == "holding_register")
    logger.log_request(sid, 3, "Read Holding Registers", sp.address, 1, [sp.default_value], 0.2, "SUCCESS", sp.name, False, ip)
    logger.log_request(sid, 6, "Write Single Register", sp.address, 1, 900, 0.2, "SUCCESS", sp.name, False, ip)
    logger.log_request(sid, 3, "Read Holding Registers", ht.address, 1, [ht.default_value], 0.2, "SUCCESS", ht.name, True, ip)
    logger.end_session(sid)
    logger.close()


@pytest.fixture
def decoy_files(tmp_path, monkeypatch):
    def make(sector="water", state_age=0.0):
        identity = generate_site_identity(sector=sector, seed=f"dash-{sector}")
        id_path, state_path, db_path = tmp_path / "id.json", tmp_path / "state.json", tmp_path / "soc.db"
        save_identity(identity, str(id_path))
        state = _write_state(str(state_path), identity, state_age)
        _populate_db(str(db_path), identity)
        monkeypatch.setenv("GHOSTGRID_IDENTITY_PATH", str(id_path))
        monkeypatch.setenv("GHOSTGRID_STATE_PATH", str(state_path))
        monkeypatch.setenv("GHOSTGRID_DB_PATH", str(db_path))
        monkeypatch.setenv("GHOSTGRID_ADMIN_PASSWORD", PASSWORD)
        return identity, state
    return make


def _logged_in_app():
    at = AppTest.from_file(APP, default_timeout=20)
    at.session_state["authenticated"] = True
    at.run()
    return at


def _all_text(at):
    parts = [m.value for m in at.markdown] + [str(m.value) for m in at.metric] + [m.label for m in at.metric]
    for df in at.dataframe:
        parts.append(df.value.to_string())
    return "\n".join(parts)


def test_refuses_to_open_without_a_password(monkeypatch, tmp_path):
    monkeypatch.delenv("GHOSTGRID_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("GHOSTGRID_IDENTITY_PATH", str(tmp_path / "missing.json"))
    at = AppTest.from_file(APP, default_timeout=20).run()
    assert not at.exception
    assert at.error, "the page must explain that no password is configured"


def test_wrong_password_is_rejected_and_right_one_accepted(decoy_files):
    decoy_files("water")
    at = AppTest.from_file(APP, default_timeout=20).run()
    at.text_input[0].set_value("not-the-password")
    at.button[0].click().run()
    assert at.error
    at.text_input[0].set_value(PASSWORD)
    at.button[0].click().run()
    assert not at.exception
    assert at.session_state["authenticated"] is True


def test_repeated_wrong_passwords_lock_out_every_session(decoy_files):
    """After five failures even the right password is refused, and a fresh session (a reload) doesn't reset it."""
    import streamlit as st
    decoy_files("water")
    st.cache_resource.clear()
    try:
        at = AppTest.from_file(APP, default_timeout=20).run()
        for _ in range(5):
            at.text_input[0].set_value("guess")
            at.button[0].click().run()

        fresh = AppTest.from_file(APP, default_timeout=20).run()
        fresh.text_input[0].set_value(PASSWORD)
        fresh.button[0].click().run()
        assert not fresh.exception
        assert any("Too many failed attempts" in e.value for e in fresh.error)
        assert "authenticated" not in fresh.session_state or not fresh.session_state["authenticated"]
    finally:
        st.cache_resource.clear()     # don't leave the lockout in place for the other tests


def test_shows_decoy_not_running_without_identity(monkeypatch, tmp_path):
    monkeypatch.setenv("GHOSTGRID_ADMIN_PASSWORD", PASSWORD)
    monkeypatch.setenv("GHOSTGRID_IDENTITY_PATH", str(tmp_path / "missing.json"))
    at = _logged_in_app()
    assert not at.exception
    assert any("Decoy not running" in w.value for w in at.warning)


@pytest.mark.parametrize("sector", ["water", "power"])
def test_renders_alerts_sessions_and_live_process_values(decoy_files, sector):
    identity, state = decoy_files(sector)
    at = _logged_in_app()
    assert not at.exception, at.exception
    text = _all_text(at)

    # Alerts and sessions from the database are shown, with the attacker's address.
    assert "10.20.30.40" in text
    assert "HONEYTOKEN_TRIGGER" in text
    assert "UNAUTHORIZED_WRITE" in text

    # The process view shows the decoy's live values, not built-in fallbacks.
    if sector == "water":
        assert f"{state['INFLOW_RATE_M3H']:,} m3/h" in text
        assert f"{state['RESERVOIR_LEVEL_PCT'] / 10:.1f} %" in text
    else:
        assert f"{state['ACTIVE_POWER_MW'] / 10:.1f} MW" in text
        assert f"{state['GRID_FREQUENCY_HZ'] / 100:.2f} Hz" in text


def test_offers_evidence_exports_for_alerts_sessions_and_commands(decoy_files):
    decoy_files("water")
    at = _logged_in_app()
    assert not at.exception
    # at.get() rather than at.download_button: the shortcut only exists in newer Streamlit test tools.
    labels = sorted(b.proto.label for b in at.get("download_button"))
    assert labels == ["Export all alerts (CSV)", "Export all commands (CSV)", "Export all sessions (CSV)"]


def test_evidence_csv_keeps_full_detail_in_utc():
    import csv
    import io
    from ghostgrid.dashboard.export import evidence_csv

    sid = "3f1c2a9e-0000-4000-8000-123456789abc"
    data = evidence_csv([
        {"session_id": sid, "timestamp": 1_700_000_000.25, "client_ip": "10.20.30.40", "description": "Café, \"quoted\""},
        {"session_id": sid, "timestamp": 1_700_000_060.0, "mitre_technique": "T0846"},
    ])
    assert data.startswith("﻿".encode("utf-8")), "a BOM, so Excel reads accented text correctly"
    rows = list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"))))
    assert rows[0]["session_id"] == sid, "full session IDs, not the 8-character display form"
    assert rows[0]["timestamp"] == "2023-11-14T22:13:20.250Z", "times in UTC ISO 8601, like the SIEM records"
    assert rows[0]["description"] == "Café, \"quoted\""
    assert set(rows[0]) == {"session_id", "timestamp", "client_ip", "description", "mitre_technique"}
    assert rows[1]["mitre_technique"] == "T0846"


def test_warns_when_live_values_are_stale(decoy_files):
    decoy_files("water", state_age=120.0)
    at = _logged_in_app()
    assert not at.exception
    assert any("stale" in w.value.lower() for w in at.warning)

