"""End-to-end runs of the simulation, shortened to a few seconds each."""
import pytest

from databox.demo import run_scenario

FAST = dict(seconds=3.0, fault_at_s=1.6, interval_s=0.05, learn=15, silence_s=0.6)


def run(name, tmp_path):
    return run_scenario(name, vault_dir=tmp_path, out=lambda line: None, **FAST)


def test_normal_run_raises_no_alarms(tmp_path):
    assert not run("normal", tmp_path).counts


@pytest.mark.parametrize("scenario, box_kind, monitor_kind", [
    ("delay", "slow lap", "slow delivery"),
    ("drop", "lost frame", "gap"),
    ("alter", "altered frame", "bad signature"),
    ("ransomware", "vault frozen", "vault frozen"),
])
def test_both_ends_catch_the_fault(tmp_path, scenario, box_kind, monitor_kind):
    counts = run(scenario, tmp_path).counts
    assert counts[("box", box_kind)] > 0
    assert counts[("monitor", monitor_kind)] > 0


def test_opening_a_canary_raises_alarms_at_both_ends(tmp_path):
    counts = run("snoop", tmp_path).counts
    assert counts[("box", "canary tripped")] > 0
    assert counts[("monitor", "canary tripped")] > 0


def test_canary_trips_from_an_earlier_run_do_not_alarm_again(tmp_path):
    # Regression: a later run on the same vault used to re-alarm old trips at the monitor.
    run("snoop", tmp_path)
    assert not run("normal", tmp_path).counts


def test_sudden_power_loss_is_noticed(tmp_path):
    assert run("cut", tmp_path).counts[("monitor", "silence")] > 0


def test_clean_battery_shutdown_is_not_mistaken_for_a_cut(tmp_path):
    report = run("battery", tmp_path)
    assert ("monitor", "silence") not in report.counts
    assert any("clean shutdown" in message for _, _, _, message in report.log)
