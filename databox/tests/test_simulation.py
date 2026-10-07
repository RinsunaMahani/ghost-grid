"""A run's life: start, stop (vault kept for review), recover after a freeze, close (temporary vault deleted)."""
import time
from pathlib import Path

import pytest

from databox.simulation import Simulation
from databox.vault import find_suspects

FAST = dict(fault_at_s=1.0, interval_s=0.05, learn=15, silence_s=0.6, out=lambda line: None)


def _frozen_run():
    sim = Simulation("ransomware", **FAST).start()
    deadline = time.monotonic() + 10
    while not sim.vault.frozen and time.monotonic() < deadline:
        time.sleep(0.05)
    assert sim.vault.frozen, "the guard should have frozen the vault"
    return sim


def test_recovery_waits_until_the_infected_source_is_stopped():
    sim = _frozen_run()
    try:
        with pytest.raises(RuntimeError, match="stop the run first"):
            sim.recover("operator")
    finally:
        sim.close()


def test_recovery_rolls_back_to_the_clean_content_and_unfreezes():
    sim = _frozen_run()
    try:
        sim.stop()
        suspects = list(sim.suspects)
        assert suspects, "stopping a frozen run lists the files to review"
        clean = {s.name: sim.vault.get(s.name, version=s.clean_version, reader="test") for s in suspects}

        restored = sim.recover("A. Operator")

        assert {v.name for v in restored} == set(clean)
        assert not sim.vault.frozen, "no suspects remain, so the vault accepts backups again"
        assert find_suspects(sim.vault) == []
        for name, data in clean.items():
            assert sim.vault.get(name, reader="test") == data, f"{name} must hold its clean content again"
            assert len(sim.vault.history(name)) > 2, "nothing deleted: the damaged version stays on record"
        status = sim.status()
        assert (status["suspects"], status["restored"], status["vault_frozen"]) == (0, len(clean), False)
    finally:
        sim.close()


def test_stop_keeps_a_temporary_vault_and_close_deletes_it():
    sim = Simulation("normal", **FAST).start()
    root = Path(sim.vault.root)
    sim.stop()
    assert root.exists(), "a stopped run keeps its vault for review"
    sim.close()
    assert not root.exists(), "closing the run deletes its temporary vault"
