"""One run of the sealed-box simulation that can be started, watched and stopped.

The command-line demo runs one for a fixed time; the live view keeps one running
and reads its parts while it goes.
"""
from __future__ import annotations

import contextlib
import os
import random
import statistics
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .box import Box
from .loop import ChainSigner, LapTimer
from .monitor import Scoreboard
from .report import Reporter
from .sim import Battery, DiodeReceiver, DiodeSender, Faults, Track
from .vault import Guard, Vault, VaultClosed, VaultFrozen, find_suspects, plant_canaries

SCENARIOS = {
    "normal": "Everything healthy. Expect no alarms.",
    "delay": "A relay tap on the fibre adds 150 ms. Expect slow laps at the box and slow delivery at the monitor.",
    "drop": "Every 5th frame is lost on the track. Expect lost frames at the box and gaps at the monitor.",
    "alter": "Every 7th frame is changed in transit. Expect altered frames at the box and bad signatures at the monitor.",
    "ransomware": "Backups start arriving encrypted. Expect the vault to freeze and the monitor to see it.",
    "snoop": "Someone at the box browses the files and opens a canary record. Expect canary alarms at both ends.",
    "battery": "A small pack drains fast. Expect a clean, announced shutdown and no silence alarm.",
    "cut": "The box loses power without warning. Expect a silence alarm at the monitor.",
}


class BackupFeed(threading.Thread):
    """Stands in for the building network sending backups into the vault.

    In the real box these arrive over a one-way link into the vault room. In
    'ransomware' mode the same files start arriving as random bytes, which is
    what encrypted files look like. It only ever writes into the simulated vault,
    and like every legitimate process it leaves canary records alone.
    """

    def __init__(self, vault: Vault, report: Reporter, rng: random.Random,
                 every_s: float = 3.0, ransomware_at_s: float | None = None):
        super().__init__(name="feed", daemon=True)
        self.vault = vault
        self.report = report
        self.rng = rng
        self.every_s = every_s
        self.ransomware_at_s = ransomware_at_s
        self._halt = threading.Event()

    def stop(self) -> None:
        self._halt.set()

    def run(self) -> None:
        start = time.monotonic()
        next_update = start + self.every_s
        names = self.vault.names(include_canaries=False)
        turn = 0
        refused = False
        while not self._halt.wait(0.05):
            now = time.monotonic()
            name = None
            try:
                if self.ransomware_at_s is not None and now - start >= self.ransomware_at_s:
                    name = names[turn % len(names)]
                    turn += 1
                    self.vault.put(name, os.urandom(self.vault.latest(name).size))
                elif now >= next_update:
                    name = self.rng.choice(names)
                    line = f"# backup {time.strftime('%H:%M:%S')} ok\n".encode()
                    self.vault.put(name, self.vault.get(name, reader="backup feed") + line)
                    next_update = now + self.every_s
            except VaultFrozen:
                if not refused:
                    refused = True
                    self.report.info("feed", f"vault refused {name}: frozen, the clean versions stay newest")
            except VaultClosed:
                return


class Snoop(threading.Thread):
    """Someone at the box itself, browsing the vault: opens the first few files listed."""

    def __init__(self, vault: Vault, at_s: float, files: int = 4):
        super().__init__(name="snoop", daemon=True)
        self.vault = vault
        self.at_s = at_s
        self.files = files
        self._halt = threading.Event()

    def stop(self) -> None:
        self._halt.set()

    def run(self) -> None:
        if self._halt.wait(self.at_s):
            return
        for name in self.vault.names()[:self.files]:
            with contextlib.suppress(VaultClosed):
                self.vault.get(name, reader="a console in the vault room")


def seed_vault(vault: Vault, rng: random.Random) -> None:
    """Twenty plain-text records of the kind a site would keep, plus three canary records."""
    for site in range(1, 9):
        rows = ["asset_id,type,location,installed,last_service"]
        for n in range(1, 40):
            kind = rng.choice(["pump", "valve", "meter", "breaker", "transformer"])
            rows.append(
                f"S{site:02d}-{n:03d},{kind},Site {site} bay {n % 7 + 1},"
                f"20{rng.randint(10, 24)}-0{rng.randint(1, 9)}-1{rng.randint(0, 9)},2026-0{rng.randint(1, 8)}-2{rng.randint(0, 8)}"
            )
        vault.put(f"assets/register-site-{site:02d}.csv", "\n".join(rows).encode())
    for unit in range(1, 7):
        lines = [f"# controller configuration backup, unit {unit}"]
        lines += [f"setpoint_{k:02d} = {rng.randint(10, 900)}" for k in range(1, 45)]
        vault.put(f"config/controller-{unit:02d}.txt", "\n".join(lines).encode())
    for area in range(1, 7):
        lines = [f"# drawing register, area {area}"]
        lines += [f"DWG-{area}{k:03d}  rev {rng.choice('ABCD')}  single-line diagram, panel {k}" for k in range(1, 30)]
        vault.put(f"drawings/area-{area:02d}-index.txt", "\n".join(lines).encode())
    plant_canaries(vault, rng)


def _copy(items: deque) -> list:
    """A list copy of a deque another thread may be appending to."""
    for _ in range(5):
        try:
            return list(items)
        except RuntimeError:   # the deque changed mid-copy; try again
            continue
    return []


class Simulation:
    def __init__(
        self,
        scenario: str = "normal",
        fault_at_s: float = 7.0,
        interval_s: float = 0.25,
        learn: int = 20,
        silence_s: float = 2.0,
        vault_dir: str | Path | None = None,
        out: Callable[[str], None] | None = None,
        auto_stop_s: float | None = None,
    ):
        if scenario not in SCENARIOS:
            raise ValueError(f"unknown scenario {scenario!r}; choose from {', '.join(SCENARIOS)}")
        self.scenario = scenario
        self.fault_at_s = fault_at_s
        self.interval_s = interval_s
        self.learn = learn
        self.silence_s = silence_s
        self.auto_stop_s = auto_stop_s
        self.report = Reporter(out=out)
        self.kept_vault = vault_dir is not None
        self._vault_dir = vault_dir
        self._stack = contextlib.ExitStack()
        self._threads: list[threading.Thread] = []
        self._timers: list[threading.Timer] = []
        self._lock = threading.Lock()
        self.running = False
        self.started_mono: float | None = None
        self.started_wall: float | None = None
        self.stopped_mono: float | None = None
        self.suspects: list = []
        self.vault: Vault | None = None
        self.box: Box | None = None
        self.monitor: Scoreboard | None = None
        self.battery: Battery | None = None

    def start(self) -> Simulation:
        with self._lock:
            if self.started_mono is not None:
                raise RuntimeError("a simulation runs once; create a new one to run again")
            stack = self._stack
            vault_dir = self._vault_dir or stack.enter_context(tempfile.TemporaryDirectory(prefix="databox-"))
            self.vault = vault = Vault(vault_dir, guard=Guard())
            if not vault.names():
                seed_vault(vault, random.Random(7))

            key = Ed25519PrivateKey.generate()   # stays inside the box
            public_key = key.public_key()        # the only thing the monitoring room is given

            # Receivers first, so every sender has an address to aim at.
            box_returns = DiodeReceiver(timeout_s=min(0.05, self.interval_s / 2))
            monitor_in = DiodeReceiver()
            track_in = DiodeReceiver()
            to_track = DiodeSender(track_in.address, copies=2)
            to_box = DiodeSender(box_returns.address, copies=1)
            to_monitors = [DiodeSender(monitor_in.address, copies=1)]
            for end in (box_returns, monitor_in, track_in, to_track, to_box, *to_monitors):
                stack.callback(end.close)

            faults = Faults(start_after_s=self.fault_at_s)
            battery = Battery()
            if self.scenario == "delay":
                faults.delay_ms = 150
            elif self.scenario == "drop":
                faults.drop_every = 5
            elif self.scenario == "alter":
                faults.alter_every = 7
            elif self.scenario == "battery":
                # Sized so the pack reaches its 10% reserve right at fault_at_s.
                battery = Battery(capacity_wh=battery.load_w * self.fault_at_s / 0.9 / 3600)
            self.battery = battery

            track = Track(track_in, to_box, to_monitors, faults)
            self.monitor = Scoreboard(monitor_in, public_key, self.report, silence_s=self.silence_s,
                                      latency_timer=LapTimer(learn=self.learn))
            self.box = Box(vault, ChainSigner(key), to_track, box_returns, battery, self.report,
                           interval_s=self.interval_s, lap_timer=LapTimer(learn=self.learn))
            feed = BackupFeed(vault, self.report, random.Random(11),
                              ransomware_at_s=self.fault_at_s if self.scenario == "ransomware" else None)
            self._threads = [track, self.monitor, self.box, feed]
            if self.scenario == "snoop":
                self._threads.append(Snoop(vault, self.fault_at_s))
            self._canary_baseline = len(vault.canary_trips())

            self.started_mono, self.started_wall = time.monotonic(), time.time()
            for t in self._threads:
                t.start()
            if self.scenario == "cut":
                self._timers.append(threading.Timer(self.fault_at_s, self.box.stop))
            if self.auto_stop_s:
                self._timers.append(threading.Timer(self.auto_stop_s, self.stop))
            for timer in self._timers:
                timer.daemon = True
                timer.start()
            self.running = True
        return self

    def stop(self) -> None:
        with self._lock:
            if not self.running:
                return
            self.running = False
            for timer in self._timers:
                timer.cancel()
            for t in reversed(self._threads):
                t.stop()
            for t in self._threads:
                t.join(timeout=2)
            self.stopped_mono = time.monotonic()

            self.suspects = find_suspects(self.vault)
            for s in self.suspects:
                self.report.info("vault", f"{s.name}: v{s.bad_version} {s.reason}; clean v{s.clean_version} is still in the vault")
            if self.suspects and self.kept_vault:
                self.report.info("vault", f"review and roll back with: python -m databox.restore --vault {self._vault_dir}")
            self._stack.close()

    # --- reading the run while it goes ----------------------------------

    @property
    def elapsed(self) -> float:
        if self.started_mono is None:
            return 0.0
        end = self.stopped_mono if self.stopped_mono is not None else time.monotonic()
        return end - self.started_mono

    @property
    def fault_active(self) -> bool:
        return self.scenario != "normal" and self.elapsed >= self.fault_at_s

    def lap_times(self) -> list[tuple[float, float]]:
        """(seconds since start, box lap time in ms)."""
        return [(t - self.started_mono, ms) for t, ms in _copy(self.box.lap_log)]

    def delivery_times(self) -> list[tuple[float, float]]:
        """(seconds since start, monitor delivery time in ms)."""
        return [(t - self.started_wall, ms) for t, ms in _copy(self.monitor.core.latencies)]

    def alarms(self) -> list[tuple[float, str, str]]:
        """(seconds since start, where, message), oldest first."""
        return [(t, source, message) for t, source, level, message in list(self.report.log) if level == "ALARM"]

    def status(self) -> dict:
        box, core, vault, battery = self.box, self.monitor.core, self.vault, self.battery
        if box.shut_down:
            box_state = "shut down"
        elif self.running and not box.is_alive():
            box_state = "no power"
        elif self.running:
            box_state = "running"
        else:
            box_state = "stopped"
        recent = [ms for _, ms in _copy(box.lap_log)[-20:]]
        return {
            "elapsed": self.elapsed,
            "running": self.running,
            "fault_active": self.fault_active,
            "box_state": box_state,
            "frames_sent": box.signer.count,
            "frames_verified": core.verified,
            "lap_median_ms": statistics.median(recent) if recent else None,
            "lap_limit_ms": box.lap_timer.limit_ms,
            "delivery_limit_ms": core.latency_timer.limit_ms,
            "monitor_silent": core.silent,
            "shutdown_announced": core.shutdown_announced,
            "vault_files": vault.file_count,
            "vault_frozen": vault.frozen,
            "freeze_reason": vault.freeze_reason,
            "canary_trips": len(vault.canary_trips()) - self._canary_baseline,
            "battery_pct": battery.pct,
            "battery_hours": battery.hours_left,
            "alarm_counts": dict(self.report.counts),
        }

    def __enter__(self) -> Simulation:
        return self.start()

    def __exit__(self, *exc) -> None:
        self.stop()


def run_scenario(
    name: str,
    seconds: float = 16.0,
    fault_at_s: float = 7.0,
    interval_s: float = 0.25,
    learn: int = 20,
    silence_s: float = 2.0,
    vault_dir: str | Path | None = None,
    out: Callable[[str], None] | None = None,
) -> Reporter:
    """Runs one scenario for a fixed time and returns its report."""
    sim = Simulation(name, fault_at_s=fault_at_s, interval_s=interval_s, learn=learn,
                     silence_s=silence_s, vault_dir=vault_dir, out=out)
    with sim:
        time.sleep(seconds)
    return sim.report
