"""The sealed box: vault, signed loop and battery running as one unit."""
from __future__ import annotations

import json
import statistics
import threading
import time
from collections import deque

from .loop import ChainSigner, Frame, FrameError, FrameRing, LapTimer
from .report import Reporter
from .sim.battery import Battery
from .sim.diode import DiodeReceiver, DiodeSender
from .vault import Vault

HEARTBEAT_S = 2.0


class Box(threading.Thread):
    """Sends a signed frame round the track every `interval_s` and checks every lap.

    Each frame carries a fingerprint of the vault and the box's status, never
    the data itself. A frame that comes back altered, late or not at all means
    something is on the track.
    """

    def __init__(
        self,
        vault: Vault,
        signer: ChainSigner,
        to_track: DiodeSender,
        returns: DiodeReceiver,
        battery: Battery,
        report: Reporter,
        interval_s: float = 0.25,
        overdue_s: float = 1.0,
        lap_timer: LapTimer | None = None,
    ):
        super().__init__(name="box", daemon=True)
        self.vault = vault
        self.signer = signer
        self.to_track = to_track
        self.returns = returns
        self.battery = battery
        self.report = report
        self.interval_s = interval_s
        self._overdue_ns = int(overdue_s * 1e9)
        self.lap_timer = lap_timer or LapTimer()
        self.ring = FrameRing()
        self._returned: deque[int] = deque(maxlen=4096)   # seqs already back, so the second copy is ignored
        self._laps: deque[float] = deque(maxlen=100)
        self.lap_log: deque[tuple[float, float]] = deque(maxlen=2400)   # (monotonic time, lap ms) for the live view
        self._halt = threading.Event()
        self._frozen_reported = False
        # Trips from earlier runs were handled then; this run only reports new ones, at both ends.
        self._canary_baseline = len(vault.canary_trips())
        self._canary_trips_reported = self._canary_baseline
        self.shut_down = False

    def stop(self) -> None:
        """Stops without announcing anything, like pulling the plug."""
        self._halt.set()

    def run(self) -> None:
        last = next_send = time.monotonic()
        next_beat = last + HEARTBEAT_S
        while not self._halt.is_set():
            now = time.monotonic()
            self.battery.drain(now - last)
            last = now
            if self.battery.must_shut_down:
                self._shut_down()
                return
            if now >= next_send:
                self._send("running")
                next_send = max(next_send + self.interval_s, now)
            self._watch_vault()

            raw = self.returns.receive()
            if raw is not None:
                self._check_return(raw)
            for frame in self.ring.overdue(time.monotonic_ns(), self._overdue_ns):
                self.report.alarm("box", "lost frame", f"#{frame.seq} never came back")
            if now >= next_beat:
                self._heartbeat()
                next_beat = now + HEARTBEAT_S

    def _send(self, state: str) -> None:
        new_trips = self.vault.canary_trips()[self._canary_baseline:]
        status = {
            "state": state,
            "files": self.vault.file_count,
            "digest": self.vault.state_digest()[:16],
            "frozen": self.vault.frozen,
            "reason": self.vault.freeze_reason,
            "canary_trips": len(new_trips),   # since this box started
            "canary_last": new_trips[-1].name if new_trips else None,
            "battery_pct": round(self.battery.pct, 1),
        }
        frame = self.signer.next_frame(json.dumps(status, separators=(",", ":")).encode())
        pushed_out = self.ring.put(frame, time.monotonic_ns())
        if pushed_out:
            self.report.alarm("box", "lost frame", f"#{pushed_out.seq} never came back")
        self.to_track.send(frame.encode())

    def _check_return(self, raw: bytes) -> None:
        now_ns = time.monotonic_ns()
        try:
            seq = Frame.decode(raw).seq
        except FrameError as e:
            self.report.alarm("box", "unreadable frame", str(e))
            return
        slot = self.ring.take(seq)
        if slot is None:
            if seq not in self._returned:
                self.report.alarm("box", "unexpected frame", f"#{seq} was not on the track (late, replayed or injected)")
            return
        self._returned.append(seq)
        sent, sent_ns = slot
        if raw != sent.encode():
            self.report.alarm("box", "altered frame", f"#{seq} came back different from what was sent")
            return
        lap_ms = (now_ns - sent_ns) / 1e6
        self._laps.append(lap_ms)
        self.lap_log.append((now_ns / 1e9, lap_ms))
        slow = self.lap_timer.record(lap_ms)
        if slow:
            self.report.alarm("box", "slow lap", f"#{seq} {slow}")

    def _watch_vault(self) -> None:
        if self.vault.frozen and not self._frozen_reported:
            self.report.alarm("box", "vault frozen", self.vault.freeze_reason or "no reason recorded")
            self._frozen_reported = True
        elif not self.vault.frozen:
            self._frozen_reported = False

        trips = self.vault.canary_trips()
        for trip in trips[self._canary_trips_reported:]:
            self.report.alarm("box", "canary tripped", f"{trip.name} was opened by {trip.reader}")
        self._canary_trips_reported = len(trips)

    def _heartbeat(self) -> None:
        lap = f"median lap {statistics.median(self._laps):.2f} ms" if self._laps else "no laps yet"
        frozen = " FROZEN" if self.vault.frozen else ""
        self.report.info(
            "box",
            f"{lap}, battery {self.battery.pct:.1f}% (~{self.battery.hours_left:.1f} h left), "
            f"vault {self.vault.file_count} files{frozen}",
        )

    def _shut_down(self) -> None:
        self._send("shutdown")
        self.vault.close()
        self.shut_down = True
        self.report.info(
            "box",
            f"battery at {self.battery.pct:.0f}% (reserve {self.battery.reserve_pct:.0f}%): "
            "clean shutdown announced, vault closed",
        )
