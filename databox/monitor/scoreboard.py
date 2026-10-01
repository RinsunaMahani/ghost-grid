"""The monitoring-room console, like NASCAR race control.

Receive-only: it holds a receiver and the box's public key. Nothing here can
send, sign, or reach into the vault.
"""
from __future__ import annotations

import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..loop import LapTimer
from ..report import Reporter
from ..sim.diode import DiodeReceiver
from .core import MonitorCore

HEARTBEAT_S = 2.0


class Scoreboard(threading.Thread):
    def __init__(
        self,
        inbound: DiodeReceiver,
        public_key: Ed25519PublicKey,
        report: Reporter,
        silence_s: float = 2.0,
        latency_timer: LapTimer | None = None,
    ):
        super().__init__(name="monitor", daemon=True)
        self.inbound = inbound
        self.core = MonitorCore(public_key, silence_s, latency_timer)
        self.report = report
        self._halt = threading.Event()

    def stop(self) -> None:
        self._halt.set()

    def run(self) -> None:
        next_beat = time.monotonic() + HEARTBEAT_S
        while not self._halt.is_set():
            raw = self.inbound.receive()
            events = self.core.handle(raw) if raw is not None else []
            for event in events + self.core.check_silence():
                if event.level == "alarm":
                    self.report.alarm("monitor", event.kind, event.detail)
                else:
                    self.report.info("monitor", event.detail)
            if time.monotonic() >= next_beat:
                self._heartbeat()
                next_beat = time.monotonic() + HEARTBEAT_S

    def _heartbeat(self) -> None:
        s = self.core.status
        if not s:
            self.report.info("monitor", "waiting for frames")
            return
        latency = self.core.median_latency()
        state = " FROZEN" if s.get("frozen") else ""
        if self.core.shutdown_announced:
            state += " (box shut down)"
        self.report.info(
            "monitor",
            f"{self.core.verified} frames verified, delivery ~{latency:.2f} ms, vault digest {s.get('digest')}, "
            f"{s.get('files')} files, battery {s.get('battery_pct')}%{state}",
        )
