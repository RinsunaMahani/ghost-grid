"""What the monitoring room works out from the frames it receives.

Kept apart from the console scoreboard so any display can reuse it. It reads frames and holds
the box's public key; it has no way to send, sign or reach into the vault.
"""
from __future__ import annotations

import json
import statistics
import time
from collections import deque
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from ..loop import ChainVerifier, Frame, FrameError, LapTimer


@dataclass(frozen=True)
class Event:
    at: float       # wall-clock time
    level: str      # "info" or "alarm"
    kind: str
    detail: str


def _alarm(kind: str, detail: str) -> Event:
    return Event(time.time(), "alarm", kind, detail)


def _info(kind: str, detail: str) -> Event:
    return Event(time.time(), "info", kind, detail)


class MonitorCore:
    def __init__(self, public_key: Ed25519PublicKey, silence_s: float = 2.0, latency_timer: LapTimer | None = None):
        self.verifier = ChainVerifier(public_key)
        self.silence_s = silence_s
        self.latency_timer = latency_timer or LapTimer()
        self.latencies: deque[tuple[float, float]] = deque(maxlen=600)   # (wall time, ms)
        self.verified = 0
        self.status: dict = {}
        self.silent = False
        self.shutdown_announced = False
        self._last_frame: float | None = None   # no silence alarm before the first genuine frame
        self._frozen_seen = False
        self._canary_trips_seen = 0

    def handle(self, raw: bytes) -> list[Event]:
        """Checks one datagram and returns what it means."""
        try:
            frame = Frame.decode(raw)
        except FrameError as e:
            return [_alarm("unreadable frame", str(e))]
        check = self.verifier.check(frame)
        events = [_alarm(kind, detail) for kind, detail in check.problems]
        if not check.accepted:
            return events

        self._last_frame = time.monotonic()
        if self.silent:
            self.silent = False
            events.append(_info("resumed", "genuine frames are arriving again"))

        # Same-machine clocks in the simulation; two real rooms would need synchronised clocks.
        now = time.time_ns()
        latency_ms = (now - frame.sent_ns) / 1e6
        self.latencies.append((now / 1e9, latency_ms))
        slow = self.latency_timer.record(latency_ms)
        if slow:
            events.append(_alarm("slow delivery", f"#{frame.seq} {slow}"))
        self.verified += 1

        self.status = json.loads(frame.payload)
        events += self._read_status()
        return events

    def _read_status(self) -> list[Event]:
        s = self.status
        events = []
        if s.get("frozen"):
            if not self._frozen_seen:
                self._frozen_seen = True
                events.append(_alarm("vault frozen", s.get("reason") or "no reason given"))
        else:
            self._frozen_seen = False

        trips = s.get("canary_trips", 0)
        if trips > self._canary_trips_seen:
            events.append(_alarm("canary tripped",
                                 f"{s.get('canary_last')} was opened inside the vault room ({trips} so far)"))
        self._canary_trips_seen = trips

        if s.get("state") == "shutdown" and not self.shutdown_announced:
            self.shutdown_announced = True
            events.append(_info("shutdown", f"box announced a clean shutdown (battery {s.get('battery_pct')}%); "
                                            "silence from now on is expected"))
        return events

    def check_silence(self) -> list[Event]:
        if self._last_frame is None or self.silent or self.shutdown_announced:
            return []
        quiet = time.monotonic() - self._last_frame
        if quiet <= self.silence_s:
            return []
        self.silent = True
        return [_alarm("silence", f"no genuine frames for {quiet:.1f}s (box off, fibre cut or track blocked)")]

    def median_latency(self) -> float | None:
        return statistics.median(ms for _, ms in self.latencies) if self.latencies else None
