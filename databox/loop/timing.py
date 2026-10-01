"""Lap timing, like the loops buried under a NASCAR track.

A tap that cuts the fibre and relays the light adds delay, the way a pit-lane
detour shows up in a car's lap time.
"""
from __future__ import annotations

from statistics import median


class LapTimer:
    """Learns what a normal lap looks like, then flags laps that take far longer."""

    def __init__(self, learn: int = 20, factor: float = 4.0, floor_ms: float = 20.0):
        self.learn = learn
        self.factor = factor
        self.floor_ms = floor_ms     # ignore jitter below this, however fast the baseline
        self._samples: list[float] = []
        self.baseline_ms: float | None = None

    @property
    def limit_ms(self) -> float | None:
        if self.baseline_ms is None:
            return None
        return max(self.floor_ms, self.baseline_ms * self.factor)

    def record(self, lap_ms: float) -> str | None:
        """Returns a description if this lap is too slow, otherwise None."""
        if self.baseline_ms is None:
            self._samples.append(lap_ms)
            if len(self._samples) >= self.learn:
                self.baseline_ms = median(self._samples)
            return None
        if lap_ms > self.limit_ms:
            return f"{lap_ms:.1f} ms (normal ~{self.baseline_ms:.2f} ms, limit {self.limit_ms:.1f} ms)"
        return None
