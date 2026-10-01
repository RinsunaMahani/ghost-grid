"""Battery model for the sealed box.

The box never connects to mains while running (docs/research-single-box.md §4.2).
It runs from a pack and shuts down cleanly before the pack is empty, so nothing
is cut off mid-write. The defaults are assumptions for a Raspberry Pi-class box
with two fibre transceivers on a large power bank: about 15 hours to reserve,
comfortably above the 8-hour substation benchmark.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Battery:
    capacity_wh: float = 100.0
    load_w: float = 6.0
    reserve_pct: float = 10.0
    charge_wh: float | None = None

    def __post_init__(self) -> None:
        if self.charge_wh is None:
            self.charge_wh = self.capacity_wh

    @property
    def pct(self) -> float:
        return 100.0 * self.charge_wh / self.capacity_wh

    @property
    def must_shut_down(self) -> bool:
        return self.pct <= self.reserve_pct

    @property
    def hours_left(self) -> float:
        """Running time left before the reserve is reached."""
        usable = self.charge_wh - self.capacity_wh * self.reserve_pct / 100
        return max(0.0, usable / self.load_w)

    def drain(self, seconds: float) -> None:
        self.charge_wh = max(0.0, self.charge_wh - self.load_w * seconds / 3600)

    def swap(self) -> None:
        """A fresh pack from the charging station outside the box."""
        self.charge_wh = self.capacity_wh
