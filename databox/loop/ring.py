"""Pre-allocated ring of frames still out on the track.

Kept in memory on purpose: these are transient laps, not stored data, and
writing them to disk would only wear the SSD and drain the battery. The vault
itself never uses a ring; it never overwrites anything.
"""
from __future__ import annotations

from .frame import Frame


class FrameRing:
    def __init__(self, size: int = 1024):
        self._slots: list[tuple[Frame, int] | None] = [None] * size

    def put(self, frame: Frame, sent_mono_ns: int) -> Frame | None:
        """Stores a frame. Returns a frame that was still out and got pushed off the ring."""
        i = frame.seq % len(self._slots)
        pushed_out = self._slots[i]
        self._slots[i] = (frame, sent_mono_ns)
        return pushed_out[0] if pushed_out else None

    def take(self, seq: int) -> tuple[Frame, int] | None:
        """Removes and returns the frame with this number, if it is still out."""
        i = seq % len(self._slots)
        slot = self._slots[i]
        if slot is None or slot[0].seq != seq:
            return None
        self._slots[i] = None
        return slot

    def overdue(self, now_mono_ns: int, timeout_ns: int) -> list[Frame]:
        """Removes and returns frames that have been out longer than the timeout."""
        late = []
        for i, slot in enumerate(self._slots):
            if slot and now_mono_ns - slot[1] > timeout_ns:
                late.append(slot[0])
                self._slots[i] = None
        return sorted(late, key=lambda f: f.seq)
