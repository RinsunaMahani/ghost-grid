"""Ransomware tripwire for the vault.

Ransomware shows up in two ways: many files change at once, and files that were
plain text suddenly look encrypted (entropy close to 8 bits per byte). Either
pattern freezes the vault, so the clean versions already inside stay the newest
trusted copies.

The thresholds must be tuned to the site's normal backup pattern. A legitimate
bulk update will also trip it; that is the intended trade-off, and an operator
reviews and unfreezes.
"""
from __future__ import annotations

import math
import time
from collections import deque
from typing import TYPE_CHECKING, Callable

if TYPE_CHECKING:
    from .store import Version

LOW_ENTROPY = 6.0          # text, CSV, configs sit around 4-5 bits per byte
HIGH_ENTROPY = 7.5         # encrypted or compressed data sits close to 8
MIN_ENTROPY_SIZE = 1024    # small files can't reach high entropy even when encrypted
DEFAULT_WINDOW_S = 10.0    # how far back a burst of changes counts


class Guard:
    def __init__(
        self,
        window_s: float = DEFAULT_WINDOW_S,
        change_ratio: float = 0.3,
        min_changes: int = 5,
        entropy_jumps: int = 3,
        clock: Callable[[], float] = time.monotonic,
    ):
        self.window_s = window_s
        self.change_ratio = change_ratio
        self.min_changes = min_changes
        self.entropy_jumps = entropy_jumps
        self._clock = clock
        self._changes: deque[tuple[float, str]] = deque()
        self._jumps: deque[tuple[float, str]] = deque()

    def check(self, name: str, previous: Version | None, entropy: float, size: int, total_files: int) -> str | None:
        """Returns a reason to freeze, or None. New files never count as changes."""
        if previous is None:
            return None
        now = self._clock()
        self._changes.append((now, name))
        if previous.entropy < LOW_ENTROPY and entropy > HIGH_ENTROPY and size >= MIN_ENTROPY_SIZE:
            self._jumps.append((now, name))
        for events in (self._changes, self._jumps):
            while events and now - events[0][0] > self.window_s:
                events.popleft()

        changed = len({n for _, n in self._changes})
        jumped = len({n for _, n in self._jumps})
        limit = max(self.min_changes, math.ceil(self.change_ratio * total_files))
        if jumped >= self.entropy_jumps:
            return f"encryption pattern: {jumped} files turned high-entropy within {self.window_s:g}s"
        if changed >= limit:
            return f"mass change: {changed} of {total_files} files modified within {self.window_s:g}s"
        return None

    def reset(self) -> None:
        self._changes.clear()
        self._jumps.clear()
