"""Console output shared by the box, the backup feed and the monitor."""
from __future__ import annotations

import threading
import time
from collections import Counter
from typing import Callable


def _print(line: str) -> None:
    print(line, flush=True)


class Reporter:
    """Prints events and counts alarms.

    An alarm that repeats on every frame is printed at most once per `quiet_s`
    but always counted, so the summary still shows the full picture.
    """

    def __init__(self, out: Callable[[str], None] | None = None, quiet_s: float = 2.0):
        self._out = out or _print
        self._quiet_s = quiet_s
        self._t0 = time.monotonic()
        self._lock = threading.Lock()
        self._last_shown: dict[tuple[str, str], float] = {}
        self.counts: Counter[tuple[str, str]] = Counter()
        self.log: list[tuple[float, str, str, str]] = []   # (seconds, source, level, message)

    def info(self, source: str, message: str) -> None:
        self._emit(source, "info ", message)

    def alarm(self, source: str, kind: str, detail: str) -> None:
        key = (source, kind)
        now = time.monotonic()
        with self._lock:
            self.counts[key] += 1
            if now - self._last_shown.get(key, float("-inf")) < self._quiet_s:
                return
            self._last_shown[key] = now
        self._emit(source, "ALARM", f"{kind}: {detail}")

    def _emit(self, source: str, level: str, message: str) -> None:
        t = time.monotonic() - self._t0
        with self._lock:
            self.log.append((t, source, level.strip(), message))
            self._out(f"{t:6.2f}s  {source:<7} {level}  {message}")
