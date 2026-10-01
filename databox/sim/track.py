"""The 'race track': fibre from the vault room to the monitoring room and back.

A passive splitter in the monitoring room copies every frame to the monitor;
the rest of the light carries on back to the box. Faults stand in for what
damage or a tap on the fibre would do to the frames, so both ends can be tested.
"""
from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass

from ..loop.frame import HEADER, SIG_LEN
from .diode import DiodeReceiver, DiodeSender


@dataclass
class Faults:
    delay_ms: float = 0.0      # a relay tap reading the light adds delay
    drop_every: int = 0        # lose every Nth frame
    alter_every: int = 0       # change a byte in every Nth frame
    start_after_s: float = 0.0 # healthy until then, so both ends can learn normal lap times


def _seq_of(raw: bytes) -> int | None:
    if len(raw) < HEADER.size:
        return None
    return struct.unpack_from(">Q", raw, 4)[0]


class Track(threading.Thread):
    def __init__(self, inbound: DiodeReceiver, to_box: DiodeSender, to_monitors: list[DiodeSender],
                 faults: Faults | None = None):
        super().__init__(name="track", daemon=True)
        self.inbound = inbound
        self.to_box = to_box
        self.to_monitors = to_monitors   # the splitter's outputs into the monitoring room
        self.faults = faults or Faults()
        self._halt = threading.Event()

    def stop(self) -> None:
        self._halt.set()

    def run(self) -> None:
        started = time.monotonic()
        while not self._halt.is_set():
            raw = self.inbound.receive()
            if raw is None:
                continue
            if time.monotonic() - started >= self.faults.start_after_s:
                raw = self._damage(raw)
                if raw is None:
                    continue
                if self.faults.delay_ms:
                    timer = threading.Timer(self.faults.delay_ms / 1000, self._forward, (raw,))
                    timer.daemon = True
                    timer.start()
                    continue
            self._forward(raw)

    def _damage(self, raw: bytes) -> bytes | None:
        seq = _seq_of(raw)
        if seq is None:
            return raw
        if self.faults.drop_every and seq % self.faults.drop_every == 0:
            return None
        if self.faults.alter_every and seq % self.faults.alter_every == 0 and len(raw) > HEADER.size + SIG_LEN:
            changed = bytearray(raw)
            changed[HEADER.size] ^= 0x01      # first payload byte
            return bytes(changed)
        return raw

    def _forward(self, raw: bytes) -> None:
        if self._halt.is_set():
            return
        try:
            for monitor in self.to_monitors:
                monitor.send(raw)       # the splitter's copies for the monitoring room
            self.to_box.send(raw)       # the rest of the light returns to the vault room
        except OSError:
            pass                        # sockets closed while a delayed frame was in flight
