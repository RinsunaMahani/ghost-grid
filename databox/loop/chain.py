"""Signing and checking the chain of frames.

The box signs with its private Ed25519 key. The monitoring room checks with the
public key only, so it holds no secret that could be used to forge frames.
"""
from __future__ import annotations

import time
from collections import OrderedDict
from dataclasses import dataclass, field, replace

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from .frame import GENESIS, Frame


class ChainSigner:
    """Box side: numbers each frame, links it to the previous one and signs it."""

    def __init__(self, key: Ed25519PrivateKey):
        self._key = key
        self._seq = 0
        self._prev = GENESIS

    @property
    def count(self) -> int:
        """Frames signed so far."""
        return self._seq

    def next_frame(self, payload: bytes) -> Frame:
        self._seq += 1
        unsigned = Frame(self._seq, time.time_ns(), self._prev, payload)
        frame = replace(unsigned, signature=self._key.sign(unsigned.body()))
        self._prev = frame.digest()
        return frame


@dataclass
class Check:
    frame: Frame
    accepted: bool = False     # the frame is genuine and moved the chain forward
    duplicate: bool = False    # a second copy of a frame already accepted
    problems: list[tuple[str, str]] = field(default_factory=list)   # (kind, detail)


class ChainVerifier:
    """Monitor side: needs only the box's public key.

    The one-way link sends every frame twice, so an identical frame arriving
    within `duplicate_window_s` is a normal duplicate. The same frame arriving
    later is a replay.
    """

    def __init__(self, public_key: Ed25519PublicKey, duplicate_window_s: float = 1.0, memory: int = 1024):
        self._pub = public_key
        self.duplicate_window_s = duplicate_window_s
        self._memory = memory
        self._last_seq = 0
        self._last_hash = GENESIS
        self._seen: OrderedDict[bytes, float] = OrderedDict()   # digest -> when accepted

    def check(self, frame: Frame) -> Check:
        result = Check(frame)
        try:
            self._pub.verify(frame.signature, frame.body())
        except InvalidSignature:
            result.problems.append(("bad signature", f"#{frame.seq} was forged or altered in transit"))
            return result

        now = time.monotonic()
        digest = frame.digest()
        seen_at = self._seen.get(digest)
        if seen_at is not None:
            if now - seen_at <= self.duplicate_window_s:
                result.duplicate = True
            else:
                result.problems.append(("replay", f"#{frame.seq} seen again {now - seen_at:.1f}s later"))
            return result
        if self._last_seq and frame.seq <= self._last_seq:
            result.problems.append(("replay", f"#{frame.seq} is older than #{self._last_seq}"))
            return result

        if self._last_seq and frame.seq > self._last_seq + 1:
            missing = frame.seq - self._last_seq - 1
            result.problems.append(("gap", f"{missing} frame(s) missing before #{frame.seq}"))
        elif (self._last_seq or frame.seq == 1) and frame.prev_hash != self._last_hash:
            result.problems.append(("chain break", f"#{frame.seq} does not link to the previous frame"))
        # A monitor that starts mid-stream simply syncs to the first genuine frame it sees.

        self._last_seq, self._last_hash = frame.seq, digest
        self._seen[digest] = now
        while len(self._seen) > self._memory:
            self._seen.popitem(last=False)
        result.accepted = True
        return result
