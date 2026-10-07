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
        # Numbers claimed by frames that failed the signature check. A gap made only of these was
        # already alarmed as "bad signature", so it isn't reported a second time. The claimed number
        # can't be trusted, but faking one to hide a real gap raises its own bad-signature alarm.
        self._rejected: OrderedDict[int, None] = OrderedDict()
        self._bad_seen: OrderedDict[bytes, float] = OrderedDict()   # digest of a bad frame -> when seen

    def check(self, frame: Frame) -> Check:
        result = Check(frame)
        try:
            self._pub.verify(frame.signature, frame.body())
        except InvalidSignature:
            # The link sends every frame twice, so an identical bad frame straight after is the same alarm.
            digest, now = frame.digest(), time.monotonic()
            seen_at = self._bad_seen.get(digest)
            if seen_at is not None and now - seen_at < self.duplicate_window_s:
                result.duplicate = True
                return result
            self._bad_seen[digest] = now
            result.problems.append(("bad signature", f"#{frame.seq} was forged or altered in transit"))
            self._rejected[frame.seq] = None
            for memo in (self._rejected, self._bad_seen):
                while len(memo) > self._memory:
                    memo.popitem(last=False)
            return result

        now = time.monotonic()
        digest = frame.digest()
        seen_at = self._seen.get(digest)
        if seen_at is not None:
            # Strictly inside the window: on Windows before Python 3.13 the clock only ticks every
            # ~15 ms, so a zero-length window must still treat a same-tick repeat as a replay.
            if now - seen_at < self.duplicate_window_s:
                result.duplicate = True
            else:
                result.problems.append(("replay", f"#{frame.seq} seen again {now - seen_at:.1f}s later"))
            return result
        if self._last_seq and frame.seq <= self._last_seq:
            result.problems.append(("replay", f"#{frame.seq} is older than #{self._last_seq}"))
            return result

        if self._last_seq and frame.seq > self._last_seq + 1:
            unexplained = sum(1 for s in range(self._last_seq + 1, frame.seq) if s not in self._rejected)
            if unexplained:
                result.problems.append(("gap", f"{unexplained} frame(s) missing before #{frame.seq}"))
        elif (self._last_seq or frame.seq == 1) and frame.prev_hash != self._last_hash:
            result.problems.append(("chain break", f"#{frame.seq} does not link to the previous frame"))
        # A monitor that starts mid-stream simply syncs to the first genuine frame it sees.

        self._last_seq, self._last_hash = frame.seq, digest
        for s in [s for s in self._rejected if s <= frame.seq]:
            del self._rejected[s]
        self._seen[digest] = now
        while len(self._seen) > self._memory:
            self._seen.popitem(last=False)
        result.accepted = True
        return result
