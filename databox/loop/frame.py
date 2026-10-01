"""One 'car' on the track: a signed frame chained to the one before it."""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

MAGIC = b"GBOX"
GENESIS = bytes(32)                   # prev_hash of the very first frame
SIG_LEN = 64                          # Ed25519 signature size
HEADER = struct.Struct(">4sQQ32sH")   # magic, seq, sent_ns, prev_hash, payload length


class FrameError(ValueError):
    """Bytes that are not a well-formed frame."""


@dataclass(frozen=True)
class Frame:
    seq: int
    sent_ns: int        # wall-clock send time, so the monitor can measure delivery time
    prev_hash: bytes    # digest of the previous frame: this is the chain
    payload: bytes
    signature: bytes = b""

    def body(self) -> bytes:
        """Everything the signature and the chain cover."""
        return HEADER.pack(MAGIC, self.seq, self.sent_ns, self.prev_hash, len(self.payload)) + self.payload

    def digest(self) -> bytes:
        return hashlib.sha256(self.body()).digest()

    def encode(self) -> bytes:
        return self.body() + self.signature

    @classmethod
    def decode(cls, raw: bytes) -> Frame:
        if len(raw) < HEADER.size + SIG_LEN:
            raise FrameError("too short")
        magic, seq, sent_ns, prev_hash, length = HEADER.unpack_from(raw)
        if magic != MAGIC:
            raise FrameError("bad magic")
        end = HEADER.size + length
        if len(raw) != end + SIG_LEN:
            raise FrameError("length mismatch")
        return cls(seq, sent_ns, prev_hash, raw[HEADER.size:end], raw[end:])
