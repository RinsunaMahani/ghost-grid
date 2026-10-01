"""Append-only, encrypted, versioned vault.

Every write becomes a new version. Objects are created in exclusive mode, so
nothing already in the vault is ever overwritten, and nothing is ever deleted.
The manifest is an append-only log of versions, freezes, restores and canary trips.

Demo limitation: the AES key sits in a file next to the data. A real box would
keep it in a TPM or HSM.
"""
from __future__ import annotations

import hashlib
import json
import math
import os
import threading
import time
from collections import Counter
from dataclasses import asdict, dataclass
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .guard import Guard

NONCE_LEN = 12


class VaultFrozen(RuntimeError):
    """The guard saw a ransomware-like pattern; writes are refused until an operator unfreezes."""


class VaultClosed(RuntimeError):
    """The box shut down; the vault accepts nothing more."""


class IntegrityError(RuntimeError):
    """A stored object no longer matches what was written."""


@dataclass(frozen=True)
class Version:
    name: str
    version: int
    fingerprint: str   # SHA-256 of the plaintext
    size: int
    entropy: float     # bits per byte of the plaintext, 0-8
    stored_at: float
    object_id: str
    restored_from: int | None = None   # set when an operator rolled back to an earlier version


@dataclass(frozen=True)
class CanaryTrip:
    name: str
    reader: str
    at: float


def shannon_entropy(data: bytes) -> float:
    """Bits of information per byte: about 4-5 for text, close to 8 for encrypted data."""
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


class Vault:
    def __init__(self, root: str | Path, guard: Guard | None = None):
        self.root = Path(root)
        self._objects = self.root / "objects"
        self._objects.mkdir(parents=True, exist_ok=True)
        self._manifest = self.root / "manifest.jsonl"
        self._aes = AESGCM(self._load_or_create_key())
        self._guard = guard
        self._lock = threading.RLock()
        self._versions: dict[str, list[Version]] = {}
        self._canaries: dict[str, str] = {}          # name -> reference planted in its content
        self._trips: list[CanaryTrip] = []
        self.frozen = False
        self.freeze_reason: str | None = None
        self.frozen_at: float | None = None
        self.closed = False
        self._replay_manifest()

    # --- writing ---------------------------------------------------------

    def put(self, name: str, data: bytes) -> Version:
        with self._lock:
            self._check_open()
            if self.frozen:
                raise VaultFrozen(self.freeze_reason)
            previous = self.latest(name)
            fingerprint = hashlib.sha256(data).hexdigest()
            if previous and previous.fingerprint == fingerprint:
                return previous
            entropy = shannon_entropy(data)
            if self._guard:
                reason = self._guard.check(name, previous, entropy, len(data), len(self._versions))
                if reason:
                    self.freeze(reason)
                    raise VaultFrozen(reason)
            return self._store(name, data, fingerprint, entropy, previous)

    def restore(self, name: str, version: int, operator: str) -> Version:
        """Makes an earlier version the newest again, stored as a new version.

        Allowed while frozen: it only brings back content that is already in the
        vault, so nothing new from outside gets in.
        """
        with self._lock:
            self._check_open()
            if name in self._canaries:
                raise ValueError(f"{name} is a canary record, not real data")
            data = self._read(name, version)
            previous = self.latest(name)
            fingerprint = hashlib.sha256(data).hexdigest()
            if previous.fingerprint == fingerprint:
                return previous
            restored = self._store(name, data, fingerprint, shannon_entropy(data), previous, restored_from=version)
            self._record({"type": "restore", "name": name, "from": version, "to": restored.version,
                          "by": operator, "at": time.time()})
            return restored

    def plant_canary(self, name: str, data: bytes, reference: str) -> Version:
        """Adds a tripwire record: nothing legitimate ever opens it."""
        with self._lock:
            if name in self._versions:
                raise ValueError(f"{name} already exists")
            version = self.put(name, data)
            self._canaries[name] = reference
            self._record({"type": "canary", "name": name, "reference": reference})
            return version

    def _store(self, name: str, data: bytes, fingerprint: str, entropy: float,
               previous: Version | None, restored_from: int | None = None) -> Version:
        object_id = f"{fingerprint[:16]}-{time.time_ns()}"
        nonce = os.urandom(NONCE_LEN)
        # The file name is bound in as associated data, so an object moved to another name won't decrypt.
        with open(self._objects / object_id, "xb") as f:
            f.write(nonce + self._aes.encrypt(nonce, data, name.encode()))
        version = Version(
            name=name,
            version=previous.version + 1 if previous else 1,
            fingerprint=fingerprint,
            size=len(data),
            entropy=round(entropy, 3),
            stored_at=time.time(),
            object_id=object_id,
            restored_from=restored_from,
        )
        self._record({"type": "version", **asdict(version)})
        self._versions.setdefault(name, []).append(version)
        return version

    # --- reading ---------------------------------------------------------

    def get(self, name: str, version: int | None = None, reader: str = "unknown") -> bytes:
        """Reads a file. Opening a canary record is recorded as a trip, and the data is returned as normal."""
        data = self._read(name, version)
        if name in self._canaries:
            with self._lock:
                trip = CanaryTrip(name, reader, time.time())
                self._trips.append(trip)
                self._record({"type": "canary_trip", **asdict(trip)})
        return data

    def _read(self, name: str, version: int | None) -> bytes:
        with self._lock:
            history = self._versions.get(name)
            if not history:
                raise KeyError(name)
            if version is None:
                v = history[-1]
            elif 1 <= version <= len(history):
                v = history[version - 1]
            else:
                raise KeyError(f"{name} has no version {version}")
        blob = (self._objects / v.object_id).read_bytes()
        try:
            data = self._aes.decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], name.encode())
        except InvalidTag as e:
            raise IntegrityError(f"{name} v{v.version}: stored object was altered") from e
        if hashlib.sha256(data).hexdigest() != v.fingerprint:
            raise IntegrityError(f"{name} v{v.version}: fingerprint mismatch")
        return data

    def latest(self, name: str) -> Version | None:
        with self._lock:
            history = self._versions.get(name)
            return history[-1] if history else None

    def history(self, name: str) -> list[Version]:
        with self._lock:
            return list(self._versions.get(name, []))

    def names(self, include_canaries: bool = True) -> list[str]:
        """Everything is listed by default, as anyone browsing would see it.
        Legitimate processes pass include_canaries=False."""
        with self._lock:
            return sorted(n for n in self._versions if include_canaries or n not in self._canaries)

    def is_canary(self, name: str) -> bool:
        with self._lock:
            return name in self._canaries

    def canary_trips(self) -> list[CanaryTrip]:
        with self._lock:
            return list(self._trips)

    @property
    def file_count(self) -> int:
        with self._lock:
            return len(self._versions)

    def state_digest(self) -> str:
        """One fingerprint for the whole vault: changes whenever any file's newest version changes."""
        with self._lock:
            lines = "".join(f"{n}:{h[-1].fingerprint}\n" for n, h in sorted(self._versions.items()))
        return hashlib.sha256(lines.encode()).hexdigest()

    # --- state -----------------------------------------------------------

    def freeze(self, reason: str) -> None:
        with self._lock:
            self.frozen, self.freeze_reason, self.frozen_at = True, reason, time.time()
            self._record({"type": "freeze", "reason": reason, "at": self.frozen_at})

    def unfreeze(self, operator: str) -> None:
        with self._lock:
            self._record({"type": "unfreeze", "by": operator, "at": time.time()})
            self.frozen, self.freeze_reason, self.frozen_at = False, None, None
            if self._guard:
                self._guard.reset()

    def close(self) -> None:
        with self._lock:
            if not self.closed:
                self._record({"type": "close", "at": time.time()})
                self.closed = True

    def _check_open(self) -> None:
        if self.closed:
            raise VaultClosed("vault is shut down")

    def _record(self, entry: dict) -> None:
        with open(self._manifest, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
            f.flush()
            os.fsync(f.fileno())

    def _replay_manifest(self) -> None:
        if not self._manifest.exists():
            return
        for line in self._manifest.read_text(encoding="utf-8").splitlines():
            entry = json.loads(line)
            kind = entry.pop("type")
            if kind == "version":
                v = Version(**entry)
                self._versions.setdefault(v.name, []).append(v)
            elif kind == "freeze":
                self.frozen, self.freeze_reason, self.frozen_at = True, entry["reason"], entry.get("at")
            elif kind == "unfreeze":
                self.frozen, self.freeze_reason, self.frozen_at = False, None, None
            elif kind == "canary":
                self._canaries[entry["name"]] = entry["reference"]
            elif kind == "canary_trip":
                self._trips.append(CanaryTrip(**entry))

    def _load_or_create_key(self) -> bytes:
        path = self.root / "vault.key"
        if path.exists():
            return path.read_bytes()
        key = AESGCM.generate_key(bit_length=256)
        with open(path, "xb") as f:
            f.write(key)
        return key
