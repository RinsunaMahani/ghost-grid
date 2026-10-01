"""Recovery after a freeze: find files that may be damaged, and roll them back.

Two kinds of suspect:
- changed just before the freeze: the file was changed inside the guard's window
  before the freeze. Whatever tripped the guard wrote these, whatever they look
  like (small encrypted files can't be recognised by entropy). As with the guard,
  a file's first version is never counted as a change.
- looks encrypted: the newest version is high-entropy while an earlier version was
  normal data. This also catches slower damage that started before the window.

Rolling back never deletes anything; the suspect versions stay on record as evidence.
"""
from __future__ import annotations

from dataclasses import dataclass

from .guard import DEFAULT_WINDOW_S, HIGH_ENTROPY, LOW_ENTROPY
from .store import Vault, Version

CHANGED_BEFORE_FREEZE = "changed just before the freeze"
LOOKS_ENCRYPTED = "looks encrypted"


@dataclass(frozen=True)
class Suspect:
    name: str
    bad_version: int
    clean_version: int
    reason: str


def _last_clean(versions: list[Version]) -> Version:
    """The newest version that looks like normal data, or else simply the newest one."""
    normal = [v for v in versions if v.entropy < LOW_ENTROPY]
    return normal[-1] if normal else versions[-1]


def find_suspects(vault: Vault, window_s: float = DEFAULT_WINDOW_S) -> list[Suspect]:
    found = []
    window_start = vault.frozen_at - window_s if vault.frozen and vault.frozen_at else None
    for name in vault.names(include_canaries=False):
        history = vault.history(name)
        newest = history[-1]
        if len(history) < 2 or newest.restored_from is not None:
            continue   # never changed, or an operator already rolled it back
        if window_start is not None:
            first_change = next((i for i, v in enumerate(history) if i > 0 and v.stored_at >= window_start), None)
            if first_change is not None:
                clean = _last_clean(history[:first_change])
                found.append(Suspect(name, newest.version, clean.version, CHANGED_BEFORE_FREEZE))
                continue
        if newest.entropy > HIGH_ENTROPY:
            normal = [v for v in history if v.entropy < LOW_ENTROPY]
            if normal:
                found.append(Suspect(name, newest.version, normal[-1].version, LOOKS_ENCRYPTED))
    return found


def restore_suspects(vault: Vault, operator: str, suspects: list[Suspect] | None = None) -> list[Version]:
    """Brings back each suspect's clean version as its newest."""
    if suspects is None:
        suspects = find_suspects(vault)
    return [vault.restore(s.name, s.clean_version, operator) for s in suspects]
