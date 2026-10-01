"""Canary records: tripwire files that no legitimate process ever opens.

They are named to look like the most tempting files in the vault. Opening one
inside the box is recorded, and the box reports it to the monitoring room on
the signed loop. Each carries a unique reference, so a copy that turns up
anywhere else shows where it came from. (A hosted Canarytoken would also call
home when opened elsewhere; a sealed site would point that callback at its own
network.)

All contents are fake.
"""
from __future__ import annotations

import random

from .store import Vault


def _door_codes(ref: str, rng: random.Random) -> str:
    lines = ["# door access codes - substations and pump stations"]
    lines += [f"Site {i:02d} main gate: {rng.randint(1000, 9999)}" for i in range(1, 13)]
    return "\n".join(lines + [f"# ref {ref}"])


def _bank_details(ref: str, rng: random.Random) -> str:
    lines = ["supplier,bank,branch,account"]
    lines += [f"Supplier {i:02d} (Pty) Ltd,Bank {rng.choice('ABCDE')},{rng.randint(100000, 999999)},"
              f"{rng.randint(10**9, 10**10 - 1)}" for i in range(1, 16)]
    return "\n".join(lines + [f"# ref {ref}"])


def _admin_accounts(ref: str, rng: random.Random) -> str:
    lines = ["# admin accounts - do not share"]
    lines += [f"admin-{i:02d}: {rng.getrandbits(64):016x}" for i in range(1, 9)]
    return "\n".join(lines + [f"# ref {ref}"])


TEMPLATES = {
    "access/door-codes-2026.txt": _door_codes,
    "finance/supplier-bank-details.csv": _bank_details,
    "config/admin-accounts.txt": _admin_accounts,
}


def plant_canaries(vault: Vault, rng: random.Random) -> dict[str, str]:
    """Plants any canaries not already in the vault. Returns name -> reference for the new ones."""
    planted = {}
    for name, make in TEMPLATES.items():
        if vault.latest(name):
            continue
        reference = f"GG-{rng.getrandbits(48):012x}"
        vault.plant_canary(name, make(reference, rng).encode(), reference)
        planted[name] = reference
    return planted
