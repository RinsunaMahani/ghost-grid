"""Operator tool: review a frozen vault, roll back encrypted files, unfreeze.

    python -m databox.restore --vault vault-data                                   # review only
    python -m databox.restore --vault vault-data --apply --operator NAME           # roll back
    python -m databox.restore --vault vault-data --apply --unfreeze --operator NAME

A file is suspect if it changed in the guard's window just before the freeze, or
if its newest version looks encrypted. Rolling back never deletes anything: each
suspect's last clean version is stored again as its newest version, and the
suspect versions stay on record as evidence. The operator's name goes into the
vault's log.
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .vault import Vault, find_suspects, restore_suspects


def _when(timestamp: float) -> str:
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(timestamp))


def review(vault: Vault) -> None:
    real = vault.names(include_canaries=False)
    print(f"Vault: {vault.root}")
    print(f"  {len(real)} files, {vault.file_count - len(real)} canary records")
    print(f"  state: {'FROZEN - ' + vault.freeze_reason if vault.frozen else 'accepting backups'}")

    trips = vault.canary_trips()
    if trips:
        print(f"\nCanary records opened ({len(trips)}): someone inside the vault room browsed the files.")
        print("  Find out who before trusting this box again.")
        for trip in trips:
            print(f"  {_when(trip.at)}  {trip.name}  by {trip.reader}")

    suspects = find_suspects(vault)
    print(f"\nFiles that may be damaged: {len(suspects) or 'none'}")
    for s in suspects:
        print(f"  {s.name}: v{s.bad_version} {s.reason}; will roll back to v{s.clean_version}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review a frozen vault, roll back encrypted files and unfreeze.")
    parser.add_argument("--vault", required=True, help="the vault folder")
    parser.add_argument("--apply", action="store_true", help="roll suspect files back to their last clean version")
    parser.add_argument("--unfreeze", action="store_true", help="accept new backups again")
    parser.add_argument("--operator", help="who is doing this; recorded in the vault's log")
    args = parser.parse_args(argv)

    root = Path(args.vault)
    if not (root / "manifest.jsonl").exists():
        print(f"No vault found in {root}")
        return 1
    vault = Vault(root)
    review(vault)

    if not (args.apply or args.unfreeze):
        print("\nReview only; nothing was changed. To roll back: add --apply --operator NAME")
        return 0
    if not args.operator:
        print("\n--operator is required for changes; it is recorded in the vault's log.")
        return 2

    if args.apply:
        restored = restore_suspects(vault, args.operator)
        print(f"\nRolled back {len(restored)} file(s):")
        for v in restored:
            print(f"  {v.name}: clean v{v.restored_from} is now the newest, stored as v{v.version}")

    if args.unfreeze:
        remaining = find_suspects(vault)
        if remaining:
            print(f"\nNot unfreezing: {len(remaining)} file(s) still need rolling back. Run with --apply first.")
            return 1
        if not vault.frozen:
            print("\nThe vault was not frozen.")
        else:
            vault.unfreeze(args.operator)
            print(f"\nUnfrozen by {args.operator}. New backups will be accepted again.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
