"""Runs the whole sealed-box simulation on one machine, from the command line.

    python -m databox.demo                          # healthy run
    python -m databox.demo ransomware               # pick a scenario
    python -m databox.demo --list                   # what each scenario shows
    python -m databox.demo ransomware --vault vault-data   # keep the vault to review it afterwards

For a live view in the browser: python -m streamlit run databox/dashboard/app.py
"""
from __future__ import annotations

import argparse

from .simulation import SCENARIOS, BackupFeed, Simulation, Snoop, run_scenario, seed_vault

__all__ = ["SCENARIOS", "BackupFeed", "Simulation", "Snoop", "main", "run_scenario", "seed_vault"]


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the sealed data box simulation.")
    parser.add_argument("scenario", nargs="?", default="normal", choices=SCENARIOS)
    parser.add_argument("--seconds", type=float, default=16.0, help="how long to run (default 16)")
    parser.add_argument("--vault", help="keep the vault in this folder instead of a temporary one")
    parser.add_argument("--list", action="store_true", help="describe the scenarios and exit")
    args = parser.parse_args(argv)

    if args.list:
        for key, text in SCENARIOS.items():
            print(f"{key:<11} {text}")
        return

    print(f"Scenario '{args.scenario}': {SCENARIOS[args.scenario]}")
    print("The box holds the private signing key; the monitoring room holds only the public key.\n")
    report = run_scenario(args.scenario, seconds=args.seconds, vault_dir=args.vault)

    print("\nAlarm summary:")
    if not report.counts:
        print("  none")
    for (source, kind), count in sorted(report.counts.items()):
        print(f"  {source:<8} {kind:<17} x{count}")


if __name__ == "__main__":
    main()
