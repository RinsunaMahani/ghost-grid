# Ghost Grid

Two related plans for protecting South African critical infrastructure. Both are private work in progress.

## 1. GhostGrid — decoy for critical infrastructure (`ghostgrid/`)

An air-gapped deception environment for OT networks in power, water, ports, rail and other critical sectors. It detects intruders on first contact, keeps them busy in a convincing fake site, and measures how much time the SOC gains.

- Research: [docs/research.md](docs/research.md)
- Implementation: [ghostgrid/README.md](ghostgrid/README.md)
- Status: built and verified (Modbus TCP decoy, physics engine, AI scenario director, SQLite SOC logging, and Streamlit console)

## 2. Sealed Data Box (`databox/`)

A sealed, battery-powered box that holds a site's critical records. It is watched from a separate monitoring room through a signed, lap-timed loop, and it freezes itself when it sees a ransomware pattern.

- Research: [docs/research-single-box.md](docs/research-single-box.md)
- Status: software simulation working, with a live browser view. See [databox/README.md](databox/README.md)

## Setup

From the repository root, with Python 3.11 or newer:

```
pip install -e ".[all]"     # everything; or ".[ghostgrid]", ".[live-view]" or ".[dev]" for one part
python -m pytest            # all tests for both projects
```

The tests also run on GitHub for every push (`.github/workflows/tests.yml`).

## How it all fits together

[docs/how-it-works.md](docs/how-it-works.md) explains both projects end to end: what each part does, how the parts connect, and why they were built that way. [docs/demo-runbook.md](docs/demo-runbook.md) is a seven-minute live demo of both, with the commands, what to point at, and likely questions.

## Background

- [docs/sa-landscape.md](docs/sa-landscape.md): what South Africa already has, and where each plan fits.
