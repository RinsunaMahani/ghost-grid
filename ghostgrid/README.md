# GhostGrid: Air-Gapped OT Deception Decoy

High-fidelity operational technology (OT) deception platform designed for critical infrastructure (water treatment facilities and electrical substations).

---

## Key Capabilities & Engineering Architecture

1. **Procedural Identity Engine**:
   - Generates unique, completely neutral South African facility names (no real utilities or real substations impersonated).
   - Randomizes vendor-matched MAC OUIs, serial numbers, firmware versions, and dynamic relative register offsets per install seed.
   - Arms randomized honeytoken register addresses and values (no static honeytoken fingerprints).
   - Automatically saves and reuses identity on restart (`ghostgrid_identity.json`) to maintain continuity.

2. **First-Principles Continuous Physical Simulations**:
   - **Water Sector Profile**: Closed-loop supervisory reservoir level control around `LEVEL_SETPOINT_PCT` (prevents artificial 100% overflow or empty reservoir anomalies); dual intake/booster pump staging (+1,100 m³/h); continuous decimal integration; SANS 241 chemical dosing (chlorine, turbidity, pH); dry-run and high/low level safety interlocks aligned with alarm limit registers.
   - **Power Sector Profile**: Calibrated true 3-phase Active Power (~46.2 MW baseline from $P = \sqrt{3} \times V_{\text{LL}} \times I_{\text{tot}} \times \text{pf}$ with zero tick-1 jump); continuous $I^2$ transformer thermal dynamics; Buchholz gas relay isolated to internal electrical/earth faults; 50.00 Hz SA Grid Code frequency dynamics.

3. **Sub-Millisecond Modbus TCP Server**:
   - Non-blocking SQLite event logging offloaded to background batch worker thread (< 1ms protocol latency).
   - High-resolution Windows timer support (`timeBeginPeriod(1)`).
   - Fully compliant Modbus exception handling (0x02 `ILLEGAL_DATA_ADDRESS` for unmapped registers, 0x03 `ILLEGAL_DATA_VALUE` for invalid coils).
   - Resilient Unit 0 broadcast handling (full PDU consumed from stream to prevent buffer desynchronization; no reply sent per Modbus standard).

4. **Forensics & Time Gained Calculation**:
   - Accurate **Time Gained for SOC** calculation clustered by attacker IP with quiet-gap separation (>1800s / 30 mins) to prevent multi-day inactivity overcounting.
   - Stale session cleanup executed safely on decoy startup only.
   - Per-visit alerting (a visit ends after 30 minutes of silence): one reconnaissance alert per attacker IP per visit, and one unauthorized-write alert for each new tag an IP writes to, once it passes `alert_threshold_writes`. Repeated writes to the same setpoint stay quiet, while an escalation to a new target (pump stop, breaker trip, shutdown) always raises a fresh alert. Honeytoken traps fire immediately.
   - Read-only SQLite dashboard mode prevents write lock contention or crashes on read-only container mounts; all database queries automatically close connections immediately.

5. **Hardened Scenario Director & Management Isolation**:
   - Background autonomous AI/offline scenario director limited to an allow-list of operational setpoints, each within a plausible range (`core/director/limits.py`). Commands, trips, alarm limits and protection settings are off limits, so a storyline can never cause a trip, directly or through a setting.
   - Holding register setpoints actively drive physical simulation behavior.
   - Docker Compose isolates local AI model on an internal bridge network (`internal: true`).
   - SOC screen bound strictly to `127.0.0.1` behind an operator password barrier (`GHOSTGRID_ADMIN_PASSWORD`).

---

## Quickstart

### 1. Run Directly with Python

```bash
# Start water treatment decoy
python -m ghostgrid.run_decoy --sector water --port 1502

# Or run power substation decoy
python -m ghostgrid.run_decoy --sector power --port 1502

# Direct script execution is also fully supported:
python ghostgrid/run_decoy.py --sector water --port 1502
```

### 2. Run with Docker Compose

Set the mandatory admin password in your environment:
```bash
cd ghostgrid
export GHOSTGRID_ADMIN_PASSWORD="your-strong-operator-password"
docker compose up -d
```

- **Modbus TCP**: Port `502` (Decoy service on `ot-network`; inside the container it listens on 5020, because it runs as an unprivileged user)
- **SOC Dashboard**: `http://127.0.0.1:8501` (Restricted to loopback/management network)
- **Local AI Runtime (Ollama)**: Running on `internal-ai-network` (isolated, no host ports exposed)

#### Container hardening
The decoy is the one service visitors talk to, so both GhostGrid containers run locked down: an unprivileged user (UID 10001), a read-only filesystem except the `/data` volume, no Linux capabilities, `no-new-privileges`, and fixed memory, CPU and process limits. Even a bug in the decoy would land a visitor in a box where they can do very little.

The Modbus server also limits connections. It allows 64 open connections in total and 16 from one address, and closes a connection that stays silent for 30 minutes. A full real PLC also refuses new connections. All three limits are set in `network.modbus` in the site config.

#### Sending alerts to your SIEM
A SOC works in its SIEM, not in a separate console, so the decoy can forward every alert the moment it is recorded. There are two outputs, and you can use either or both:

- **Syslog over UDP** (RFC 5424) to a collector, with the alert as JSON or as **CEF**, which Splunk, QRadar, ArcSight, Microsoft Sentinel and Wazuh read natively. UDP only ever sends, so the feed can cross a one-way data diode into the SOC network without giving anyone on the OT side a way back.
- **A JSON Lines file**, one alert per line, for a log shipper such as Filebeat, Fluent Bit or a Wazuh agent. Rotate it with your usual log rotation.

Each alert carries the time (UTC), severity, alarm type, ATT&CK for ICS technique, source address and port, session ID, decoy name and description. Set it up in `logging.siem` in the site config, or with the environment variables shown in `docker-compose.yml`. A collector that can't be reached is reported once in the decoy's log and never slows the decoy down. The SQLite database stays the primary record either way.

To check it works before involving a real SIEM, run the stand-in listener and point the decoy at it:

```bash
python -m ghostgrid.siem_listen --port 5514          # prints each alert as it arrives
GHOSTGRID_SYSLOG_HOST=127.0.0.1 GHOSTGRID_SYSLOG_PORT=5514 GHOSTGRID_SYSLOG_FORMAT=cef \
  python -m ghostgrid.run_decoy --sector water --port 1502
```

#### The Ollama image is pinned
An air-gapped site shouldn't drift to whatever `latest` was on the day of the pull, so `docker-compose.yml` pins Ollama 0.40.0 by its registry digest. The digest guarantees the identical image even if the tag were moved. To upgrade, look up the new release's digest and set it in `ghostgrid/.env`:
```bash
docker buildx imagetools inspect ollama/ollama:<version>    # copy the top "Digest:" line
# ghostgrid/.env:   OLLAMA_IMAGE=ollama/ollama:<version>@sha256:...
```

#### Preloading the Local AI Model (Ollama)
Because the `ghostgrid-llm` container is strictly air-gapped on an internal Docker bridge network (`internal: true` with no external gateway), Ollama cannot pull models over the internet inside the container.

To load the model into the persistent volume, use a temporary Ollama container on the default network (which can reach the internet), then remove it. Run this once, from the `ghostgrid` folder, before `docker compose up`:
```bash
docker run -d --name ollama-preload -v ghostgrid_ollama-data:/root/.ollama ollama/ollama:0.40.0@sha256:1bef639749741b375e9a1eb2c1346fb57ce52f5432de1f74846e44ccc18e1687
docker exec ollama-preload ollama pull qwen2.5:1.5b
docker rm -f ollama-preload
```
The image's entrypoint is already `ollama`, and `ollama pull` needs a running Ollama server, which is why the model is pulled with `docker exec` inside a running container. The volume name comes from the Compose project name (the folder name, `ghostgrid`); check it with `docker volume ls` if you run Compose from a different folder.

> **Note**: If the AI model is not preloaded or Ollama is offline, GhostGrid automatically uses its built-in realistic South African operational storylines seamlessly.

---

## Running Test Suite

```bash
python -m pytest ghostgrid/tests -v
```
