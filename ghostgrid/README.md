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
   - Background autonomous AI/offline scenario director strictly prevented from flipping command coils or safety trips (`PUMP_1_CMD`, `EMERGENCY_SHUTDOWN_CMD`, breakers).
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

- **Modbus TCP**: Port `502` (Decoy service on `ot-network`)
- **SOC Dashboard**: `http://127.0.0.1:8501` (Restricted to loopback/management network)
- **Local AI Runtime (Ollama)**: Running on `internal-ai-network` (isolated, no host ports exposed)

#### Preloading the Local AI Model (Ollama)
Because the `ghostgrid-llm` container is strictly air-gapped on an internal Docker bridge network (`internal: true` with no external gateway), Ollama cannot pull models over the internet inside the container.

To load the model into the persistent volume, use a temporary Ollama container on the default network (which can reach the internet), then remove it. Run this once, from the `ghostgrid` folder, before `docker compose up`:
```bash
docker run -d --name ollama-preload -v ghostgrid_ollama-data:/root/.ollama ollama/ollama:latest
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
