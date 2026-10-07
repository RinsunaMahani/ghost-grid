# How it all works and fits together

This repository holds two separate defences for critical infrastructure. They answer two different questions:

| | GhostGrid | Sealed Data Box |
|---|---|---|
| **Question** | Someone is inside the OT network. How do we spot them early and slow them down? | The site's most important records must survive anything. How do we keep them safe and *prove* they still are? |
| **Idea** | A convincing fake control system that no legitimate person ever touches, so any contact at all is an alarm | A sealed, battery-powered box that only takes backups, never lets data out, and reports its health on a loop watched from another room |
| **What it protects** | Time: every minute an intruder spends on the decoy is a minute the SOC gains | Data: clean copies of the records, plus proof they haven't been touched |
| **Folder** | `ghostgrid/` | `databox/` |

They share nothing in code. They share a philosophy: **assume the attacker gets in, and design so that being in does them little good and gets them noticed fast.**

---

## Part 1: GhostGrid

### The idea in one paragraph

A real plant's control network is full of PLCs: small industrial computers that run pumps, valves and breakers and talk a protocol called Modbus TCP. GhostGrid pretends to be one of those PLCs. Nothing legitimate is ever configured to talk to it, so **the first packet it receives is already suspicious**. From then on it behaves like a real plant: values move with believable physics, setpoints change how the process behaves, and the visitor can spend hours mapping it. Meanwhile every request is logged, alarms go to the SOC, and the console counts the **time gained**: how long the visitor has been busy with the decoy instead of the real plant.

### The parts and how a request flows through them

```
                    ┌──────────────────────── the decoy process (run_decoy.py) ─────────────────────────┐
                    │                                                                                    │
 visitor ──TCP 502──▶ ModbusServer ──reads/writes──▶ StateEngine ◀──every tick── sector profile (physics) │
                    │      │                            │   ▲                                            │
                    │      │ log every request          │   └── small setpoint drift ── ScenarioDirector │
                    │      ▼                            │                                  │ (local AI or │
                    │  EventLogger (SQLite)             │ writes live values               │  built-in    │
                    │  sessions · requests · alerts     ▼ every tick                       │  storylines) │
                    └──────┬─────────────────── ghostgrid_state.json ──────────────────────┘──────────────┘
                           │ read-only                   │ read-only
                           ▼                             ▼
                      SOC dashboard (Streamlit, 127.0.0.1 only, operator password)
```

**1. Identity (`core/identity/generator.py`).** When the decoy starts for the first time it invents a whole site: a facility name, a sector (water or power), a vendor, model, firmware, serial number and MAC address that belong together, and a register map with every tag's address, scale and unit. Two things make it hard to tell apart from a real PLC, and from other copies of GhostGrid:

- **It is saved** (`ghostgrid_identity.json`) and reused on every restart, so the "PLC" doesn't change personality overnight.
- **The register layout differs per install.** Which addresses are used, and which tag sits where, is drawn at random, with gaps like the spare registers real maps have. If every GhostGrid looked the same, one scan would expose them all.

Some tags are **honeytokens**: registers that look valuable, such as a vendor calibration password, a safety-interlock bypass or a telemetry encryption key, but that nothing legitimate would ever read.

**2. Physics (`profiles/water`, `profiles/power`, run by `core/state/engine.py`).** A background thread steps the process forward once a second (`tick_interval_seconds` in the config):

- *Water:* a reservoir with pumps filling it and demand draining it. Pump 1 switches on and off around the level setpoint, much like a real level controller. Chlorine, turbidity, pH and pressure follow from what the pumps and valves are doing.
- *Power:* a substation with grid frequency near 50 Hz, bus voltage, feeder currents, a tap changer and transformer temperature.

The important property: **writes have consequences.** Change the level setpoint and the reservoir really settles at the new level, a few minutes later, at a realistic rate. Stop a pump and the level falls. A visitor who experiments sees a plant that reacts, which is what keeps them engaged. Trips can reset themselves after 30 seconds (`auto_recovery`) so the decoy doesn't stay "broken" after an experiment.

Each tick also writes the live values to `ghostgrid_state.json`, *off* the request path, so the console can show them without slowing the decoy down.

**3. The Modbus server (`core/protocol/`).** It answers the standard read and write functions from the live state, with a small processing delay like a real PLC. Its behaviour copies real devices on purpose:

- an address that isn't mapped gets the proper Modbus error (illegal data address), not silence;
- device-identification requests return the invented vendor, model and firmware;
- broadcast messages get no reply, as the standard says.

It also protects itself. It allows 64 open connections in total and 16 from one address, and closes a connection that has been silent for 30 minutes. Real PLCs also have a small, fixed connection table. The timeout is long on purpose, because a visitor who keeps the connection open is exactly what we want.

**4. The scenario director (`core/director/`).** Every minute or so it writes a short "operational storyline" (*"Afternoon demand peak, booster pump on standby"*) and may nudge a setpoint slightly, so the plant isn't suspiciously static. It can use a small local AI model through Ollama, or fall back to built-in storylines when there is no model, and the decoy works the same either way. Two safety rules hold:

- **It can only change an allow-list of operational setpoints**, each inside a plausible range (`core/director/limits.py`): the level, pressure and dosing setpoints for water, and the tap changer for power. Commands, trips, alarm limits and protection settings are all off limits. That last part matters because settings can cause trips indirectly: a raised low-level limit trips the pumps, and a lowered overcurrent pickup trips a feeder. Anything else the model suggests is ignored, and the SOC log records only what actually changed.
- **It never sees what the visitor typed.** It only receives counts (connections, requests, writes). So the visitor can't steer the AI model through the decoy.

**5. The event logger (`core/logger/db.py`).** Every connection becomes a *session* and every request a *row*. Writes to SQLite happen on a background thread through a queue, so logging never delays a reply. Alarms are raised as activity happens:

| Alarm | When | Severity | ATT&CK for ICS |
|---|---|---|---|
| `FIRST_CONTACT` | Any connection at all | High | T0846 Remote System Discovery |
| `RECON_SCAN` | A visitor passes the request threshold in one visit | Medium | T0846 |
| `UNAUTHORIZED_WRITE` | A write to a tag not yet written this visit | Critical | T0855 Unauthorized Command Message |
| `HONEYTOKEN_TRIGGER` | Any read or write of a honeytoken | Critical | T0861 Point & Tag Identification (read) / T0836 Modify Parameter (write) |

Every alarm can also be **forwarded to the SOC's SIEM** the moment it is committed: syslog over UDP, as JSON or CEF, or a JSON-lines file for a log shipper (`core/logger/forward.py`). UDP syslog only sends, so the alert feed can cross a one-way data diode, the same idea the data box uses.

Write alarms fire once per new target per *visit*. Repeating the same setpoint write stays quiet, but moving on to a new target (a pump, a breaker, the shutdown coil) always raises a fresh alarm, because that's escalation. A **visit** ends after 30 minutes of silence from an address, and the next contact starts a new visit with fresh alarms.

**6. Time gained.** The headline number. For each address, its sessions are merged into visits (again split by 30-minute gaps), and the lengths of all visits are added up. Merging matters: a visitor who reconnects every few seconds shouldn't count ten times over, and two visits a day apart shouldn't count as one 24-hour visit.

**7. The SOC console (`dashboard/app.py`).** A Streamlit page, reachable only on `127.0.0.1` and only with the operator password. Five wrong passwords lock everyone out for a minute, and reloading the page doesn't reset that. It opens the database **read-only**, so the console can never change the evidence. It shows the four headline numbers, the alarm stream, every session and command, the live process values with their real units, and the armed honeytokens. If the live values stop updating it says so, rather than showing old numbers as if they were current. Each table can be **exported as evidence**: a CSV of every record (full session IDs, every column, UTC times that line up with the SIEM), built only when the button is clicked.

### How it's deployed (`docker-compose.yml`)

Three containers on three separate networks:

```
   OT network (where a visitor would be)          management network            internal-only network
 ───────────────────────────────────────────    ──────────────────────        ───────────────────────
            ghostgrid-decoy :502  ──────────── shared /data volume ──────────── ghostgrid-llm (Ollama)
                                                      │ (read-only)               no internet, no ports
                                              ghostgrid-dashboard
                                              127.0.0.1:8501 only
```

- The **decoy** is the only thing a visitor can reach. It is also the most locked down: an unprivileged user, a read-only filesystem except `/data`, no Linux capabilities, and memory, CPU and process limits.
- The **dashboard** is on the management side and bound to loopback.
- The **AI model** sits on a network with no route out at all (`internal: true`), so it cannot leak anything or be reached from outside. Its model is loaded once in advance, and its image should be pinned to an exact version.

### Why it's built this way

- **Zero false positives by design.** A real system has normal traffic to tell apart from attacks. The decoy has none, so every alarm means something.
- **Engagement over blocking.** A firewall that drops the visitor teaches them to go elsewhere. A plant that seems real keeps them occupied, and that time belongs to the defenders.
- **Air-gapped.** Nothing calls out to the internet: no cloud AI, no telemetry. It suits sites that can't allow outbound connections, and it can't be used as a stepping stone outwards.

---

## Part 2: Sealed Data Box

### The idea in one paragraph

Put a site's critical records (designs, safety procedures, key accounts) in one sealed, battery-powered box. The box **accepts backups, but nothing ever reads data out over the network**. It proves it's healthy by sending a signed, numbered "heartbeat" frame every quarter second around a fibre loop, like a car lapping a race track. Engineers in a **separate monitoring room** watch every lap through a passive tap. If a lap is late, missing, altered, or stops altogether, someone is interfering, and both ends notice.

### The parts

```
 VAULT ROOM                                                        MONITORING ROOM
┌──────────────────────────────────┐                        ┌──────────────────────────────┐
│  backups ──▶ Vault (encrypted,   │                        │                              │
│              append-only)        │   frames out ──▶       │  passive tap (receive only)  │
│     ▲   Guard (ransomware        │  ════════════════╗     │      │                       │
│     │   tripwire) · Canaries     │                  ║─────┼──────┘ MonitorCore:          │
│  Box: signs a frame every 0.25 s │  ◀── frames back ║     │   verify signature (public   │
│       checks every lap returns   │  ════════════════╝     │   key only), check order,    │
│       on time and unchanged      │       fibre loop       │   time delivery, read status │
│  Battery (clean stop at 10%)     │                        │   → Scoreboard / live view   │
└──────────────────────────────────┘                        └──────────────────────────────┘
```

**The vault (`vault/store.py`).** Files are encrypted with AES-256-GCM, with each file's name bound into the encryption so a file can't be swapped for another. Storage is **append-only**: a new backup becomes a new version, and old versions are never overwritten or deleted. Even a successful attack can only add bad versions on top of good ones.

**The guard (`vault/guard.py`).** It watches what arrives. Two patterns mean ransomware:

- **Many files changing at once** (mass change inside a 10-second window);
- **Files turning into random-looking data** (high entropy, which is what encryption looks like).

Either one **freezes** the vault: it refuses new backups until an operator has reviewed what happened.

**Recovery (`vault/recovery.py`, `restore.py`).** After a freeze, the restore tool lists suspect files: files that changed in the window before the freeze, or whose newest version looks encrypted while an earlier one didn't. Rolling back stores each file's last clean version again as its newest. Nothing is deleted, so the damaged versions stay as evidence, and the operator's name is recorded. The vault refuses to unfreeze while suspects remain.

**Canary records (`vault/canary.py`).** Three fake files that look worth stealing: door codes, supplier bank details and admin accounts. Nothing legitimate ever opens them. Opening one is logged, reported on the loop, and alarmed at both ends. Each carries a unique reference, so if a copy turns up elsewhere, you know where it came from.

**The loop (`loop/`).** This is the heart of the design.

- *Frames (`frame.py`, `chain.py`):* each frame has a sequence number, a timestamp, the hash of the previous frame and a status summary (a fingerprint of the vault, never its contents). It is signed with the box's **Ed25519 private key**. The monitoring room holds only the **public key**: it can check every frame but can never forge one. Because each frame contains the previous one's hash, the frames form a chain, and removing or reordering one breaks it.
- *Lap timing (`timing.py`):* both ends learn what a normal lap or delivery time looks like during the first few seconds, from the median, so a fault starting early doesn't spoil it. After that, anything well beyond normal is flagged, with a 50 ms floor so the simulation's own jitter is ignored: here the "fibre" is threads on a laptop, which a busy moment can stall for 30–40 ms. Real hardware laps take microseconds and could use a far lower floor.
- *The ring (`ring.py`):* the box remembers which frames are still on the track, so it notices one that never comes back.

**The one-way link (`sim/diode.py`).** The monitoring room *receives only*. In the simulation that's enforced by code structure: the receiver has no send method. A real installation would use a hardware data diode or a passive fibre splitter, where sending back is physically impossible. Because nothing can answer, every frame is simply sent twice, and the monitor ignores the second copy.

**The monitor (`monitor/core.py`).** For each frame it checks:

1. **Signature:** was it really signed by the box? If not, "bad signature".
2. **Order:** is it the next number? A skipped number is a "gap". An old frame arriving again is a "replay". A frame that doesn't link to the previous one is a "chain break".
3. **Timing:** did it take far longer than normal? That's "slow delivery".
4. **Status:** does the box report a frozen vault, a canary opened, or a clean shutdown?
5. **Silence:** no genuine frames for 2 seconds means the box is off, the fibre is cut or the track is blocked.

Each problem is reported once. An altered frame raises one "bad signature" alarm. It isn't reported again as a gap when the next good frame arrives, and its second copy from the link doesn't count twice.

**The battery (`sim/battery.py`).** When the pack reaches its 10% reserve, the box sends a **signed** "shutting down" status and stops cleanly. The monitor then knows the silence that follows is expected and doesn't raise an alarm. An unannounced silence, as when power is cut, is always an alarm. The difference between those two is the point: an attacker can't fake the announcement without the private key.

### What each scenario demonstrates

| Scenario | What happens | Who notices, and how |
|---|---|---|
| `normal` | Nothing | Nobody: no false alarms |
| `delay` | A relay on the fibre adds 150 ms (someone copying traffic in the middle) | Both ends: laps and deliveries exceed the learned limit |
| `drop` | Every 5th frame is lost | Box: a frame never came back. Monitor: gaps |
| `alter` | Every 7th frame is changed in transit | Box: the frame came back different. Monitor: bad signature |
| `ransomware` | Backups start arriving encrypted | Guard freezes the vault; the frozen status reaches the monitor on the loop |
| `snoop` | Someone at the box opens a canary | Box and monitor: canary tripped |
| `battery` | The pack runs down | A clean, announced shutdown with **no** silence alarm |
| `cut` | Power lost without warning | Monitor: silence |

`demo.py` runs one scenario in the terminal. `dashboard/` shows the same thing live in the browser: the loop with frames lapping it, the tiles, the timing chart and the alarm feed. After a `ransomware` run it also shows the operator's side of the incident: the damaged files, and a button that rolls them back and unfreezes the vault, exactly as the restore tool does. `simulation.py` is the one place where all the parts are wired together, used by both.

### Why it's built this way

- **Two independent witnesses.** The box checks its own laps, and the monitor checks them separately with only a public key. To hide tampering, an attacker would have to fool both, and they can't sign frames.
- **Status, never data, on the loop.** Even someone tapping the fibre learns only that the vault is healthy, not what's in it.
- **Freeze rather than fight.** The box doesn't try to clean up an infection automatically. It stops accepting anything and waits for a human, with every clean version still there.
- **Silence is information.** Frames every quarter second mean an outage or a cut is noticed within two seconds, and the battery announcement separates a planned stop from an attack.

### What the simulation doesn't yet prove

All of this runs on one computer, which leaves gaps a real build must close:

- the one-way link is code, not hardware (needs a data diode or passive splitter);
- the encryption key sits in a file next to the data (needs a TPM or HSM);
- both "rooms" share one clock (two real rooms need synchronised clocks for delivery timing);
- the guard's thresholds are demo values (they must be tuned to the site's real backup pattern).

A small hardware prototype, such as a single-board computer with a TPM, a fibre loop and a cheap passive splitter, would be the convincing next step.

---

## How the two fit together

They defend different moments of the same story:

```
 intruder reaches the OT network ──▶ touches GhostGrid ──▶ SOC alerted within seconds, intruder kept busy
                                                                           │
                         if they still reach the real systems              ▼
 ransomware / tampering ─────────────▶ Sealed Data Box ──▶ vault freezes, clean copies kept,
                                                          monitoring room sees it on the loop
```

- **GhostGrid buys time** at the *start* of an intrusion: early detection and a measured head start for the SOC.
- **The data box limits the damage** at the *end*: whatever happens on the network, the critical records survive with proof of their integrity.

Both are built for sites that can't depend on the internet. Neither calls out, both are watched from a separate place, and both treat "something touched this" as the alarm.

## Where to look in the code

| You want to understand… | Start with |
|---|---|
| How the decoy starts and what it wires together | `ghostgrid/run_decoy.py` |
| Why the decoy looks like a real, unique PLC | `ghostgrid/core/identity/generator.py` |
| How the plant reacts to writes | `ghostgrid/profiles/water/simulation.py` |
| How alarms and time gained are worked out | `ghostgrid/core/logger/db.py` |
| How the data box run is assembled | `databox/simulation.py` |
| How frames are signed and checked | `databox/loop/chain.py` |
| What the monitoring room concludes from frames | `databox/monitor/core.py` |
| How ransomware is caught and rolled back | `databox/vault/guard.py`, `databox/vault/recovery.py` |
