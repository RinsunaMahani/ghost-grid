# Demo runbook

A live demo of both projects in about seven minutes. Commands are for Windows `cmd`, run from the repository root.

**The story in one line:** assume the intruder gets in. GhostGrid notices them within seconds and buys the SOC time; the Sealed Data Box makes sure the critical records survive, and proves it.

## Set up

**The day before**

```
pip install -e ".[all]"
python -m pytest
```

Every test should pass. Then do one full dry run of this script on the laptop you'll present from.

**Fifteen minutes before**

- Plug the laptop in and close heavy apps. The data box simulation runs on the laptop's own threads, and a struggling CPU shows up as slow laps.
- Open four terminals and start everything:

| Terminal | Command | What it is |
|---|---|---|
| 1 | `python -m ghostgrid.siem_listen --port 5514` | Stand-in SIEM: prints each alert it receives |
| 2 | `set GHOSTGRID_SYSLOG_HOST=127.0.0.1` then `set GHOSTGRID_SYSLOG_PORT=5514` then `set GHOSTGRID_SYSLOG_FORMAT=cef` then `python -m ghostgrid.run_decoy --sector water --port 1502` | The decoy |
| 3 | `set GHOSTGRID_ADMIN_PASSWORD=pick-a-demo-password` then `python -m streamlit run ghostgrid/dashboard/app.py --server.address 127.0.0.1 --server.port 8501` | SOC console |
| 4 | `python -m streamlit run databox/dashboard/app.py --server.address 127.0.0.1 --server.port 8502` | Data box live view |

- Log in to the SOC console at `http://127.0.0.1:8501` and leave it on the **Alerts & ATT&CK** tab.
- Have a Modbus client ready to play the visitor: a GUI client such as QModMaster or Modbus Poll is the most visual. Point it at the decoy (`127.0.0.1`, port 1502, unit 1). Pick two addresses from the console's **Process View → All registers** list: `LEVEL_SETPOINT_PCT`, and one holding register marked **Honeytoken**. The console lists protocol addresses, counting from 0. If your client counts from 1, as Modbus Poll does by default, add one, or the read will hit an unmapped address and get an error.
- If Windows Firewall asks about Python, allow **private networks only**.

## Part 1: GhostGrid (about 3½ minutes)

1. **The empty console.** Point at *Time Gained* (zero) and the quiet alarm stream. *"Nothing legitimate is ever configured to talk to this device, so the first packet it receives is already an alarm. No false positives by design."*
2. **The visitor arrives.** Connect the Modbus client and read the normal setpoint. Within seconds: a `FIRST_CONTACT` alarm (T0846), a new row under **Sessions & Commands**, and *Time Gained* starting to count. Point at terminal 1: *"and it's already in the SIEM"*, showing the CEF line with the visitor's address.
3. **The plant feels real.** Open **Process View**: live values with real units, moving with believable physics. From the client, write a level setpoint below the current level: values are raw, in tenths of a percent, so `700` means 70.0%. Within a second **Pump 1 stops**, inflow drops to zero and the net flow turns negative. The 50-megalitre reservoir then drains at a realistic, slow rate. *"Writes have consequences, which keeps a visitor experimenting."* The write also raises a `CRITICAL` unauthorized-write alarm (T0855).
4. **The trap.** Read the honeytoken address. A `HONEYTOKEN_TRIGGER` alarm appears straight away (T0861), because nothing legitimate ever reads that register.
5. **Evidence.** Click **Export all alerts (CSV)**. *"Full records in UTC, ready for the incident report, and they line up with the SIEM."*

## Part 2: Sealed Data Box (about 3½ minutes)

Use the live view at `http://127.0.0.1:8502`. Each link below starts a scenario on its own.

1. **The idea.** Point at the drawing: the sealed box in the vault room, the fibre loop, and the monitoring room's receive-only tap. *"Every quarter second the box sends a signed, numbered frame round the loop, like a car lapping a track. The monitoring room holds only the public key: it can check every frame, but never forge one."*
2. **A tap on the fibre:** `http://127.0.0.1:8502/?start=delay&fault=5&length=40`. After five healthy seconds the frames turn amber and slow down, both lines on the chart jump from about 0.5 ms to about 150 ms, and *both* ends raise alarms independently.
3. **Ransomware:** `http://127.0.0.1:8502/?start=ransomware&fault=5&length=20`. Encrypted backups start arriving, the vault freezes within seconds, and the monitoring room learns about it over the loop. When the run stops, the recovery panel lists the damaged files. Click **Roll back and unfreeze**. *"Every file is back to its clean version, and nothing was deleted: the encrypted versions stay on record as evidence, with the operator's name in the log."*
4. **If you have time: `cut` versus `battery`.** A cut raises a silence alarm. A flat battery doesn't, because the box sends a *signed* "shutting down" message first. *"An attacker can't fake that message without the private key."*

## Questions you'll likely get

- **"Can't an attacker tell it's a decoy?"** Each install gets its own identity: vendor, firmware, serial, MAC and register layout. The physics react to writes, and the responses follow the Modbus standard, including its error codes. A determined expert with enough time might still tell; the point is early warning and time gained, not perfect deception.
- **"What about false positives?"** None by design: no legitimate system talks to the decoy.
- **"Isn't putting AI in there risky?"** It never sees what the visitor sends, only counts. It can only nudge a short allow-list of setpoints within plausible ranges, never commands, trips, alarm limits or protection settings. The decoy works the same without it.
- **"How does this reach a real SOC?"** Syslog in CEF or JSON, which Splunk, QRadar, Sentinel and Wazuh read natively. UDP only sends, so the feed can cross a one-way data diode.
- **"Why not just keep backups?"** Ransomware encrypts backups too. The vault is append-only, freezes itself on the encryption pattern, and proves its health on a loop the attacker can't forge.
- **"What's real and what's simulated?"** GhostGrid runs as real software today. The data box is a software simulation: the next step is hardware, meaning a data diode or passive splitter, and a TPM for the key.

## If something goes wrong

- **The data box shows slow-lap alarms in a healthy run.** The laptop is too busy. Close apps, plug in, and start the scenario again.
- **The visitor's client can't connect from a second laptop.** Run the client on the presenting laptop against `127.0.0.1` instead.
- **The SOC console says "Decoy not running".** Terminals 2 and 3 must run from the same folder, so they share the decoy's files.
- **No Modbus client at all.** Show the console from a previous dry run, and spend the time on the data box: it needs nothing but the browser.
