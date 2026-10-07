# Sealed Data Box — simulation

A software model of the sealed box from [docs/research-single-box.md](../docs/research-single-box.md). Everything runs on one machine: the vault, the "race track" loop, the monitoring room and the battery.

## Run it

From the repository root:

```
pip install cryptography pytest
python -m databox.demo --list                        # what each scenario shows
python -m databox.demo                               # healthy run, 16 seconds
python -m databox.demo ransomware --vault vault-data # keep the vault so you can review it afterwards
python -m databox.restore --vault vault-data         # the operator's review (changes nothing)
python -m pytest                                     # all tests
```

Every scenario runs healthy for 7 seconds, so both ends can learn what normal lap times look like, and then the fault starts.

## Watch it live

```
pip install streamlit
python -m streamlit run databox/dashboard/app.py --server.address 127.0.0.1
```

The address flag keeps the page on this computer. Without it, Streamlit also serves it to the local network, and anyone there could start and stop runs.

Pick a scenario in the sidebar, choose when the fault starts, and press **Start**. The page updates every second:

- **The loop:** the vault room and the monitoring room joined by the fibre loop, with each signed frame drawn as a dot lapping it. A fault on the track shows where it happens: a tap that slows frames, frames that go missing, or a frame that turns red when altered. Each room shows its own status: box running, vault frozen, canary opened, clean shutdown, no power, alarm raised, silence.
- **The numbers:** frames sent, frames verified by the monitor, the box's lap time, the vault, the battery and the alarm count.
- **Lap and delivery times:** the box's lap time and the monitor's delivery time on one chart, with the alarm limit both ends learned and the moment the fault started.
- **Alarm feed:** every alarm as it is raised, marked with where it came from.

A link like `http://localhost:8501/?start=ransomware&fault=3&length=60` starts that scenario as soon as the page opens; `fault` and `length` are in seconds and both optional. A run stops itself after the time chosen in the sidebar (two minutes for a link without `length`).

After a `ransomware` run stops, the page shows the operator's side of the incident: the files that changed just before the freeze or now look encrypted, and a **Roll back and unfreeze** button. It does what the restore tool does on a real box: each file's last clean version becomes its newest version again, nothing is deleted, and the operator's name goes into the vault's log.

| Scenario | What happens | What should catch it |
|---|---|---|
| `normal` | Nothing | No alarms |
| `delay` | A relay tap adds 150 ms | Box: slow lap. Monitor: slow delivery |
| `drop` | Every 5th frame is lost | Box: lost frame. Monitor: gap |
| `alter` | Every 7th frame is changed in transit | Box: altered frame. Monitor: bad signature |
| `ransomware` | Backups start arriving encrypted | Box and monitor: vault frozen. The clean versions are still in the vault |
| `snoop` | Someone at the box browses the files and opens a canary record | Box and monitor: canary tripped |
| `battery` | A small pack runs down | A clean, announced shutdown with **no** silence alarm |
| `cut` | The box loses power without warning | Monitor: silence |

## After a freeze: review and roll back

When the guard sees a ransomware pattern, the vault freezes and refuses new backups. The operator then uses the restore tool:

```
python -m databox.restore --vault vault-data                                   # review only
python -m databox.restore --vault vault-data --apply --operator NAME           # roll back
python -m databox.restore --vault vault-data --apply --unfreeze --operator NAME
```

A file counts as possibly damaged if either:
- it **changed in the 10 seconds before the freeze**. Whatever tripped the guard wrote these, even files too small to look encrypted.
- its **newest version looks encrypted** while an earlier version was normal data.

Rolling back stores each file's last clean version again as its newest version. **Nothing is deleted**: the damaged versions stay on record as evidence, and the operator's name goes into the vault's log. The tool refuses to unfreeze while any damaged file is still waiting to be rolled back.

Rolling back is cautious on purpose. A legitimate backup that happened to land in those 10 seconds is rolled back too. Its newer version is still in the vault and can be re-sent once the freeze has been reviewed.

## Canary records

Three tripwire files are planted in the vault: door codes, supplier bank details and admin accounts. Their contents are fake, and nothing legitimate ever opens them. Opening one is recorded, and the box reports it to the monitoring room on the signed loop, so both ends raise an alarm. Each canary carries a unique reference, so a copy found anywhere else shows where it came from. Trips from earlier runs stay in the vault's log, but only new trips raise alarms.

## How the parts map to the design

| Folder | Part of the design |
|---|---|
| `vault/store.py` | Append-only, encrypted (AES-256-GCM), versioned storage. Objects are created in exclusive mode, so nothing is ever overwritten |
| `vault/guard.py` | Ransomware tripwire: many files changing at once, or files turning high-entropy (looking encrypted), freezes the vault |
| `vault/recovery.py`, `restore.py` | Finding possibly damaged files after a freeze, and the operator's review and roll-back tool |
| `vault/canary.py` | The tripwire records |
| `loop/frame.py`, `loop/chain.py` | Each frame is numbered, linked to the previous frame's hash, and signed with Ed25519. The monitoring room verifies with the **public key only** |
| `loop/ring.py` | In-memory ring of frames still on the track, so the box can check each one comes back |
| `loop/timing.py` | Lap timing: learns a normal lap, then flags slow ones |
| `sim/diode.py` | Simulated one-way link: senders never receive, receivers never send, and every frame is sent twice |
| `sim/track.py` | The fibre loop with a passive splitter to the monitoring room, plus fault injection |
| `sim/battery.py` | Battery pack with a clean shutdown at the 10% reserve |
| `box.py` | The box: sends a frame every 0.25 s and checks every lap |
| `monitor/core.py`, `monitor/scoreboard.py` | The monitoring room: verifies, times and displays; receive-only |
| `simulation.py` | One run of a scenario that can be started, watched and stopped; wires all the parts together |
| `demo.py` | The command-line demo: runs a scenario for a fixed time and prints the alarms |
| `dashboard/` | The live browser view (`app.py`) and its drawing and chart helpers (`views.py`) |

Frames carry a **fingerprint of the vault and the box's status, never the data itself**.

## Limits of this simulation

- **The one-way link is enforced by code structure, not physics.** A real box needs a hardware diode or a passive fibre splitter.
- **Everything runs on one machine,** so monitor delivery times use one clock. Two real rooms need synchronised clocks.
- **The AES key is a file next to the data** (`vault.key`, which `.gitignore` excludes). A real box keeps it in a TPM or HSM.
- **The guard's thresholds are demo values.** They must be tuned to a site's real backup pattern. A legitimate bulk update will also freeze the vault until an operator reviews it; that is deliberate.
- **Don't run the restore tool while a demo is using the same vault.** Each process keeps its own view of the vault's log.
