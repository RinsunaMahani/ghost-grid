# Sealed Data Box — Research

*Compiled 2026-09-28. Working title. A separate plan from GhostGrid.*

**The proposal:** one self-contained box holds a building's **critical data**. Data **circulates only inside the box**. The box runs on its **own independent power supply (batteries)**, not the building's mains.

**The short answer:** the research supports it, and the battery part is stronger than it might look. Data can leak out of a computer **through its power cable**, and the standard power filters on equipment don't stop it. A box that runs on batteries with no mains connection removes that path. Two design questions matter most: how the batteries get charged, and how data gets in and out (§4).

---

## 0. Why this matters in South Africa

Every major incident at a South African critical-infrastructure operator so far has hit **IT systems and data**:

| When | Who | What happened |
|---|---|---|
| Jul 2019 | City Power (Johannesburg) | Ransomware encrypted databases, applications and the network. Up to ~250,000 customers couldn't buy electricity ([HSF](https://www.hsfkramer.com/notes/africa/2023-08/high-profile-cyberattacks-increase-emphasis-upon-cyber-resilience-in-south-africas-energy-sector)). |
| Jul 2021 | Transnet | Ransomware forced a declaration of force majeure at the container terminals. Staff tracked ships manually and **cleared cargo on paper** ([Wikipedia](https://en.wikipedia.org/wiki/Transnet_ransomware_attack)). |
| Mar 2022 | Eskom | Ransomware, with company data **offered for sale** on the dark web ([HSF](https://www.hsfkramer.com/notes/africa/2023-08/high-profile-cyberattacks-increase-emphasis-upon-cyber-resilience-in-south-africas-energy-sector)). |
| Sep 2026 | Rand Water | Cyberattack on IT systems (payments, GIS). Water supply unaffected ([TechCentral](https://techcentral.co.za/rand-water-cyberattack/285746/)). |

In each case, how fast the organisation recovers depends on whether it holds a copy of its critical data that the attacker **could not reach**. A sealed, independently powered box is one way to guarantee that.

---

## 1. How a byte travels through a wire

### 1.1 Bits become voltages
- A byte is 8 bits. For example, the letter `G` is `0100 0111`.
- To send it, the transmitter changes the **voltage** on a wire in a pattern the receiver has agreed to read.
- The data does **not** ride on electrons flowing down the wire. Electrons drift very slowly. What travels is the **electromagnetic wave** guided by the copper, at roughly 60–70% of the speed of light in typical network cable.
- Because the signal is an electromagnetic wave, **every cable also radiates a little of it into the air**. That is why the leaks in §3 are possible.

### 1.2 Why a wire can't just go "on = 1, off = 0"
Real links use **line coding** for three reasons:
- **Clock recovery:** the receiver has to tell where one bit ends and the next begins. A long run of identical bits gives it nothing to lock onto.
- **No DC drift:** Ethernet passes signals through small transformers, and transformers block steady DC. The signal must keep swinging up and down.
- **Bandwidth:** packing more bits into each voltage change lets a cable carry more data.

### 1.3 Common links and how they encode data

| Link | Where you find it | How bits become signals |
|---|---|---|
| **RS-485** | Industrial serial links (e.g. Modbus RTU), building systems | Two wires, **differential**: the bit value depends on which wire is at the higher voltage. Noise hits both wires equally and cancels out. |
| **100BASE-TX** (Fast Ethernet) | Many devices and switches | Data is first converted by 4B5B coding, then sent as **MLT-3**, which uses three voltage levels (−, 0, +). A `1` moves to the next level in the cycle 0 → + → 0 → − → 0. A `0` stays at the same level ([MLT-3](https://en.wikipedia.org/wiki/MLT-3_encoding)). |
| **1000BASE-T** (Gigabit Ethernet) | Modern networks | **PAM-5**, which uses five voltage levels (−2 … +2) and carries about 2 bits per symbol. It runs on all **four twisted pairs** at once, at roughly 1 V peak to peak per pair ([5G Technology World](https://www.5gtechnologyworld.com/how-does-4d-pam5-work-in-gigabit-ethernet/), [GRL](https://www.graniteriverlabs.com/en-us/technical-blog/ethernet-lan-test)). |
| **Fibre** | Backbones, and **data diodes** | **Light pulses** in glass. Nothing electrical flows between the two ends. |
| **Power-line communication (PLC)** | Smart meters, utility telemetry | Data is added **on top of the 50 Hz mains** as many small carrier tones, a technique called OFDM. G3-PLC uses 35.9–90.6 kHz and PRIME uses 42–90 kHz ([Berger et al.](https://onlinelibrary.wiley.com/doi/10.1155/2013/712376)). Broadband HomePlug/IEEE 1901 works in the MHz range. |

**Worked example: the byte `G` (`0100 0111`) as MLT-3 levels**, starting at 0. This is illustrative only; real 100BASE-TX applies 4B5B coding and scrambling first.

```
bit:     0    1    0    0    0    1    1    1
level:   0   +1   +1   +1   +1    0   -1    0
```

### 1.4 Power lines are data lines
The PLC row above is the key point. Power cables already carry deliberate data in the smart-meter world. **Any device that changes how much current it draws is, in effect, a transmitter on the power line**, whether its owner intends it or not.

### 1.5 Galvanic isolation: what Ethernet already does
Every standard Ethernet port has a small **isolation transformer** between the chip and the RJ45 socket. IEEE 802.3 requires it to withstand **1500 V rms for 60 seconds** ([IEEE 802.3 isolation proposal](https://www.ieee802.org/3/ad_hoc/isolation/public/Isolation%20IEEE%20802.3%20%20Rev%201%20%20%20083117.pdf), [Come-Star](https://www.come-star.com/blog/ethernet-galvanic-isolation/)). The data crosses the gap magnetically, but no DC current flows through it. Network cables are therefore already isolated electrically. The leak from them is **radiation** (§3.2), not conduction.

---

## 2. Power analysis: why a box holding secrets should not share mains

**Power analysis** ([Kocher et al., 1999](https://en.wikipedia.org/wiki/Power_analysis), [Rambus](https://www.rambus.com/blogs/side-channel-attacks/)) works because a chip's power draw changes with what it is computing. Statistical analysis of that draw (Differential Power Analysis, DPA) can **recover encryption keys**, even from noisy systems.

**What this means for the box:** the critical data should be encrypted at rest, so the box will hold **encryption keys**. Anyone who can measure the box's power draw has a possible route to those keys. With batteries only, there is no external power cable to measure.

---

## 3. How data leaks out of an isolated box

Removing the network cable is not the same as isolating the data. Research from Ben-Gurion University (Guri et al.) shows that malware on an isolated machine can still push data out through **seven physical channels**: electromagnetic, magnetic, electric, acoustic, thermal, optical and vibrational. The threat model for the box is: **malware gets in somehow (e.g. on a USB drive), then leaks the data out with no network at all.**

### 3.1 Through the power line: PowerHammer ([Guri et al., arXiv 1804.04014](https://arxiv.org/abs/1804.04014))
- **How it works:** malware switches CPU cores between busy and idle in a pattern. That changes the current the computer draws, and the pattern **travels out along the power cable**. An attacker reads it with a clamp-on current sensor.
- **Speed:** **1,000 bit/s** with a probe on the computer's own power cable. **10 bit/s** with a probe in the **floor's main electrical panel**, meaning the attacker never has to be near the computer.
- **Why normal defences miss it:** the signal sits at **0–24 kHz**. Standard EMI filters, and FCC Part 15 conducted-emission rules (450 kHz–30 MHz), target much higher frequencies, so the channel works **"even with equipment that is fully compliant with the regulations"**.
- **The authors' countermeasures:**
  - Monitor the power line (hard; they call detection "challenging").
  - Fit filters at *every* outlet (most filters don't cover this band).
  - Run random background workloads as jamming (costs performance).

### 3.2 Radiated from network cables
- **LANTENNA** ([arXiv 2110.00104](https://arxiv.org/abs/2110.00104)): malware makes Ethernet cables radiate at **125 MHz and its harmonics, strongest at 250 MHz**. It achieved **1–5 bit/s with no errors at up to 3 m**. Countermeasures: zone separation (the TEMPEST approach), **shielded S/FTP cable**, RF monitoring and jamming.
- **Reflecthernet** ([arXiv 2605.02702](https://arxiv.org/abs/2605.02702), May 2026): a **tiny hardware implant** built from transistors or diodes, attached to a 100BASE-TX line. A remote radio "illuminates" it, and the reflection carries the MLT-3 signal back, so the attacker can **read the Ethernet traffic from a distance**. This is a physical tampering and supply-chain risk.

### 3.3 Other channels

| Channel | Example | Notes |
|---|---|---|
| Electromagnetic | **COVID-bit** ([arXiv 2212.03520](https://arxiv.org/abs/2212.03520)) | The CPU's power use makes the power supply radiate at **0–60 kHz**. It reaches **>2 m at up to 1,000 bit/s**. |
| Electromagnetic | AirHopper, GSMem | FM or cellular-band emissions picked up by a phone. |
| Magnetic | ODINI, MAGNETO ([arXiv 1802.02317](https://arxiv.org/abs/1802.02317)) | Low-frequency magnetic fields from the CPU. These **pass through Faraday cages**. |
| Acoustic | MOSQUITO, POWER-SUPPLaY ([IACR 2020/516](https://eprint.iacr.org/2020/516.pdf)) | Ultrasonic sound from speakers, or from the power supply itself. |
| Thermal | BitWhisper | Heat between adjacent machines. Very slow. |
| Optical | CTRL-ALT-LED ([arXiv 1907.05851](https://arxiv.org/abs/1907.05851)) | Status and keyboard LEDs. |
| Vibrational | AiR-ViBeR ([arXiv 2004.06195](https://arxiv.org/abs/2004.06195)) | Fan vibrations picked up by a phone's accelerometer. |

**Takeaway:** "sealed" is a spectrum. Every wire and surface of the box can carry data. The design goal is to remove the channels that are cheap to exploit and make the rest short-range, slow and monitored. Keeping malware out in the first place (§4.3) matters as much as blocking these channels.

---

## 4. Design implications

### 4.1 Getting data in and out: three options

"Data circulates only inside the box" still needs a rule for how data gets in and who can read it:

```
 A) WRITE-ONLY VAULT            B) READ-ONLY SOURCE            C) FULLY SEALED
 building ──► diode ──► box     box ──► diode ──► building     no network at all;
 (backups flow in;              (box publishes reference        data moves only on
  nothing can come out           data; nothing can change        physical media under
  over the network; read         it remotely)                    a written procedure
  only at the box itself)
```

- A **data diode** is fibre with the transmitter removed on one side and the receiver removed on the other, so data **physically** flows only one way. NIST SP 800-82 describes the unidirectional gateway built on it as **"physically unable to send any information back"** ([Waterfall](https://waterfall-security.com/data-diode-and-unidirectional-gateways/), [Wikipedia](https://en.wikipedia.org/wiki/Unidirectional_network), [Industrial Cyber](https://industrialcyber.co/analysis/implementation-of-data-diodes-can-boost-cybersecurity-architecture-at-critical-infrastructure-installations/)). Because it uses light, it also isolates electrically.
- **Option A fits the SA incidents in §0 best.** Ransomware on the building network can't reach the copy, because nothing on the network can talk back into or out of the box.

### 4.2 Power: battery only
1. **No mains connection while the box is running.** This removes the PowerHammer (§3.1) and power-analysis (§2) paths.
2. **Charging is the weak point.**
   - The strongest option is **two swappable battery packs**: pack A runs the box while pack B charges somewhere else, and the box never touches mains.
   - If swapping isn't practical, the fallback is charging through an **isolated DC-DC converter**, adding low-frequency filtering and a constant **"flattening" load** that keeps total draw steady. This is weaker, because ordinary filters miss the 0–24 kHz band.
   - *My inference, not tested in the papers:* a standard UPS isn't designed to hide load changes. Its charger's mains draw can still track what the box is doing, so treat a normal UPS as resilience, not isolation.
3. **Runtime benchmark:**
   - Substations run protection, control and communications from **110 V or 220 V DC battery banks**, commonly sized for **about 8 hours** ([EEP](https://electrical-engineering-portal.com/substation-dc-auxiliary-supply-battery-and-charger-applications), [SEL](https://selinc.com/api/download/3482)).
   - **SA status (Sept 2026):** formal load shedding has been **suspended since about May 2025**, but **local load reduction** still cuts power in overloaded areas **05:00–09:00 and 17:00–22:00** ([Eskom](https://www.eskom.co.za/power-system-status/), [Relocating to SA](https://relocatingtosouthafrica.com/guides/load-shedding-south-africa-2026/), [EnergyBee](https://energybee.co.za/news/load-reduction-schedule-south-africa-2026)).
   - A recovery box is needed most during outages and incidents, so it has to stay up through them.
4. **Shut down cleanly before the battery runs out.** Stored data survives a power loss, but a hard cut in the middle of a write can corrupt it. The box should monitor its own charge and power down safely.

### 4.3 The enclosure and what goes near it
1. **A metal enclosure, shielded S/FTP cable and short cable runs** reduce radiated leaks (§3.2).
2. **Keep phones and radios out of the zone around the box**, because magnetic channels pass through metal. This follows TEMPEST zone separation.
3. **Make tampering visible** with seals, tamper switches, and a log of every time the enclosure is opened. Reflecthernet shows that a tiny implant is enough.
4. **Encrypt the data at rest**, and never let the keys leave the box.
5. **Control removable media strictly.** Stuxnet reportedly arrived on a USB drive. Any update or data transfer by hand needs a written, two-person procedure.
6. **Keep software jamming on.** A random background load makes the box's power and EM signature noisy.

---

## 5. The monitoring room and the data "race track"

**The proposal:** security engineers watch the box from a **separate room**, connected by a dedicated "tunnel". Critical data is kept **circulating in a loop, like cars on a NASCAR oval**, and is watched from the other side so that any theft shows up.

### 5.1 The idea has a real precedent
- **Early computers stored their memory this way.** EDSAC (Cambridge, 1949) kept its 512 words of memory as pulses **circulating through 32 mercury delay lines**. Each line turned bits into sound waves, sent them down a tube of mercury, and fed the output back to the input, "creating a continuous loop where the data would circulate endlessly" until it was read or changed ([Computer History Museum](https://www.computerhistory.org/storageengine/edsac-computer-employs-delay-line-storage/), [EDSAC](https://en.wikipedia.org/wiki/EDSAC)).
- **NASCAR's scoring system is a monitoring loop.** Every car carries a transponder at a fixed position. **Wire timing loops are buried about a foot under the track**, and the most important one is at the start/finish line. Each time a car crosses a loop, a computer logs **which car, which loop and the exact time**, to within ±0.0015 s. The results appear on screens in NASCAR race control and on pit road ([NBC Sports](https://www.nbcsports.com/nascar/news/daniel-suarez-denny-hamlin-joey-logano-dr-diandra-nascar-monitors-pit-road-speed), [Fox Sports](https://www.foxsports.com/stories/nascar/nascar-finish-line-timing-system-confusing-but-works)).

**How the analogy maps:**

| NASCAR | Sealed data box |
|---|---|
| Track | A **fibre-optic loop** running from the vault room to the monitoring room and back |
| Car | A **data frame** carrying encrypted data or a fingerprint of it |
| Transponder | Each frame's **ID, sequence number and integrity tag** (a cryptographic checksum) |
| Timing loop at the start/finish line | A **passive optical tap** in the monitoring room that sees every frame go past |
| Race control | The **monitoring room** screens: every frame present, on time, unaltered |
| A car detouring through pit lane shows up in its lap time | A tap or relay on the fibre **adds delay**, which shows up in lap timing |

### 5.2 ⚠️ The catch: stealing data is copying, not removing
In NASCAR, a stolen car **disappears from the track**, and race control sees it immediately. **Data theft doesn't work like that.** A thief copies the data, and the original keeps lapping with nothing missing. Counting frames alone would never notice.

So the loop has to catch **the act of tapping in**, not a missing frame. The research gives four ways to do that:

1. **Measure the light.** The easiest way to tap fibre is a clip-on **bend coupler**, which bends the fibre so some light leaks out. That costs **around 1 dB or more of optical power**. Power-monitoring systems alarm on that drop. **OTDR**, a tool that sends test pulses down the fibre and records the reflections, compares each trace with a reference to find and locate small new losses along the route ([Photonics 2025](https://doi.org/10.3390/photonics12050501), [VIAVI](https://www.viavisolutions.com/en-us/literature/fiber-tapping-detection-onmsi-optical-network-monitoring-system-application-notes-en.pdf)).
   - *Limit:* a skilled attacker can polish away the fibre's cladding and tap it without a telltale bend. Light monitoring raises the bar but is not absolute.
   - *Real case:* a fibre tap was found on Verizon's network in 2003, used to get a mutual fund's results before they were public (Photonics 2025).
2. **Alarm the tunnel itself.** The US government's standard for exactly this situation, a cable run carrying sensitive data between rooms, is the **Protected Distribution System** (PDS, [CNSSI 7003](https://www.dcsa.mil/Portals/91/documents/ctp/nao/CNSSI_7003_PDS_September_2015.pdf)). An **"alarmed carrier" PDS** runs extra sensing fibres inside the conduit to detect the **vibration of someone trying to get at the cables**, and monitors them around the clock ([Wikipedia](https://en.wikipedia.org/wiki/Protective_distribution_system), [Network Integrity Systems](https://www.networkintegritysystems.com/alarmed-carrier-protected-distribution-system-solutions)). **This is the professional version of your "tunnel".**
3. **Time every lap.** Light in fibre takes a fixed, measurable time to go round. A tap that cuts the fibre and relays the data, reading it on the way, adds delay, the same way a pit-lane detour shows in a car's lap time. *This is standard physics rather than a cited study; how small a delay can be detected needs testing.*
4. **Use physics that notices being watched (future option).** In **quantum key distribution (QKD)**, reading a photon in the wrong way disturbs it. An eavesdropper therefore raises the error rate: a basic intercept-and-resend attack causes **at least ~25% errors**, and the key is thrown away above **~11%** ([arXiv 2603.27278](https://arxiv.org/html/2603.27278v1), [arXiv 2312.05609](https://arxiv.org/html/2312.05609v1)). It works over fibre up to about 100–200 km, which easily covers two rooms, but the hardware is expensive.
   - **South African angle:** Stellenbosch University and USTC built a **12,900 km quantum satellite link** with the Jinan-1 microsatellite in October 2024 and published it in *Nature*. It was the first quantum satellite link in the Southern Hemisphere ([Stellenbosch University](https://www.su.ac.za/en/node/19887), [ScienceDaily](https://www.sciencedaily.com/releases/2025/03/250319142833.htm)). The local expertise exists.

**Plus a fifth layer that catches theft after the fact: tripwire data.** Put **canary records** in the loop: fake files or entries that nothing legitimate ever uses. [Canarytokens](https://blog.thinkst.com/p/canarytokensorg-quick-free-detection.html) (Thinkst) embed a callback in a document or file, and **"if anyone opens it — whether in your backup environment or after exfiltration — you get an alert"** with the source IP and time ([Thinkst help](https://help.canary.tools/hc/en-gb/articles/4701687447325-What-are-Canarytokens)). This is the closest thing to a stolen car setting off an alarm once it leaves the track. For a sealed site, the alert would go to a server the engineers control, not a public one.

### 5.3 How the track could be built

```
      VAULT ROOM                  alarmed conduit (PDS)            MONITORING ROOM
 ┌──────────────────┐   ═══════════════════════════════════   ┌────────────────────────────┐
 │  Box             │                                          │                            │
 │   TX ────────────┼──── fibre loop (outbound) ──────────────►│─┬─ passive optical tap     │
 │                  │                                          │ │    └─► receiver only ──► │
 │   RX ◄───────────┼──── fibre loop (return) ─────────────────│◄┘        timing & scoring │
 │                  │                                          │          screens          │
 │  checks every    │   sensing fibre in conduit ─────────────►│──► intrusion alarm        │
 │  frame returns   │                                          │   OTDR / optical power ──►│
 └──────────────────┘   ═══════════════════════════════════   └────────────────────────────┘
```

Design rules:
1. **Make the track fibre, not copper.** Fibre carries light, so it doesn't radiate the way copper Ethernet does (LANTENNA, §3.2), and it isolates the two rooms electrically.
2. **The monitoring room gets receivers only.** A **passive optical tap** splits off a copy of the light. It needs no power, adds no delay, and **physically cannot send anything back**, so "even if monitoring or security tools become compromised, attackers cannot inject traffic back" ([Network Critical](https://www.networkcritical.com/blogs/what-is-a-passive-network-tap), [Siemon](https://www.siemon.com/en/optical-network-tapping/)). This is the same one-way principle as the data diode in §4.1: the engineers can watch everything but control nothing in the vault.
3. **Check at both ends.** The box confirms every frame comes back intact and on time. The monitoring room independently scores every frame that passes: ID, sequence, lap time, integrity tag and light level. An attacker would have to fool both.
4. **Decide what goes round the track:**
   - **Recommended: fingerprints plus canary frames.** Circulate cryptographic hashes of the data, meaning short fingerprints that change if the data changes, plus the tripwire records. The real data stays encrypted at rest in the box. This gives full monitoring with minimum exposure.
   - **Alternative: the real data, encrypted.** A tap captures only ciphertext, because the keys never leave the box. It works, but the data is constantly on the wire, and the loop uses more battery.
5. **Keep the rooms separate for people too.** The engineers watching the screens shouldn't have access to the vault room, and vice versa. Record every entry to both rooms.

### 5.4 What the track can't catch
- **Malware already inside the box** that leaks data through the covert channels in §3 (power, EM, magnetic, acoustic). The loop watches the cable, not the box's own emissions. §4 still applies.
- **A careful tap that causes no bend and no delay.** Light monitoring alone can miss one. The alarmed conduit and canary records are the backup layers.

---

## 6. Does this already exist, and will it work?

This assesses the three ideas: the sealed battery box, the separate monitoring room, and the data loop. It is based on searches done on 2026-09-28. **This is not a patent search**, so before claiming anything is new in a pitch or a patent filing, search Google Patents and South Africa's CIPC.

### 6.1 Sealed box on its own batteries

**Already exists (in parts):**
- **Air-gapped recovery vaults.** Dell PowerProtect Cyber Recovery keeps critical data in an isolated vault "with its own controls, credentials and management plane" and stores immutable copies. It is endorsed for **Sheltered Harbor**, the US banking sector's data-vaulting standard ([Dell](https://www.dell.com/en-uk/lp/data-protection-cyber-recovery-solution), [Dell: Sheltered Harbor](https://www.delltechnologies.com/asset/en-sg/products/data-protection/briefs-summaries/h18199-powerprotect-cyber-recovery-for-sheltered-harbor-solution-brief-endorsement.pdf)). CISA, FBI and NSA recommend **"offline, encrypted backups of critical data"** because ransomware hunts for and destroys backups it can reach ([#StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)).
- **Sealed tamper-responsive boxes.** Hardware security modules (HSMs) at FIPS 140-3 Level 4 wrap their contents in an envelope that detects entry from any direction and **wipes the keys immediately** ([FIPS 140](https://en.wikipedia.org/wiki/FIPS_140), [HSM](https://en.wikipedia.org/wiki/Hardware_security_module)).
- **Power treated as a leak path.** Classified rooms (SCIFs, under ICD 705 and TEMPEST) use **power-line filters, isolation transformers, fibre and shielding** because "energy can couple onto power conductors" and carry compromising signals out ([Bridgeport Magnetics](https://bridgeportmagnetics.com/scif-isolation-transformer/), [Signals Defense](https://signalsdefense.com/tempest-and-scif-design/)).

**What's different about your version:** established practice *filters* the mains; your idea *removes* it. That's stronger against PowerHammer-type leaks, which get past ordinary filters (§3.1). I didn't find battery-only operation used as the isolation method for a data vault.

| | Verdict |
|---|---|
| Viable? | **Yes, at small scale:** documents, drawings, configs and keys on SSD, with a low-power computer. Hard at data-centre scale because of power. Swapping batteries is the ongoing burden. |
| Effective? | **Yes** against the SA incident pattern (ransomware reaching data, §0), matching CISA's offline-backup advice. **Yes** against power-line leaks. The weak point is how data gets in and out (§4.1). |

### 6.2 Separate monitoring room with a tunnel

**Already exists, and it's standard practice:**
- **Alarmed Protected Distribution Systems** (CNSSI 7003) are the US government's method for cable runs carrying sensitive data between rooms. Commercial systems such as Network Integrity Systems' INTERCEPTOR **"make the entire cable a sensor"** with monitored fibres, detecting tapping and tampering around the clock ([NIS](https://www.networkintegritysystems.com/interceptor-products), [CNSSI 7003](https://www.dcsa.mil/Portals/91/documents/ctp/nao/CNSSI_7003_PDS_September_2015.pdf)).
- **Passive one-way fibre taps** and **data diodes** feeding a separate security operations room are established OT practice (§4.1, §5.3).

| | Verdict |
|---|---|
| Viable? | **Yes.** All the parts can be bought today. |
| Effective? | **Yes.** It's what classified networks use. |
| New? | **No.** That's a good sign, though: your instinct matches professional practice. The pitch is "government-grade protection, applied to SA critical infrastructure". |

### 6.3 The NASCAR data loop

**Exists in pieces, but I didn't find it as one system:**
- **Data circulating in a loop:** delay-line memory (EDSAC, 1949, §5.1). That was for storage, not security.
- **Checking every record each lap:** file integrity monitoring. **Tripwire (1992)** records a hash baseline of every file and re-scans periodically for any addition, deletion or change ([Tripwire](https://www.tripwire.com/state-of-security/past-present-and-future-file-integrity-monitoring)). This is the "lap check" without the moving track.
- **Watching the cable for taps:** alarmed PDS and OTDR (§5.2).
- **Keeping data on the move to frustrate attackers:** **Moving Target Defense**, which DHS defines as "controlled change across multiple network and system dimensions to increase uncertainty and complexity for attackers", including storage variants ([Help Net Security](https://www.helpnetsecurity.com/2023/03/02/moving-target-defense/), [ScienceDirect](https://www.sciencedirect.com/topics/computer-science/moving-target-defense)).
- **Physics that notices being read:** QKD (§5.2).

**What's different about your version:** the data frames themselves serve as the sensor. Every lap is timed and checked at **both ends**, with the light level watched at the same time. Parts of this may exist in patents or products my search didn't find.

| | Verdict |
|---|---|
| Viable? | **Yes.** It can be built from standard fibre, transceivers, passive taps and small computers. |
| Effective? | **As a tamper alarm, yes. As the main defence against theft, no.** Copying doesn't remove data (§5.2), so the loop only catches a thief who disturbs the light, the timing or the conduit. Circulating the *real* data also keeps it on the wire all the time, which is more exposure than leaving it encrypted at rest. The likelier weak points in practice are the **ends**: malware in the box, or an insider in the monitoring room. The cable in between is less likely to be attacked. |
| Best use | Circulate **fingerprints and canary records** as a tamper-evident heartbeat, and keep the real data encrypted inside the box. |

### 6.4 Overall
- Each idea has precedent on its own.
- **What stands out is the combination:** a battery-isolated vault, an alarmed link to a receive-only monitoring room, and a timed tripwire loop.
- **It targets the gap the research found:** SA state-owned enterprises and municipalities keep losing IT systems and data to ransomware, and the existing solutions (Dell-class vaults, SCIF construction, alarmed PDS) are expensive, imported, and built for banks and militaries.
- **An affordable local version** is a credible pitch. It sells better as a new *combination and delivery* than as a new invention.

---

## 7. Open questions for you

1. **What data goes in the box?** For example: building drawings, asset inventories, system configurations, backups, access-control records. The size and how often it changes decide the storage and the flow design.
2. **Which direction does data flow:** A (write-only vault), B (read-only source) or C (fully sealed)?
3. **What goes round the track:** fingerprints plus canary frames (recommended), or the real data encrypted?
4. **How far apart are the two rooms,** and can the fibre run through its own conduit? That decides whether an alarmed PDS is practical.
5. **Who reads the data, and how?** Only at the box, or from somewhere else?
6. **Battery swapping:** could someone on site swap packs every few days?

---

## Sources

**South African incidents**
- [HSF: SA energy sector cyberattacks](https://www.hsfkramer.com/notes/africa/2023-08/high-profile-cyberattacks-increase-emphasis-upon-cyber-resilience-in-south-africas-energy-sector) · [Transnet ransomware attack](https://en.wikipedia.org/wiki/Transnet_ransomware_attack) · [TechCentral: Rand Water](https://techcentral.co.za/rand-water-cyberattack/285746/)

**How data travels**
- [MLT-3 encoding](https://en.wikipedia.org/wiki/MLT-3_encoding) · [How 4D-PAM5 works in Gigabit Ethernet](https://www.5gtechnologyworld.com/how-does-4d-pam5-work-in-gigabit-ethernet/) · [GRL: Intro to Ethernet](https://www.graniteriverlabs.com/en-us/technical-blog/ethernet-lan-test)
- [Berger et al., PLC for Smart Grid](https://onlinelibrary.wiley.com/doi/10.1155/2013/712376) · [State of the art in PLC (arXiv 1602.09019)](https://arxiv.org/abs/1602.09019)
- [IEEE 802.3 isolation proposal](https://www.ieee802.org/3/ad_hoc/isolation/public/Isolation%20IEEE%20802.3%20%20Rev%201%20%20%20083117.pdf) · [Ethernet galvanic isolation explained](https://www.come-star.com/blog/ethernet-galvanic-isolation/)

**Side channels and covert channels**
- [Power analysis](https://en.wikipedia.org/wiki/Power_analysis) · [Rambus: side-channel attacks](https://www.rambus.com/blogs/side-channel-attacks/)
- [PowerHammer (arXiv 1804.04014)](https://arxiv.org/abs/1804.04014) · [LANTENNA (arXiv 2110.00104)](https://arxiv.org/abs/2110.00104) · [Reflecthernet (arXiv 2605.02702)](https://arxiv.org/abs/2605.02702)
- [COVID-bit (arXiv 2212.03520)](https://arxiv.org/abs/2212.03520) · [MAGNETO (arXiv 1802.02317)](https://arxiv.org/abs/1802.02317) · [POWER-SUPPLaY (IACR 2020/516)](https://eprint.iacr.org/2020/516.pdf) · [CTRL-ALT-LED (arXiv 1907.05851)](https://arxiv.org/abs/1907.05851) · [AiR-ViBeR (arXiv 2004.06195)](https://arxiv.org/abs/2004.06195)

**Data diodes**
- [Waterfall: data diodes and unidirectional gateways](https://waterfall-security.com/data-diode-and-unidirectional-gateways/) · [Unidirectional network](https://en.wikipedia.org/wiki/Unidirectional_network) · [Industrial Cyber: data diodes in CI](https://industrialcyber.co/analysis/implementation-of-data-diodes-can-boost-cybersecurity-architecture-at-critical-infrastructure-installations/)

**Monitoring room and the data loop**
- [CHM: EDSAC delay-line storage](https://www.computerhistory.org/storageengine/edsac-computer-employs-delay-line-storage/) · [EDSAC](https://en.wikipedia.org/wiki/EDSAC)
- [NBC Sports: how NASCAR monitors pit road](https://www.nbcsports.com/nascar/news/daniel-suarez-denny-hamlin-joey-logano-dr-diandra-nascar-monitors-pit-road-speed) · [Fox Sports: NASCAR finish-line timing](https://www.foxsports.com/stories/nascar/nascar-finish-line-timing-system-confusing-but-works)
- [Fiber eavesdropping detection and location (Photonics 2025)](https://doi.org/10.3390/photonics12050501) · [VIAVI: fiber tapping detection](https://www.viavisolutions.com/en-us/literature/fiber-tapping-detection-onmsi-optical-network-monitoring-system-application-notes-en.pdf)
- [CNSSI 7003: Protected Distribution Systems](https://www.dcsa.mil/Portals/91/documents/ctp/nao/CNSSI_7003_PDS_September_2015.pdf) · [Protective distribution system](https://en.wikipedia.org/wiki/Protective_distribution_system) · [Network Integrity Systems: alarmed carrier](https://www.networkintegritysystems.com/alarmed-carrier-protected-distribution-system-solutions)
- [Network Critical: passive network TAP](https://www.networkcritical.com/blogs/what-is-a-passive-network-tap) · [Siemon: optical network tapping](https://www.siemon.com/en/optical-network-tapping/)
- [BB84 QBER analysis (arXiv 2603.27278)](https://arxiv.org/html/2603.27278v1) · [BB84 analysis (arXiv 2312.05609)](https://arxiv.org/html/2312.05609v1)
- [Stellenbosch University: SA–China quantum satellite link](https://www.su.ac.za/en/node/19887) · [ScienceDaily](https://www.sciencedaily.com/releases/2025/03/250319142833.htm)
- [Thinkst: Canarytokens](https://blog.thinkst.com/p/canarytokensorg-quick-free-detection.html) · [What are Canarytokens?](https://help.canary.tools/hc/en-gb/articles/4701687447325-What-are-Canarytokens)

**Prior art (§6)**
- [Dell PowerProtect Cyber Recovery](https://www.dell.com/en-uk/lp/data-protection-cyber-recovery-solution) · [Dell: Sheltered Harbor endorsement](https://www.delltechnologies.com/asset/en-sg/products/data-protection/briefs-summaries/h18199-powerprotect-cyber-recovery-for-sheltered-harbor-solution-brief-endorsement.pdf) · [CISA #StopRansomware Guide](https://www.cisa.gov/stopransomware/ransomware-guide)
- [FIPS 140](https://en.wikipedia.org/wiki/FIPS_140) · [Hardware security module](https://en.wikipedia.org/wiki/Hardware_security_module)
- [Bridgeport Magnetics: SCIF isolation transformers](https://bridgeportmagnetics.com/scif-isolation-transformer/) · [Signals Defense: TEMPEST and SCIF design](https://signalsdefense.com/tempest-and-scif-design/)
- [Network Integrity Systems: INTERCEPTOR](https://www.networkintegritysystems.com/interceptor-products)
- [Tripwire: history of FIM](https://www.tripwire.com/state-of-security/past-present-and-future-file-integrity-monitoring) · [Help Net Security: Moving Target Defense](https://www.helpnetsecurity.com/2023/03/02/moving-target-defense/) · [ScienceDirect: MTD overview](https://www.sciencedirect.com/topics/computer-science/moving-target-defense)

**Power and batteries**
- [EEP: Substation DC auxiliary supply](https://electrical-engineering-portal.com/substation-dc-auxiliary-supply-battery-and-charger-applications) · [SEL: Auxiliary DC control power design](https://selinc.com/api/download/3482)
- [Eskom power system status](https://www.eskom.co.za/power-system-status/) · [Load-shedding in SA (2026)](https://relocatingtosouthafrica.com/guides/load-shedding-south-africa-2026/) · [EnergyBee: load reduction 2026](https://energybee.co.za/news/load-reduction-schedule-south-africa-2026)
