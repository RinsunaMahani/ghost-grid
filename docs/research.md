# GhostGrid — Research Notes

*Compiled 2026-09-28. Sources are linked inline and listed at the end.*

**Scope:** GhostGrid is for **all critical infrastructure**, not one utility or sector. That includes power, water, ports, rail, pipelines, fuel and petrochemicals, and district heating. The main users are the state-owned enterprises and municipal entities that run these systems. The research below is organized so that a shared core serves every sector, and each sector adds its own profile.

## TL;DR

1. **The attacker methods are the same in every sector.** They get into IT, spend weeks to months on reconnaissance, reach OT, then read and write controller registers with Modbus, IEC-104, S7 or OPC UA. This held for Industroyer2 (power), Triton (petrochemical), FrostyGoop (district heating) and CyberAv3ngers (water). A decoy that targets the reconnaissance phase therefore works in all of them.
2. **GhostGrid is not the first LLM-powered ICS honeypot.** [LLMPot](https://arxiv.org/abs/2405.05999) (2024, open source) already uses a small model to emulate Modbus and S7comm PLCs. The best ways to stand out are:
   - one engine that covers **every sector**;
   - the "time gained for the SOC" metric;
   - fully offline operation;
   - South African realism;
   - poisoning the attacker's reconnaissance.
3. **Putting the LLM on the per-request path is itself a giveaway.** Small local models take about 3 s per response, while real controllers answer in milliseconds. The LLM should direct scenarios in the background. It is well suited to writing site identities and storylines for any sector, which removes the need to hand-build every decoy.
4. **The "swap real data for poison" wording carries a safety risk.** If GhostGrid sits inline and misclassifies a legitimate operator, a water or grid control room sees fake data. A separate decoy twin avoids this (§7).
5. **This is topical in South Africa right now.** Rand Water, which supplies bulk water to 11M+ people, disclosed a cyberattack on **3 September 2026**. It hit IT only, but experts warned that in an OT attack "reservoirs draw down in hours, not days".

---

## 1. Prior art: what already exists

### 1.1 LLM-based ICS honeypots (closest competitor)

**LLMPot** (Vasilatos, Mahboobeh, Lamri, Alam, Maniatakos; [arXiv 2405.05999](https://arxiv.org/abs/2405.05999), [code](https://github.com/momalab/LLMPot)):
- Emulates **Modbus** and **S7comm**.
- Uses **ByT5-small (300M params)**, which works directly on bytes. The authors also tried ByT5-base and **Llama3.2 1B**, and ByT5-small matched them at lower cost.
- Training data comes from probing a real PLC and capturing its responses. That means it needs a real device to learn from.
- Results: 99.3% of responses were valid protocol messages, and 85.3% matched the real PLC byte for byte (Modbus).
- Stated weakness: it **degrades on complex control logic** and on large or fluctuating value ranges. That describes most real infrastructure processes.
- The paper does not report response latency.

**What this means for GhostGrid:** LLMPot uses the LLM as the protocol emulator. GhostGrid should use a deterministic protocol stack and physics profiles, with the LLM directing the scenario (§6). This design also needs no real PLC to train on, which matters when the aim is to cover many sectors.

### 1.2 LLM honeypots in general (mostly SSH/HTTP)

- **shelLM** ([Sladić et al. 2023](https://arxiv.org/abs/2309.00155)): humans rated its LLM-generated Linux shell as real 90% of the time (true-negative rate 0.90).
- **HoneyGPT / HoneyLLM** ([Wang et al.](https://www.cse.psu.edu/~sxz16/papers/HoneyGPT.pdf)): frames the honeypot "trilemma" of flexibility, interaction depth and deception.
- **LLMHoney** ([arXiv 2509.01463](https://arxiv.org/abs/2509.01463)): tested 13 models from 0.36B to 3.8B parameters. **Qwen2.5:1.5B and Phi3:3.8B were the most reliable, at ~3 s mean latency. Smaller models often produced incorrect or out-of-character output.** Common commands are served from a dictionary, and the LLM only handles new inputs.
- **SoK: Honeypots & LLMs** ([Bridges et al., arXiv 2510.25939](https://arxiv.org/abs/2510.25939)): the best overview of the field. Its key points are in §2 and §5.

### 1.3 Classic and physics-aware ICS honeypots

| Project | Notes |
|---|---|
| Conpot | The default ICS honeypot. GridPot, T-Pot and others wrap it and inherit its **default fingerprints** (S7 plant ID `"Mouser Factory"`, serial `"88111222"`). |
| GridPot | Conpot plus a GridLAB-D power simulation. It attracted more traffic than plain Conpot ([Maesschalck et al.](https://www.acsac.org/2021/workshops/icss/2021-icss-maesschalck.pdf)). Power only. |
| HoneyPLC, ICSpot | Higher-interaction PLC honeypots. ICSpot's process model **has no sensor noise**, which is a known tell. |
| ICSLure ([arXiv 2509.04080](https://arxiv.org/abs/2509.04080)) | Real PLC hardware plus a physics simulator. Siemens TIA Portal flagged Conpot, HoneyPLC and ICSpot as honeypots, but not a real idle PLC. |
| HoneyICS | A high-interaction honeynet with a physics-aware process model ([ACM ARES 2023](https://dl.acm.org/doi/10.1145/3600160.3604984)). |

Most of these projects model **one process**, such as one grid or one plant. None of them lets you switch between sector profiles.

### 1.4 Commercial

- **FortiDeceptor** (Fortinet): 100+ decoy templates across IT, OT (SCADA, Modbus, PROFINET, S7 PLCs, GE iFix HMIs), healthcare and finance. The decoys are **deployed passively alongside live OT, "requiring no changes to existing systems"** ([Fortinet](https://www.fortinet.com/products/fortideceptor)).
- **CounterCraft, Thinkst Canary, Zscaler Deception, Rapid7**: broader deception platforms ([overview](https://expertinsights.com/network-security/best-deception-technology-companies)).

**Gap GhostGrid can fill:** the commercial options are licensed, vendor-coupled and based on fixed templates. None of them is air-gapped, auditable, able to generate sector-specific decoys on demand, tuned to South Africa, or measured on SOC time gained.

---

## 2. How honeypots get detected

This is the threat model for GhostGrid's own believability, and it applies in every sector.

### 2.1 From large-scale scans ([Mladenov et al., IEEE EuroS&P 2025](https://gsmaragd.github.io/publications/EuroSP2025-ICS/EuroSP2025-ICS.pdf))
- About **150,000 ICS devices** are exposed across 17 protocols, and **15–25% of them are honeypots**.
- Detection signals:
  - **Open port count:** 89.2% of real ICS hosts have ≤10 open ports, and 94.2% have ≤30. One T-Pot instance had **64,527**.
  - **Hosting location:** honeypots sit in cloud or hosting provider IP ranges, while real ICS sits on ISP or business networks.
  - **Known signatures:** default banners, default device identity, sloppy protocol emulation.
- Shodan's Honeyscore gets about 70% precision on ICS ([Dodson et al., CyCon 2020](https://ccdcoe.org/uploads/2020/05/CyCon_2020_15_Dodson_Beresford_Vingaard.pdf)).

### 2.2 The four detection categories (from the SoK)

| Category | Example | Can an LLM help? |
|---|---|---|
| Contents & posture | Default banners, unrealistic services | **Yes.** It can generate unique names, tags and identities for each deployment. |
| Outputs & behavior | Response timing, static values | **No.** The SoK says LLMs "cannot reproduce temporal fidelity or real-time dynamics". |
| Functional limits | Actions with no real side effects (e.g. a pump "starts" but flow and pressure don't change) | **Partly.** A state model is needed for this. |
| Feature synthesis | ML classifiers combining several signals | It breaks static signatures. |

**The key point for OT:** telemetry in every sector is about real-time physics, whether that's frequency, reservoir level, pipeline pressure or flow. LLMs can't produce that, so a deterministic model has to.

### 2.3 Process realism
- Deterministic or overly smooth values are a tell. Real sensors have noise from hardware, weather, EMI and people on site ([ICSLure](https://arxiv.org/html/2509.04080)).
- Newer work uses **LSTM and BiLSTM models trained on historical data** to generate realistic noise.
- Cross-signal consistency is necessary, whatever the sector:
  - **Power:** an open breaker means zero current on that line, and every bus shares one frequency.
  - **Water:** a pump running means flow > 0 and rising downstream pressure. Tank level must equal the integral of inflow minus outflow.
  - **Pipelines:** a closed valve means no flow, and pressure upstream of it builds up.

---

## 3. Latency: the main design constraint

| Component | Typical response time |
|---|---|
| Real PLC or RTU answering a Modbus register read | Milliseconds |
| Phi3 3.8B / Qwen2.5 1.5B on local hardware ([LLMHoney](https://arxiv.org/abs/2509.01463)) | **~3 s mean** |
| IEC 60870-5-104 protocol timers (IEC standard defaults) | t1 = 15 s (APDU acknowledgement timeout) |

A 3 s delay on a register read is abnormal, and timing has been used to fingerprint honeypots for 20 years (SoK §3.1.2). The SoK also flags **prompt injection and DoS through input flooding** as specific attack surfaces for LLM honeypots.

**Conclusion:** the LLM must not sit between the attacker's request and the response.

---

## 4. Threat landscape across sectors

### 4.1 The same attack pattern in every sector

| Sector | Incident | What happened | Lesson for GhostGrid |
|---|---|---|---|
| **Power** | Industroyer2, Ukraine, Apr 2022 ([ESET](https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/), [Netresec](https://www.netresec.com/?page=Blog&month=2022-04&post=Industroyer2-IEC-104-Analysis)) | In IT from at least Feb 2022, in ICS by mid-March. The payload was compiled on 23 March with **hard-coded IEC-104 addresses** for one substation. The target utility served about 2M people. | The payload was built from reconnaissance data. **Poisoned reconnaissance means it hits the wrong addresses.** |
| **Petrochemical** | Triton/Trisis, Saudi Arabia, 2017 ([Mandiant](https://cloud.google.com/blog/topics/threat-intelligence/attackers-deploy-new-ics-attack-framework-triton), [CSO / FireEye 2019](https://www.csoonline.com/article/567145/group-behind-triton-industrial-sabotage-malware-made-more-victims.html)) | Attackers spent **almost a year** in the network before reaching the safety-system engineering workstation. They reprogrammed the Triconex safety controllers, which put them into a failed state and shut the plant down. | Most of that year was reconnaissance and lateral movement, which gives decoys a long window to work in. |
| **District heating** | FrostyGoop, Lviv, Jan 2024 ([Dragos](https://hub.dragos.com/report/frostygoop-ics-malware-impacting-operational-technology), [SecurityWeek](https://www.securityweek.com/frostygoop-ics-malware-left-ukrainian-citys-residents-without-heating/)) | The first malware known to sabotage OT **directly over Modbus TCP**. It left **600 buildings without heat for ~2 days**. Dragos counted ~46,000 internet-exposed Modbus devices. | Modbus TCP should be the first protocol GhostGrid supports. |
| **Water** | CyberAv3ngers, Aliquippa (US), Nov 2023 ([WaterISAC](https://www.waterisac.org/tlpclear-water-utility-control-system-cyber-incident-advisory-icsscada-incident-municipal), [Sophos](https://www.sophos.com/en-us/blog/iranian-cyber-av3ngers-compromise-unitronics-systems)) | Attackers took over a booster-station Unitronics PLC through **weak or default passwords** and defaced it. About 1,800 Unitronics PLCs were internet-reachable. Multiple US water utilities, a brewery and an aquarium were hit. | Opportunistic attackers scan for exposed PLCs. A decoy exposed to the internet catches them first and gives early warning. |
| **Water / dams** | Risevatnet dam, Bremanger (Norway), Apr 2025 ([Wikipedia](https://en.wikipedia.org/wiki/Bremanger_dam_sabotage), [Claroty](https://claroty.com/blog/cyberattack-on-norwegian-dam-highlights-password-exposure-risks)) | Access came through a weak password. A discharge valve was forced **100% open for ~4 hours**, releasing 497 L/s above normal, **before operators noticed**. | This is **4 hours of attacker action before detection**, the gap GhostGrid's "time gained" metric is meant to close. |
| **Cross-sector** | PIPEDREAM / INCONTROLLER, 2022 ([Kudelski](https://kudelskisecurity.com/research/incontroller-pipedream-ics-toolkit-targeting-energy-sector), [Wikipedia](https://en.wikipedia.org/wiki/Pipedream_(toolkit))) | A state-sponsored toolkit for **Schneider and Omron PLCs and OPC UA servers**. It is aimed mainly at electricity and gas, but is not limited to them. No known successful deployment. | Attack tooling is modular and works across sectors, so defensive tooling should be too. |
| **All sectors** | Volt Typhoon ([CISA AA24-038A](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)) | Access to US **communications, energy, transport and water** IT networks kept for **at least 5 years**, pre-positioning for OT disruption. | Reconnaissance is slow and patient, so tarpitting can work against it. |

**What's out of scope:** some infrastructure attacks don't use IP networks at all. In the 2023 Poland rail attack, anyone with about $30 of radio equipment could send the analogue RADIOSTOP emergency signal, and 20 trains were halted ([Schneier](https://www.schneier.com/blog/archives/2023/08/remotely-stopping-polish-trains.html)). GhostGrid addresses **network-reachable OT**. Say this plainly in the pitch so judges don't catch it first.

### 4.2 South African context by sector

| Sector | Entity | Incident |
|---|---|---|
| Water | **Rand Water** (bulk water to 11M+ people in Gauteng, parts of Mpumalanga, Free State and North West) | Cyberattack disclosed **3 Sept 2026** through a notice to its JSE debt holders. It hit **IT only (payments, GIS)**. Treatment, quality control and bulk supply were unaffected. No attacker or vector disclosed ([TechCentral](https://techcentral.co.za/rand-water-cyberattack/285746/), [MyBroadband](https://mybroadband.co.za/news/security/665683-south-africas-largest-bulk-water-utility-crippled-by-cyberattack.html)). |
| Ports / rail / pipelines | **Transnet** | Ransomware in **July 2021** forced a declaration of force majeure at the Durban, Ngqura, Port Elizabeth and Cape Town container terminals, and operations fell back to paper ([Wikipedia](https://en.wikipedia.org/wiki/Transnet_ransomware_attack)). Durban handles about 60% of container traffic. |
| Power (municipal) | **City Power**, Johannesburg | Ransomware in **July 2019** blocked prepaid electricity purchases for up to ~250,000 customers ([HSF](https://www.hsfkramer.com/notes/africa/2023-08/high-profile-cyberattacks-increase-emphasis-upon-cyber-resilience-in-south-africas-energy-sector)). |
| Power (national) | **Eskom** | Ransomware in **March 2022**, with data offered for sale (same source). Eskom's CISO reports **~1 billion attempted attacks per month** ([IT-Online, Aug 2026](https://it-online.co.za/2026/08/14/sas-critical-infrastructure-is-running-on-unpatched-systems-attackers-know-that/)). |

**The pattern:** so far, every SA incident has been on the **IT side**. The only thing between those attacks and pumps, valves or breakers has been IT/OT separation, which worked in Rand Water's case. GhostGrid is a layer for the attacker who gets across that boundary.

Other points from local coverage:
- Local experts discussing Rand Water: "Reservoirs draw down in hours, not days" (Anna Collard, KnowBe4) and "Physical disruptions can unfold within minutes" (Bongani Majola, ScaryByte). The realistic water risk is **empty reservoirs and pressure loss**, not poisoning ([The Citizen](https://www.citizen.co.za/news/forget-poisoned-water-a-cyberattacks-real-threat-to-gauteng-is-empty-reservoirs/)).
- Most SA public entities have **no obligation to report incidents publicly**. Rand Water only disclosed because it has listed debt (TechCentral). SA also has **no dedicated critical-infrastructure cybersecurity legislation**, and most OT environments lack asset inventories (IT-Online).
- **Legal:** the [Critical Infrastructure Protection Act 8 of 2019](https://lawlibrary.org.za/akn/za/act/2019/8/eng@2019-11-28) covers infrastructure across sectors and replaces the National Key Points Act. Only some of its sections commenced, on 30 April 2022. The Cybercrimes Act 19 of 2020 and POPIA also apply ([Obiter](https://obiter.mandela.ac.za/article/view/14883)). I found **no SA guidance on running honeypots**, so get a legal opinion before any real deployment. It is not needed for a hackathon demo.

---

## 5. Framing and metrics

### 5.1 Where "time gained" fits
- **MITRE Engage** ([engage.mitre.org](https://engage.mitre.org/)) sets three goals: **Expose** (detect), **Affect** (raise the attacker's costs) and **Elicit** (collect intelligence). Classic honeypots aim at Elicit. **GhostGrid's "time gained" is an Affect goal.**
- The SoK's **evaluation tetrad** has four parts: (1) believability, (2) fidelity including timing, (3) attacker cost and intelligence (engagement depth, session length, diversity of ATT&CK techniques), and (4) defender cost. "Time gained" is a concrete, operational version of (3), and the field still lacks standardized metrics.
- **The Norway dam case makes the baseline concrete:** the attacker had ~4 hours before operators noticed. GhostGrid's claim is that its alert fires at first contact with the decoy, well before the attacker reaches a real valve.

### 5.2 Which attackers to target
The SoK's three tiers of attacker:
- **Tier 1, scripted bots:** 99.2% of honeypot traffic in one study. This includes opportunistic attackers like CyberAv3ngers. Static decoys are enough.
- **Tier 2, autonomous LLM agents:** the SoK's **main target for LLM honeypots**. They need consistency and believability, and they can be made to waste a lot of time.
- **Tier 3, skilled humans:** such as the Triton and Industroyer operators. They need high-interaction environments, so the aim here is to slow them down and raise an early alert.

### 5.3 A possible definition of "time gained"

```
T_gained      = t(attacker disengages or shows detection behaviour) − t(first contact with decoy)
SOC lead time = t(real-asset isolation complete) − t(GhostGrid alert)
```

---

## 6. What this means for GhostGrid's architecture

A **shared core** handles protocols, state, the LLM director and logging. **Sector profiles** provide the physics for each sector:

```
Attacker ──► Protocol front-end: Modbus TCP (all sectors) → IEC-104 (power)
                  │               → S7 / OPC UA / DNP3 later
                  │  answers in ms from current state (no LLM here)
                  ▼
             Process state ◄── Sector profile (pluggable physics)
                  ▲              • power:    frequency, V/I/P/Q, breakers
                  │              • water:    reservoir levels, pumps, flow,
                  │                          pressure, dosing
                  │              • pipeline/port: pressure, valves, flow
                  │              heavy-tailed noise + cross-signal consistency
                  │
             Scenario director (local LLM, slow loop: seconds–minutes)
               • builds a unique site identity per deployment
                 (site names, tag lists, register maps, banners)
               • writes the storyline: "Load reduction 17:00–22:00 on feeder F3" /
                 "Reservoir R3 refill cycle" / "Pump P2 maintenance"
               • adjusts the storyline to what the attacker is probing
                  │
             Session logger ──► SOC dashboard (time gained, ATT&CK for ICS,
                                alerts)
```

**Why the LLM is worth including:** building believable decoys for many sectors by hand is what makes existing honeypots single-sector and full of defaults. The LLM can generate a new site in any sector that looks lived-in: tag names, alarm lists, operator notes and maintenance history. Meanwhile, the physics profile keeps the numbers honest.

Design rules taken from the research:
1. **No LLM on the request path.** Serve every request deterministically, and have the LLM change state and storyline asynchronously.
2. **No defaults.** Each deployment gets a unique identity, register map and banners.
3. **Realistic network posture.** Expose ≤10 ports, match one real device type, and never run from a cloud IP range.
4. **Physics before prose.** Use heavy-tailed noise and enforce consistency between signals (§2.3).
5. **Poison the reconnaissance.** Fake register and IOA maps act as honeytokens. If a payload later uses those addresses on the real network, that is a very reliable alert.
6. **Harden the LLM.** Attacker input never reaches the prompt verbatim; the prompt gets structured session features instead.

**Model choice:** phi3 3.8B or qwen2.5 1.5B were the most reliable small models in LLMHoney, and llama3.2:1b is fine for a slow-loop director. Since the LLM is off the hot path, 3 s latency no longer matters.

---

## 7. ⚠️ Safety risk: inline swapping vs a separate decoy

"Swap real data for poison when an unauthorized query arrives" implies GhostGrid sits **inline** between clients and real devices. The risks:
- A **false positive** means a legitimate engineer or SCADA master sees fake water levels, grid frequency or pipeline pressure. In any sector that is a safety incident.
- **Adding latency or failure modes** to the live control path, which asset owners in every sector will not accept.
- Deception products that ship today (e.g. FortiDeceptor) deliberately deploy **passively alongside** live OT.

**Recommended:** a separate decoy twin on its own IPs or VLAN. Traffic reaches it through reconnaissance lures such as fake HMI shortcuts, honey credentials, and DNS or asset-inventory entries, or through network-level redirection of sessions that are already untrusted. If GhostGrid fails, the real OT network is unaffected. The pitch still holds: "the attacker thinks they're on the real system."

---

## 8. Sector profile data (South Africa)

### 8.1 Power
- **Nominal frequency:** 50 Hz.
- **SA Grid Code** ([System Operation Code, NERSA](https://www.nersa.org.za/files/files/2022/02/SAGC-System-Ops-Version-10.1_January-2022.pdf)): stations must use reasonable endeavours to keep frequency between **49 and 51 Hz**. **Below 49.85 Hz**, all available plant runs at maximum continuous rating and emergency reserves are dispatched.
- **Statistics of SA grid frequency** ([Rydin Gorjão & Maritz (University of the Free State), arXiv 2211.05582](https://arxiv.org/abs/2211.05582)):
  - The distributions are **non-Gaussian**: heavy-tailed (kurtosis > 3) and skewed.
  - Excursions of about ±300 mHz appear in the plotted data.
  - **Load shedding** is a visible driver.
  - Public SA data is only 15-minute resolution, so the power profile must be **modelled rather than replayed** (swing equation with multiplicative noise).
- **Storylines must match current reality.** Formal load shedding has been suspended since about May 2025, but **local load reduction** (05:00–09:00, 17:00–22:00 in overloaded areas) continues. Use load reduction, not "Stage N load shedding". Otherwise the decoy is out of date and gives itself away ([Eskom](https://www.eskom.co.za/power-system-status/), [EnergyBee](https://energybee.co.za/news/load-reduction-schedule-south-africa-2026)).

### 8.2 Water
- Rand Water treats and supplies bulk water to 11M+ people, with testing against **SANS 241**, South Africa's drinking-water standard (TechCentral).
- Physics to model:
  - reservoir level = ∫(inflow − outflow);
  - pump on/off drives flow and pressure;
  - the network is gravity-fed, so higher-lying areas lose supply first, and pressure loss creates a back-siphoning risk (The Citizen).
- The timescale is **hours** for reservoir drawdown and **minutes** for pressure transients, much slower than grid frequency. That makes the water physics simpler to build credibly.
- **Still to research:** typical SA reservoir and pump-station tag structures, and SANS 241 parameter limits (chlorine residual, turbidity) for the dosing values.

### 8.3 Ports, rail and pipelines (Transnet), fuel and petrochemical
- **Still to research.** Candidate signals are pipeline pressure and flow, valve positions, and tank-farm levels. Safety-instrumented systems, the kind Triton targeted, would be a high-value decoy target.

---

## 9. Open questions for you

1. **Inline or separate decoy (§7)?** I recommend a separate decoy.
2. **Which sector profiles for the hackathon demo?** I recommend **water as the first, fully built profile**, for three reasons:
   - it's topical because of Rand Water;
   - its physics is slower and simpler;
   - Modbus is common in water.

   Add **power as a second, thinner profile** to show the core really is sector-agnostic. Two profiles on one engine back up the "all critical infrastructure" claim; one profile doesn't.
3. **Protocol order:** Modbus TCP first (FrostyGoop and water PLCs), then IEC-104 (power)?
4. **Attacker for the demo:** a scripted reconnaissance bot (Tier 1), an LLM-agent attacker (Tier 2), or both?
5. **Relationship to LLMPot:** cite it as prior work and set GhostGrid apart from it, or reuse its Modbus emulation?

---

## Sources

**LLM and ICS honeypot research**
- [LLMPot (arXiv 2405.05999)](https://arxiv.org/abs/2405.05999) · [code](https://github.com/momalab/LLMPot)
- [SoK: Honeypots & LLMs (arXiv 2510.25939)](https://arxiv.org/abs/2510.25939)
- [LLMHoney (arXiv 2509.01463)](https://arxiv.org/abs/2509.01463)
- [LLM in the Shell / shelLM (arXiv 2309.00155)](https://arxiv.org/abs/2309.00155)
- [HoneyGPT / HoneyLLM](https://www.cse.psu.edu/~sxz16/papers/HoneyGPT.pdf)
- [Mladenov et al., "All that Glitters is not Gold", EuroS&P 2025](https://gsmaragd.github.io/publications/EuroSP2025-ICS/EuroSP2025-ICS.pdf)
- [Maesschalck et al., World Wide ICS Honeypots (ACSAC ICSS 2021)](https://www.acsac.org/2021/workshops/icss/2021-icss-maesschalck.pdf)
- [Dodson et al., CyCon 2020](https://ccdcoe.org/uploads/2020/05/CyCon_2020_15_Dodson_Beresford_Vingaard.pdf)
- [ICSLure (arXiv 2509.04080)](https://arxiv.org/abs/2509.04080) · [HoneyICS (ACM ARES 2023)](https://dl.acm.org/doi/10.1145/3600160.3604984)
- [FortiDeceptor](https://www.fortinet.com/products/fortideceptor) · [Deception vendors overview](https://expertinsights.com/network-security/best-deception-technology-companies)

**Incidents**
- Power: [ESET: Industroyer2](https://www.welivesecurity.com/2022/04/12/industroyer2-industroyer-reloaded/) · [Netresec IEC-104 analysis](https://www.netresec.com/?page=Blog&month=2022-04&post=Industroyer2-IEC-104-Analysis) · [MITRE S1072](https://attack.mitre.org/software/S1072/)
- Petrochemical: [Mandiant: TRITON](https://cloud.google.com/blog/topics/threat-intelligence/attackers-deploy-new-ics-attack-framework-triton) · [CSO Online (FireEye 2019 findings)](https://www.csoonline.com/article/567145/group-behind-triton-industrial-sabotage-malware-made-more-victims.html)
- Heating: [Dragos: FrostyGoop](https://hub.dragos.com/report/frostygoop-ics-malware-impacting-operational-technology) · [SecurityWeek](https://www.securityweek.com/frostygoop-ics-malware-left-ukrainian-citys-residents-without-heating/)
- Water: [WaterISAC: Aliquippa](https://www.waterisac.org/tlpclear-water-utility-control-system-cyber-incident-advisory-icsscada-incident-municipal) · [Sophos: CyberAv3ngers](https://www.sophos.com/en-us/blog/iranian-cyber-av3ngers-compromise-unitronics-systems) · [Bremanger dam sabotage](https://en.wikipedia.org/wiki/Bremanger_dam_sabotage) · [Claroty](https://claroty.com/blog/cyberattack-on-norwegian-dam-highlights-password-exposure-risks)
- Cross-sector: [Kudelski: PIPEDREAM](https://kudelskisecurity.com/research/incontroller-pipedream-ics-toolkit-targeting-energy-sector) · [CISA AA24-038A (Volt Typhoon)](https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a)
- Rail (out of scope): [Schneier: Polish trains](https://www.schneier.com/blog/archives/2023/08/remotely-stopping-polish-trains.html)

**South Africa**
- [TechCentral: Rand Water cyberattack](https://techcentral.co.za/rand-water-cyberattack/285746/) · [MyBroadband](https://mybroadband.co.za/news/security/665683-south-africas-largest-bulk-water-utility-crippled-by-cyberattack.html) · [The Citizen: empty reservoirs](https://www.citizen.co.za/news/forget-poisoned-water-a-cyberattacks-real-threat-to-gauteng-is-empty-reservoirs/)
- [Transnet ransomware attack](https://en.wikipedia.org/wiki/Transnet_ransomware_attack) · [HSF: SA energy sector](https://www.hsfkramer.com/notes/africa/2023-08/high-profile-cyberattacks-increase-emphasis-upon-cyber-resilience-in-south-africas-energy-sector) · [IT-Online, Aug 2026](https://it-online.co.za/2026/08/14/sas-critical-infrastructure-is-running-on-unpatched-systems-attackers-know-that/) · [ISS Africa](https://issafrica.org/iss-today/critical-infrastructure-attacks-why-south-africa-should-worry)
- [Critical Infrastructure Protection Act 8 of 2019](https://lawlibrary.org.za/akn/za/act/2019/8/eng@2019-11-28) · [Cybercrimes Act & POPIA (Obiter)](https://obiter.mandela.ac.za/article/view/14883)
- [SA Grid Code: System Operation Code v10.1](https://www.nersa.org.za/files/files/2022/02/SAGC-System-Ops-Version-10.1_January-2022.pdf) · [Stochastic nature of SA grid frequency (arXiv 2211.05582)](https://arxiv.org/abs/2211.05582)

**Frameworks**
- [MITRE Engage](https://engage.mitre.org/)
