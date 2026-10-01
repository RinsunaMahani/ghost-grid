# What South Africa Already Has, and Where GhostGrid and the Sealed Data Box Fit

*Compiled 2026-09-28. Covers both plans in this repo. Research: [research.md](research.md) (GhostGrid) and [research-single-box.md](research-single-box.md) (Sealed Data Box).*

## 1. What South Africa already has

### 1.1 National level

| What | Status |
|---|---|
| **Cybersecurity Hub**, the national CSIRT (incident response team) | Set up in 2015 under the National Cybersecurity Policy Framework (2012), now run by DCDT (the Department of Communications and Digital Technologies). It coordinates incident response and information sharing ([Cybersecurity Hub](https://www.cybersecurityhub.gov.za/), [DCDT](https://www.dcdt.gov.za/cybersecurity-hub-project.html)). **In May 2026**, after a wave of DDoS attacks on SA hosting providers (1-grid, Xneelo, Host Africa and others), experts said SA "possesses legislative frameworks … but lacks practical capacity". The Hub's website was inactive, with only email contact, and SAPS has no dedicated cyber division ([TechCentral](https://techcentral.co.za/ddos-attacks-expose-south-africas-cyber-response-gap/281740/)). |
| **Laws** | Critical Infrastructure Protection Act 8 of 2019 (only partly in force), Cybercrimes Act 19 of 2020, and POPIA (the Protection of Personal Information Act). There is **no dedicated critical-infrastructure cybersecurity law**, and most OT environments lack asset inventories ([IT-Online, Aug 2026](https://it-online.co.za/2026/08/14/sas-critical-infrastructure-is-running-on-unpatched-systems-attackers-know-that/)). |
| **Classified information** | **MISS** (Minimum Information Security Standards) governs classified government information ([SITA copy](https://www.sita.co.za/sites/default/files/documents/MISS/Minimum%20Information%20Security%20Standards%20(MISS).pdf)). **COMSEC**, a state-owned company under the intelligence services, secures government communications and verifies the security products government uses ([Wikipedia](https://en.wikipedia.org/wiki/COMSEC_(South_Africa))). This covers **government**, not SOE plant or municipal infrastructure. |
| **Data policy** | The **National Policy on Data and Cloud (May 2024)** requires government data related to national security and sovereignty to be "stored only in digital infrastructure located within the borders of South Africa". **SITA**, the State Information Technology Agency, sources government data centres, which will be unified and cloud-enabled ([Bowmans](https://bowmanslaw.com/insights/south-africa-the-national-policy-on-data-and-cloud-some-highlights/), [gov.za](https://www.gov.za/sites/default/files/gcis_document/202406/50741gen2533.pdf)). |
| **Research** | **CSIR** (the Council for Scientific and Industrial Research) has researched a **virtual honeynet** protecting SANReN, the national research network ([Pieterse, ResearchGate](https://www.researchgate.net/profile/Heloise-Pieterse)). It has also worked on an SA threat-intelligence sharing platform, noting that commercial threat-intel providers have **"little to no presence in South Africa"** and that their insights are "slanted towards developed countries" ([CSIR ResearchSpace](https://researchspace.csir.co.za/dspace/handle/10204/10159)). And it has published on the **privacy and legal implications of processing honeypot data** ([Springer](https://link.springer.com/chapter/10.1007/978-3-032-09660-9_2)). **Stellenbosch University** ran a 12,900 km quantum satellite link with China in 2024 ([SU](https://www.su.ac.za/en/node/19887)). |

### 1.2 Industry

| What | Notes |
|---|---|
| **Thinkst Canary** (Cape Town) | **South Africa's honeypot success story.** Founded by Haroon Meer, it launched Canary honeypots and tripwires in 2015, and Canarytokens is open source. It reached **$19M annual recurring revenue with no venture capital** by May 2024 ([MyBroadband](https://mybroadband.co.za/news/security/557130-the-south-african-hacker-who-revolutionised-cybersecurity-around-the-world.html), [Gadgeteer](https://gadgeteer.co.za/the-south-african-hacker-who-revolutionised-cybersecurity-around-the-world-with-his-canary-honeypot-tools/)). It is aimed mainly at **enterprise IT**; I didn't confirm how deep its OT/ICS support goes. |
| Imported OT security | OT monitoring (Dragos, Claroty, Nozomi) and OT deception (e.g. FortiDeceptor, [research.md §1.4](research.md)) are global products sold through partners. |
| Backup and vaults | Global: Dell Cyber Recovery, Veeam, Commvault, Rubrik. Local: e.g. **Vault-IT** (Durban, immutable backups) ([Vault-IT](https://www.vaultit.co.za/)). An SA industry view from **22 Sept 2026**: attackers now "corrupt, encrypt, or poison backup systems", sometimes staying undetected for weeks. It recommends **air-gapped, immutable copies, data kept within SA borders, and quarterly recovery drills** ([Lifestyle & Tech](https://lifestyleandtech.co.za/ai-cloud/article/2026-09-22/when-the-last-line-of-defence-fails-the-new-reality-of-backup-resilience)). |
| Operators | Eskom has a CISO and reports ~1 billion attempted attacks a month (IT-Online). Rand Water's IT/OT separation held in September 2026 ([TechCentral](https://techcentral.co.za/rand-water-cyberattack/285746/)). |

### 1.3 The gaps
1. **Capacity, not law.** The frameworks exist, but national response capacity is thin (TechCentral, May 2026).
2. **No local threat intelligence on OT.** Commercial intel barely covers SA (CSIR), and no one publishes SA-specific data on attacks against infrastructure control systems.
3. **Decoys exist for IT, not for SA OT.** Thinkst covers enterprise IT well. For OT, SA relies on imported deception built for other markets.
4. **Vaults are mostly *logically* isolated.** Most vault products isolate data with credentials and network rules on mains-powered hardware, often in the cloud. Physically isolated, independently powered storage isn't a standard offering.
5. **Classified-grade protections (MISS, COMSEC) cover government, not SOE plants or municipalities.**

---

## 2. GhostGrid: different? effective?

**Different from what SA has? Yes, on four points:**

| | Thinkst Canary | Imported OT deception | CSIR honeynet | **GhostGrid** |
|---|---|---|---|---|
| Main target | Enterprise IT | OT | Research network | **OT across CI sectors** |
| Decoy content | Configured services | Fixed templates | Research honeypots | **Generated per site and sector by a local LLM, with SA-realistic telemetry** |
| Goal | Detect on touch | Detect | Collect intel | **Detect, then *keep the attacker busy* and measure SOC time gained** |
| Where it runs | Appliance / cloud console | Vendor platform | Research infrastructure | **Air-gapped, on site** |
| SA threat intel | — | Vendor's global feed | Yes (research) | **SA OT-specific, filling the CSIR-identified gap** |

**Effective?**
- **Detection: very likely.** No legitimate user ever talks to a decoy, so any contact is a high-quality alert. That is the principle Thinkst built a $19M business on.
- **Time gained: unproven.** The research ([research.md §5](research.md)) shows skilled humans can spot simulations, and most honeypot traffic is simple bots. The value is strongest against automated and AI-driven reconnaissance. **The hackathon demo needs to measure time gained**, not just claim it.
- **Positioning:** judges will know Thinkst. Present GhostGrid as complementary: "Canary tells you someone's in; GhostGrid keeps an OT attacker busy in a convincing fake plant and tells you how much time you've bought."

## 3. Sealed Data Box: different? effective?

**Different from what SA has? Yes:**
- **Physical, not logical, isolation.** No network path that credentials or firewall rules control.
- **Battery-only power.** This removes power-line leaks (research-single-box.md §3.1), and the box keeps running through load reduction.
- **An alarmed link to a receive-only monitoring room, plus the timed tripwire loop.** This is the kind of protection classified government facilities use (§1.1), which SOEs and municipalities don't have.
- **Data stays on site in SA,** which matches the Data and Cloud Policy and the industry's localisation advice.

**Effective? Yes against the main SA threat, with one important fix:**
- It directly addresses the pattern behind City Power, Transnet, Eskom and Rand Water: attackers reaching data and backups.
- ⚠️ **Poisoned data still gets in.** The 22 Sept 2026 advice warns that attackers corrupt backups for weeks before striking. A write-only vault that receives corrupted or encrypted files will faithfully store them. **The fix:**
  - keep **versioned, never-overwritten copies** inside the box;
  - use the **loop's lap checks as a ransomware alarm.** If a large share of file fingerprints changes at once, something is encrypting the data, so the box stops accepting new versions and raises an alert.
  - This turns the NASCAR loop from a nice-to-have into a core defence.
- **Scale:** suited to critical records (drawings, configurations, asset registers, keys, key databases), not whole data centres. Good targets are municipalities, SOE sites and hospitals, which can't afford Dell-class vaults.

## 4. Summary

| | Exists in SA? | Different? | Effective? |
|---|---|---|---|
| **GhostGrid** | IT decoys (Thinkst), imported OT deception, CSIR research honeynet | **Yes:** OT-focused, generative, SA-realistic, tarpitting and time-gained metric, air-gapped | **Detection: yes. Tarpitting: to be proven in the demo.** |
| **Sealed Data Box** | Logically air-gapped and cloud vaults (global and local), MISS/COMSEC for government only | **Yes:** physical isolation, battery power, alarmed monitoring link, tripwire loop, for non-government CI | **Yes against ransomware on backups,** if it keeps versions and uses the loop as a mass-change alarm |

---

## Sources
- [Cybersecurity Hub](https://www.cybersecurityhub.gov.za/) · [DCDT: Cybersecurity Hub project](https://www.dcdt.gov.za/cybersecurity-hub-project.html) · [TechCentral: DDoS attacks expose SA's cyber response gap (May 2026)](https://techcentral.co.za/ddos-attacks-expose-south-africas-cyber-response-gap/281740/)
- [IT-Online, Aug 2026](https://it-online.co.za/2026/08/14/sas-critical-infrastructure-is-running-on-unpatched-systems-attackers-know-that/) · [TechCentral: Rand Water](https://techcentral.co.za/rand-water-cyberattack/285746/)
- [MISS (SITA copy)](https://www.sita.co.za/sites/default/files/documents/MISS/Minimum%20Information%20Security%20Standards%20(MISS).pdf) · [COMSEC (South Africa)](https://en.wikipedia.org/wiki/COMSEC_(South_Africa))
- [Bowmans: National Policy on Data and Cloud](https://bowmanslaw.com/insights/south-africa-the-national-policy-on-data-and-cloud-some-highlights/) · [National Policy on Data and Cloud 2024 (gov.za)](https://www.gov.za/sites/default/files/gcis_document/202406/50741gen2533.pdf)
- [CSIR ResearchSpace: threat intel sharing platform](https://researchspace.csir.co.za/dspace/handle/10204/10159) · [Heloise Pieterse (CSIR)](https://www.researchgate.net/profile/Heloise-Pieterse) · [Privacy and legal implications of honeypot data (Springer)](https://link.springer.com/chapter/10.1007/978-3-032-09660-9_2) · [Stellenbosch quantum link](https://www.su.ac.za/en/node/19887)
- [MyBroadband: Haroon Meer / Thinkst](https://mybroadband.co.za/news/security/557130-the-south-african-hacker-who-revolutionised-cybersecurity-around-the-world.html) · [Gadgeteer: Thinkst Canary](https://gadgeteer.co.za/the-south-african-hacker-who-revolutionised-cybersecurity-around-the-world-with-his-canary-honeypot-tools/)
- [Vault-IT](https://www.vaultit.co.za/) · [Lifestyle & Tech: backup resilience (22 Sept 2026)](https://lifestyleandtech.co.za/ai-cloud/article/2026-09-22/when-the-last-line-of-defence-fails-the-new-reality-of-backup-resilience)
