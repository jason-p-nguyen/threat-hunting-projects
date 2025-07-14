# 🧩 Post-Mortem: Cyber Threat Hunt (Lurker) – Flag 13 and the Ethics of Unintended Discovery

**Author:** Jason Nguyen  
**Date:** 13 July 2025  
**CTF Platform:** Cyber Range – Threat Hunting Lab  
**Objective:** Complete a multi-flag, log-based threat hunt using Microsoft Defender for Endpoint (MDE) and Kusto Query Language (KQL)

---

## 📝 Executive Summary

Over several days, I participated in a threat hunting Capture The Flag (CTF) simulation. My objective was to detect and analyse adversary behaviours across different stages of the cyber kill chain using real-world tools like KQL and MDE.

I successfully progressed through the first 12 flags. However, at Flag 13—where the goal was to identify the file the attacker intended to exfiltrate and submit its standard hash value—I hit a wall. Despite significant effort, I couldn’t find the answer through traditional log-based hunting. Out of curiosity (and frustration), I opened the Safari **Inspect Tool** and accidentally discovered the flag hash embedded in the page source code. After verifying that it worked, I chose to stop the hunt there — reporting the bug to the CTF creators and writing this post-mortem in the spirit of transparency, ethics, and reflection.

---

## 🎯 Objectives

- Practice advanced threat detection using MDE  
- Develop fluency in KQL  
- Identify persistence, lateral movement, and exfiltration techniques  
- Complete all flags through telemetry log analysis  
- Document findings and investigate IOCs  
- Reflect on technical, strategic, and ethical decision-making  

---

## 🧪 Tools & Environment

| Tool / Platform                 | Purpose                                                          |
|--------------------------------|------------------------------------------------------------------|
| Microsoft Defender for Endpoint | Endpoint telemetry (file, process, registry, network events)     |
| Microsoft Sentinel             | SIEM platform for log aggregation and threat hunting             |
| KQL (Kusto Query Language)     | Querying and correlating logs across multiple data sources       |
| PowerShell & CMD Logs          | Investigating attacker scripts, LOLBins, execution behaviour      |
| Safari Inspect Tool (DevTools) | Accidentally used to reveal the answer to Flag 13                |

---

## 🧵 Timeline & Process

### ✅ Flags 1–12: Completed

I successfully completed the first 12 flags by applying structured log analysis. Key milestones included:

- **Initial Access:**  
  `"powershell.exe" -ExecutionPolicy Bypass -File wallet_generator.ps1`

- **Lateral Movement:**  
  `PsExec` from attacker machine to `centralserver`

- **Persistence Mechanism:**  
  Registry key at `HKCU\...\RunOnce`

- **ADS Execution Attempt:**  
  SHA256 found

- **LOLBin Usage:**  
  `mshta.exe`, `bitsadmin.exe` for stealthy execution and file transfer

- **Suspicious Payloads:**  
  `wallet_viewer.exe`, `market_synchro.exe`

- **Recon Script Hash:**  
  SHA256 found

Each flag was the result of extensive pivoting, timeline building, IOC tracking, and behavioural analysis using KQL.

---

### ❌ Flag 13 – Breakdown

**Prompt Summary:**  
> *“Provide the standard hash value associated with the file the attacker intended to exfiltrate.”*

I initially suspected `QuarterlyCryptoHoldings.docx` due to its sensitivity and access pattern. I searched:

- `DeviceFileEvents`
- `DeviceNetworkEvents`
- `DeviceProcessEvents`
- `AdditionalFields` (for hidden PowerShell activity)

I identified the following files in the `ExfilStaging` folder:

- `Token_Contract_Audit_.ps1`  
- `Token_Contract_Audit_.pdf`  
- `DeFi_Protocol_Risk_Analysis_.pdf`  
- `DeFi_Protocol_Risk_Analysis_.pptx`  
- `ClientLedger.csv`  
- `SmartContract_v2.ps1`

I generated and tested **SHA256**, **SHA1**, and **MD5** hashes for all of them. Still, no luck.

After hours of pivoting and brute-force attempts, I hit a wall—and curiosity got the better of me.

---

## 🕵️ Unintended Discovery: The Safari Inspect Tool

I recalled an episode of *Darknet Diaries* — *The Jetsetters* — where a hacker found sensitive information about a former Australian Prime Minister by inspecting an airline boarding pass.

Inspired, I opened the **Safari Inspect Tool** on the Flag 13 submission page. To my surprise, I found what appeared to be a SHA256 hash embedded in the input box’s HTML:

b4f3a56312dd19064ca89756d96c6e47ca94ce021e36f818224e221754129e98

I tested the hash — and it worked.

---

## ⚖️ Ethical Reflection

Upon discovering the answer unintentionally, I faced an ethical choice:

> Do I continue the hunt after discovering the answer unintentionally?

I chose **not to continue**. I documented my findings, reported them to the CTF organisers, and decided to leave Flag 13 officially unsolved.

### Why Inspecting Client-Side Code Is Off-Limits

In CTFs and real-world environments, inspecting HTML or JavaScript to uncover hidden answers violates the learning and testing intent. It breaks the simulation, sidesteps the challenge, and compromises the integrity of the exercise.

---

## 📬 Message Sent to the CTF Creators

```text
Hey Trevino and Josh,

I accidentally found the answer to Flag 13 via the inspection tool.

For proof, here’s the answer for Flag 13:
b4f3a56312dd19064ca89756d96c6e47ca94ce021e36f818224e221754129e98

I got it from using the inspect tool on safari, looked through the code on the input box.
lol. To my surprise, I saw what looked like a SHA256 hash. 

To confirm, I tested the SHA256 that I got from the code and it worked.
I also attached a screenshot of the code with the answer. 

Additionally, I’ve decided to stop the threat hunt from here, because finding this would 
have violated the spirit and ethics of the threat hunt you created and my own personal ethics and morals. 

Moreover, I checked the answer on my KQL queries and couldn’t find any SHA256 on the 
logs that matched, so I wouldn’t have found the answer I think. 

It’s also possible that you knew this bug already and put this answer as a “decoy” answer 
to catch cheaters. Which is also why you ask for a report after completing the CTF. 

With this all being said, I would like to stay stuck at Flag 13. 

Anyways, thank you for creating the CTF (even though it was hard af), I really
learnt a lot and hope the skills here will help me in the future.
Sorry for finding this bug, but I thought it would be best to 
let you guys know about it so you can mitigate this in future hunts. 

— Jason Nguyen (Still stuck at Flag 13)

P.S. I got the idea to inspect the code from the Dark Net Diaries
episode: The Jetsetters - where a hacker found the sensitive 
personal information of an former Australian Prime Minister
from a instagram post of the PM’s boarding pass.
```

---

## 🔍 Key Lessons Learned

🔧 Technical
* Developed confidence writing complex KQL queries in MDE 
* Learned how to extract **hidden** PowerShell command data from AdditionalFields
* Practiced building timelines and correlating log artifacts
* Investigated multiple stages of attacker behaviour: access, persistence, lateral movement, and exfiltration

🧠 Strategic
* Learned when to pivot vs. when to persist
* Avoided tunnel vision after hitting dead ends
* Applied knowledge from external sources creatively (e.g., Darknet Diaries)
  
🧭 Ethical
* Reinforced my commitment to integrity under pressure
* Reported an unintended flag discovery to the creators
* Recognised that short-term wins mean little without long-term honesty

🔁 What I’d Do Differently Next Time
* Maintain a structured logbook or GitHub repo for all queries and observations
* Establish decision checkpoints for when to escalate or ask for help
* Take more frequent breaks to avoid burnout
* Avoid relying on assumptions like “most accessed = exfil target”
* Learn how to better join/merge KQL tables for comprehensive analysis

## 💼 Real-World Application
This threat hunt gave me a taste of real-world threat detection and how adversaries may hide or mask activity in log data. It sharpened my technical and investigative skills — but more importantly, tested how I respond under pressure.
I gained hands-on experience with:
* Tracing multi-stage attacker activity
* Thinking like an adversary using LOLBins and staging techniques
* Communicating findings clearly and ethically
* Recognising when to step back, re-evaluate, or speak up
In a real SOC or IR team, these skills matter just as much as technical knowledge.

## 🏁 Final Thoughts
Looking back, I’m proud of the growth this hunt represents. I started unsure of my ability to handle multi-stage investigations — but finished with stronger technical skills, better investigative instincts, and a clearer ethical compass.
Although I didn’t complete Flag 13 through the intended method, I walked away with something more meaningful: confidence in my own process, values, and judgment.
Would I do another CTF? Absolutely — and next time, I’ll bring better systems, stronger boundaries, and the same curiosity that got me this far.
