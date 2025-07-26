# 🧠 Threat Hunting Postmortem – Dropbox Data Exfiltration (Insider Threat)

## 1. 🗂 Project Overview

**Project Title:**  
Dropbox Data Exfiltration (Insider Threat)

**Threat Scenario:**  
Simulated an insider threat where a user exfiltrated sensitive files to a personal Dropbox account.

**Goal of the Hunt:**  
- Simulate a realistic insider threat conducting data exfiltration  
- Create a Dropbox account and prepare a fake employee identity  
- Generate sensitive files and change file metadata  
- Install Dropbox and upload files stealthily  
- Hunt for related activity in Microsoft Defender for Endpoint (MDE) using KQL

---

## 2. ✅ What Went Well

- Generating sensitive files and creating a confidential folder was straightforward using ChatGPT.
- Added a **Cyber Kill Chain** and **MITRE ATT&CK mapping** to the report — a valuable visual addition for clarity and professionalism.
- Improved **KQL query skills** thanks to prior CTF experience, which translated into faster and more confident log analysis.

**Effective Tools & Techniques:**
- Step-by-step guide development made the process more organized.
- KQL was used effectively for querying relevant signals.
- Added visual mapping (Cyber Kill Chain + MITRE ATT&CK) enhanced report presentation and made the TTPs clearer to the reader.

**Skills Demonstrated:**
- KQL log analysis and threat hunting in MDE  
- Email account creation (ProtonMail) for threat actor setup  
- Creative iteration based on a previous project (unauthorized Firefox usage)  
- Simulating a user (John Doe) and building a realistic threat scenario  
- Debugging PowerShell-based Dropbox installation and handling cleanup

---

## 3. ⚠️ What Could Be Improved

- A week-long delay between implementation and hunting (due to the CTF) disrupted workflow and made it harder to recall earlier steps.
- Setting up email accounts without SMS verification was time-consuming but informative from a security standpoint.
- PowerShell-based Dropbox installation was trickier than expected — had to choose between installer vs. scripting. Ultimately used PowerShell.
- Cleanup script failed to run, requiring manual file and app removal.
- Could not create a new "John Doe" user on the VM due to permissions; ended up using the admin account, which limited realism.

**Mistakes & Oversights:**
- Initially unclear about the **threat actor’s persona** (accidental vs. malicious insider) — the scope shifted mid-project.
- Underestimated the impact of delayed momentum between phases — learned to develop a clear **step-by-step workflow** to stay on track.
- Creating email accounts took longer than expected due to multi-factor authentication barriers.

**Unexpected Difficulties:**
- PowerShell cleanup script failed and was hard to debug, so manual cleanup was required.

---

## 4. 📘 Lessons Learned

- Define a **clear threat actor persona and capabilities** early on (e.g., novice employee vs. malicious insider).
- Preconfigure email accounts for future use to save time.
- Rebuild the VM using a realistic user schema (e.g., "John Doe") or set up a network to simulate lateral movement or broader scenarios.
- Plant more files in multiple locations to increase search surface.
- Test PowerShell scripts outside the hunt first or iterate during implementation to **generate cleaner logs for detection**.
- Consider adding a **forensics or incident response** phase as a follow-up project, showing how an IR team might handle detection escalation.

**What I Learned:**
- Getting lost in noisy logs is becoming less of a problem — I’m better at spotting anomalies and filtering data using KQL.
- Learned about additional MDE data tables that can enrich investigation.
- Step-by-step planning significantly improves execution and makes it easier to pause/resume long projects.

**Change in Approach:**
- I now rely on a **documented step-by-step process** to stay focused, improve pipelines, and reduce confusion between project phases.

---

## 5. 🔮 Next Steps & Future Ideas

**Project Expansion Ideas:**
- Replace Dropbox with **C2-based exfiltration** for added realism  
- Simulate **automated or persistent malware** that exfiltrates files on its own  
- Add a **forensics and incident response** report separate from the hunt  

**Future Focus:**
- Not sure yet — potential next steps could involve CVE exploitation, Linux-based scenarios, or IR simulations

**Relevance to SOC/Real-World:**
- Yes. Unauthorized tools like Dropbox are commonly used — even without malicious intent, they pose a data leakage risk.
- Simulates a realistic insider threat workflow, showing how exfiltration might look in logs.

---

## 6. 🛠 Tools & References

**Tools Used:**
- KQL (Kusto Query Language)  
- Microsoft Defender for Endpoint (MDE)  
- PowerShell  
- ChatGPT  
- Dropbox  
- ProtonMail (proton.me)  
- Windows 10  
- Microsoft Azure  

**GitHub Repository:**  
🔗 [Dropbox Exfiltration – Threat Hunting Project](https://github.com/jason-p-nguyen/threat-hunting-projects/tree/main/dropbox_exfiltration)
