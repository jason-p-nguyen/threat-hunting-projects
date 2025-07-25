# 🧠 Threat Hunting Postmortem – Unauthorized Firefox Installation and Extension Usage

## 1. 🗂 Project Overview

**Project Title:**  
Unauthorized Firefox Installation and Extension Usage

**Threat Scenario:**  
Simulated an unauthorized installation and usage of Firefox by an employee in a corporate environment.

**Goal of the Hunt:**  
- Complete my first solo end-to-end threat hunting project  
- Simulate employee behavior in a real-world corporate setting  
- Use PowerShell to silently install Firefox  
- Identify and analyze related log activity using MDE and KQL  
- Document the findings in a complete threat hunt report

---

## 2. ✅ What Went Well

- Used a previous **Tor usage lab** as a base, which made designing this scenario faster and more structured.
- Created a **repeatable pipeline** for scenario design, implementation, and reporting — helpful for future projects.

**Effective Tools & Techniques:**
- **PowerShell** for running the silent install of Firefox  
- **ChatGPT** was extremely helpful for writing and debugging scripts  
- **KQL and Microsoft Defender for Endpoint (MDE)** were effective for log hunting  
- Built a working **project pipeline** that included scenario creation, hunting, and reporting

**Skills Demonstrated:**
- End-to-end creation and execution of a threat hunting scenario  
- PowerShell scripting for silent software installation  
- Debugging and problem solving with AI assistance  
- Writing a structured report based on logs and behavior analysis

---

## 3. ⚠️ What Could Be Improved

- Originally included an uninstall script and a text file artifact — later removed them to make the threat scenario more realistic.
- Couldn’t find all logs related to Firefox behavior, such as **extension installation activity**.

**Mistakes & Oversights:**
- The **threat actor's persona** was not well-defined. In retrospect, a finance employee likely wouldn’t know how to use PowerShell for a silent install, so the scenario needed clearer boundaries on the actor's skills and intent.
- I forgot to download and add logs of the KQL queries to the GitHub project folder. 

**Unexpected Difficulties:**
- None major, since the process followed a similar flow to the earlier Tor usage lab.

---

## 4. 📘 Lessons Learned

- Define the **actor’s intent and technical skill level** from the beginning to create a more believable scenario.
- Realized that scenario development, hunting, and reporting is **time-consuming**, even with AI support.
- Future projects will benefit from a **repeatable template or pipeline** to maintain consistency and save time.

**Insights Gained:**
- I'm growing more confident with log analysis, but need to dig deeper and consider **forensics** for better context.
- Scenario creation is just as important as the hunt — it's the foundation of everything that follows.

**Shift in Approach:**
- I now recognize the need to create **clearer personas** for simulated users, and to build more realism into their behavior.

---

## 5. 🔮 Next Steps & Future Ideas

**Expansion Ideas:**
- Add a **follow-up incident response report**, showing how alerts or policies could be implemented to prevent this behavior

**Future Focus:**
- Simulate another **unauthorized software installation** — e.g., AnyDesk or TeamViewer  
- Expand into **alert rule creation or endpoint lockdown strategies**

**Relevance to SOC/Real-World Environments:**
- Yes. Unauthorized software is a **common security risk** in workplaces, especially when software restrictions or policies are vague or unenforced.

---

## 6. 🛠 Tools & References

**Tools Used:**
- Firefox  
- PowerShell  
- Windows 10  
- Microsoft Defender for Endpoint (MDE)  
- KQL  
- Microsoft Azure  

**GitHub Repository:**  
🔗 [Unauthorized Firefox Installation – Threat Hunting Project](https://github.com/jason-p-nguyen/threat-hunting-projects/tree/main/unauthorised_firefox_usage)
