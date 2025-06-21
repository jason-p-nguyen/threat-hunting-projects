# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/joshmadakor0/threat-hunting-scenario-tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "employee" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `2024-11-08T22:27:19.7259964Z`. These events began at `2024-11-08T22:14:48.6065231Z`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName == "employee"  
| where FileName contains "tor"  
| where Timestamp >= datetime(2024-11-08T22:14:48.6065231Z)  
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/71402e84-8767-44f8-908c-1805be31122d">

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser-windows-x86_64-portable-14.0.1.exe". Based on the logs returned, at `2024-11-08T22:16:47.4484567Z`, an employee on the "threat-hunt-lab" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.0.1.exe"  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b07ac4b4-9cb3-4834-8fac-9f5f29709d78">

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "employee" actually opened the TOR browser. There was evidence that they did open it at `2024-11-08T22:17:21.6357935Z`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

**Query used to locate events:**

```kql
DeviceProcessEvents  
| where DeviceName == "threat-hunt-lab"  
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")  
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/b13707ae-8c2d-4081-a381-2b521d3a0d8f">

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `2024-11-08T22:18:01.1246358Z`, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address `176.198.159.33` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe`. There were a couple of other connections to sites over port `443`.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "threat-hunt-lab"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1212" alt="image" src="https://github.com/user-attachments/assets/87a02b5b-7d12-4f53-9255-f5e750d0e3cb">

---

## Chronological Event Timeline 

## 1. File Renamed - TOR Installer

**Timestamp:** 2025-06-20T01:57:11.869503Z
**Event:** The user "uyowfonkmiv" renamed a file named `tor-browser-windows-x86_64-portable-14.5.3.exe` in the Downloads folder.
**Action:** File rename detected, likely indicating preparation for installation.
**File Path:**
`C:\Users\uyowfonkmiv\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

## 2. Process Execution - TOR Browser Installation

**Timestamp:** 2025-06-20T02:01:15.2403386Z
**Event:** The user "uyowfonkmiv" executed the renamed Tor Browser installer in silent mode using the `/S` flag.
**Action:** Process creation detected.
**Command:**
`tor-browser-windows-x86_64-portable-14.5.3.exe /S`
**File Path:**
`C:\Users\uyowfonkmiv\Downloads\tor-browser-windows-x86_64-portable-14.5.3.exe`

## 3. File Creation - TOR Program Files

**Timestamps:** 2025-06-20T02:01:29Z to 2025-06-20T02:01:38Z
**Event:** Multiple files related to the Tor Browser were created on the desktop, including the main binary (`tor.exe`), documentation files, and a desktop shortcut.
**Action:** File creation detected.
**Files Created:**

* tor.exe
* tor.txt
* Torbutton.txt
* Tor-Launcher.txt
* Tor Browser.lnk
  **Directory:**
  `C:\Users\uyowfonkmiv\Desktop\Tor Browser`

## 4. Process Execution - TOR Browser Launch

**Timestamp:** 2025-06-20T02:02:41.2739331Z
**Event:** The user launched the Tor Browser (`firefox.exe`) from the desktop directory.
**Action:** Process creation of Tor Browser detected.
**File Path:**
`C:\Users\uyowfonkmiv\Desktop\Tor Browser\Browser\firefox.exe`

## 5. Process Execution - TOR Runtime (tor.exe and firefox.exe)

**Timestamps:** 2025-06-20T02:02:46Z to 2025-06-20T02:03:23Z
**Event:** The system spawned multiple instances of `firefox.exe` and one `tor.exe` process, indicating full execution of the Tor Browser’s internal architecture.
**Action:** Multiple process creation events detected.
**Notable Process:**
`tor.exe` was run with custom configuration flags using torrc files and SOCKS proxy setup.
**tor.exe Path:**
`C:\Users\uyowfonkmiv\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

## 6. Network Connection - TOR Network Entry

**Timestamp:** 2025-06-20T02:03:09.9754231Z
**Event:** The user’s system, via `tor.exe`, successfully established an external connection to IP address `93.158.213.15` on port `443`, and also connected to `45.157.234.84` on port `9001`, which is commonly used for Tor relays.
**Action:** Outbound Tor network traffic confirmed.
**Process:** `tor.exe`
**File Path:**
`C:\Users\uyowfonkmiv\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

## 7. Additional Network Connections - Tor Browser Activity

**Timestamps:**

* 2025-06-20T02:03:06Z – Connected to `200.122.181.2` on port `443`
* 2025-06-20T02:03:08Z – Connected to `86.60.148.189` on port `9001`
* 2025-06-20T02:03:10Z – Connections to hidden service domains
* 2025-06-20T02:03:17Z – Localhost communication over port `9150`

**Event:** Multiple successful connections were initiated by both `tor.exe` and `firefox.exe`, suggesting Tor routing and potential browsing.
**Action:** Ongoing encrypted traffic and relay usage via Tor.
**Processes:** `tor.exe` and `firefox.exe`

## 8. File Creation - User Note or Artifact

**Timestamp:** 2025-06-20T02:13:03.034063Z
**Event:** A text file named `tor-shopping-list.txt` was created in the user's Documents folder. This may suggest a list of tasks, sites, or actions related to Tor activity.
**Action:** File creation detected.
**File Path:**
`C:\Users\uyowfonkmiv\Documents\tor-shopping-list.txt`

## 9. File Deletion - Cleanup Activity

**Timestamp:** 2025-06-20T02:13:23Z
**Event:** The file `tor.exe` was deleted from the Tor Browser installation directory.
**Action:** File deletion detected, possibly indicating an attempt to cover tracks or uninstall.
**File Path:**
`C:\Users\uyowfonkmiv\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

On June 20, 2025, user `uyowfonkmiv` downloaded and silently installed the Tor Browser on host `j-win10-threat-`. Shortly after installation, they launched the browser, triggering multiple firefox.exe and tor.exe processes.

The system established connections to known Tor relay IPs and localhost proxies, confirming active use of the Tor network. About 10 minutes later, the user created a file called `tor-shopping-list.txt`, along with browsing data artifacts, suggesting ongoing or planned activity within the Tor environment.

Later, the user deleted `tor-shopping-list.txt`, indicating an attempt to remove evidence of their actions. These activities point to intentional and privacy-aware Tor usage, potentially for suspicious purposes.

---

## Response Taken

TOR usage was confirmed on the endpoint `j-win10-threat-` by the user `uyowfonkmiv`. The device was isolated, and the user's direct manager was notified.

---
