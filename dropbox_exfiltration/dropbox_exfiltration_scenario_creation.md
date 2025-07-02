# Threat Event (Dropbox Data Exfiltration)

**Large Sensitive File Uploaded to Unauthorized Cloud Storage (Dropbox)**

---
## Pre-steps: 

1. **Created a fake corporate user** (John Doe) to simulate insider behavior

   * Username: `j.doe` (standard user)
   * Did not switch users due to VM limitations; actions taken under `jnguyen.admin`

2. **Created sensitive files to simulate high-value data:**

   * `Employee_Record_Dump.csv`
   * `Quarterly_Financial_Projections_Q3.docx`
   * `Client_Credentials_Access.xlsx`
   * Files stored in `Documents\Confidential`
   * Metadata timestamps backdated using PowerShell

3. **Registered a personal email and Dropbox account:**

   * Email: `johndoe197541@proton.me`
   * Dropbox account created with same address

## Steps the "Bad Actor" Took to Create Logs and IoCs:

4. **Downloaded and installed Dropbox silently:**

   ```powershell
   Start-Process -FilePath "C:\Users\jnguyen.admin\Downloads\DropboxInstaller.exe" -ArgumentList "/S" -Wait
   ```

5. **Logged into the Dropbox desktop app using John Doe’s personal account**

6. **Uploaded sensitive files:**

   * Dragged into Dropbox sync folder
   * Manually uploaded via browser at `https://dropbox.com`

7. **Attempted cleanup:**

   * Cleared browser file upload history
   * Removed files from recent files list
   * Ran PowerShell script to silently uninstall Dropbox and delete associated files and folders

---

## Tables Used to Detect IoCs:

| **Parameter** | **Description**                                                                                                                                                                  |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceFileEvents                                                                                                                                                                 |
| **Info**      | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table) |
| **Purpose**   | Detect Dropbox installer, file movement to sync folders, and deletion of local traces.                                                                                           |

| **Parameter** | **Description**                                                                                                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceProcessEvents                                                                                                                                                                    |
| **Info**      | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) |
| **Purpose**   | Detect Dropbox app installation or execution of desktop client.                                                                                                                        |

| **Parameter** | **Description**                                                                                                                                                                        |
| ------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Name**      | DeviceNetworkEvents                                                                                                                                                                    |
| **Info**      | [https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table) |
| **Purpose**   | Monitor network traffic to Dropbox domains during data upload.                                                                                                                         |

---

## Related Queries:

```kql
// Detect Dropbox installer download
DeviceFileEvents
| where DeviceName == "fin-w10-wks-8"
| where FileName has "DropboxInstaller"
| order by Timestamp desc 

// Detect Dropbox being installed silently
DeviceProcessEvents
| where DeviceName == "fin-w10-wks-8"
| where ProcessCommandLine has "DropboxInstaller"
| where ProcessCommandLine has "/S"
| order by Timestamp desc 

// Detect Dropbox app launch
DeviceProcessEvents
| where DeviceName == "fin-w10-wks-8"
| where FileName =~ "dropbox.exe"
| order by Timestamp desc 

// Detect sensitive files moved to Dropbox folder (user sync path)
DeviceFileEvents
| where DeviceName == "fin-w10-wks-8"
| where FolderPath has "Dropbox"
| order by Timestamp desc 

// Detect upload to Dropbox via browser or app
DeviceNetworkEvents
| where DeviceName == "fin-w10-wks-8"
| where RemoteUrl has_any ("dropbox.com", "dl.dropboxusercontent.com", "api.dropboxapi.com")
| where InitiatingProcessFileName in~ ("dropbox.exe", "chrome.exe", "firefox.exe", "msedge.exe")
| order by Timestamp desc 

// Detect cleanup activity: deletion of Dropbox folders
DeviceFileEvents
| where DeviceName == "fin-w10-wks-8"
| where FolderPath has "Dropbox"
| where ActionType == "FileDeleted"
| order by Timestamp desc 
```

---

## Created By:

* **Author Name**: Jason Nguyen
* **Author Contact**: [https://github.com/jason-p-nguyen](https://github.com/jason-p-nguyen)
* **Date**: July 2, 2025

---

## Additional Notes:

* Dropbox is not inherently malicious but is often **unauthorized in corporate environments** due to data loss risks.
* This scenario highlights **insider threat behavior**, **shadow IT usage**, and **exfiltration via trusted services**.
* Consider pairing this hunt with:

  * Proxy logs
  * CASB (Cloud Access Security Broker) alerts
  * DLP (Data Loss Prevention) detections

---

## Revision History:

| **Version** | **Changes**   | **Date**     | **Modified By** |
| ----------- | ------------- | ------------ | --------------- |
| 1.0         | Initial draft | July 1, 2025 | Jason Nguyen    |
