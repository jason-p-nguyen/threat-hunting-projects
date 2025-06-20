# Threat Event (Unauthorized TOR Usage)
**Unauthorized TOR Browser Installation and Use**

## Steps the "Bad Actor" took Create Logs and IoCs:
1. Download the TOR browser installer: https://www.torproject.org/download/
2. Install it silently: ```tor-browser-windows-x86_64-portable-14.5.3.exe /S```
3. Opens the TOR browser from the folder on the desktop
4. Connect to TOR and browse a few sites.
   - Current Dread Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion```
   - Dark Markets Forum: ```dreadytofatroptsdj6io7l3xptbet6onoyno2yv7jicoxknyazubrad.onion/d/DarkNetMarkets```
   - Current Elysium Market: ```https://elysiumutkwscnmdohj23gkcyp3ebrf4iio3sngc5tvcgyfp4nqqmwad.top/login```
   - ** It's possible the onion link for Dread Forum has changed, for latest links, you can try to check here: https://dread-forum.com/ **
6. Create a file on your desktop called ```tor-shopping-list.txt``` and put a few fake (illicit) items in there
7. Delete the file.
8. Delete TOR browser folder.

---

## Tables Used to Detect IoCs:
| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceFileEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used for detecting TOR download and installation, as well as the shopping list creation and deletion. |

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceProcessEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceinfo-table|
| **Purpose**| Used to detect the silent installation of TOR as well as the TOR browser and service launching.|

| **Parameter**       | **Description**                                                              |
|---------------------|------------------------------------------------------------------------------|
| **Name**| DeviceNetworkEvents|
| **Info**|https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table|
| **Purpose**| Used to detect TOR network activity, specifically tor.exe and firefox.exe making connections over ports to be used by TOR (9001, 9030, 9040, 9050, 9051, 9150).|

---

## Related Queries:
```kql
//check for devicenames
DeviceInfo
| distinct DeviceName

//check for my vm
DeviceInfo
| where DeviceName == "j-win10-threat-"

//check for logs that show tor was installed
DeviceFileEvents
| where DeviceName == "j-win10-threat-"
| where FileName startswith "tor"

// check to see if tor browser was installed silently
// note: two spaces before the /S 
DeviceProcessEvents
| where DeviceName == "j-win10-threat-"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe  /S"
| project Timestamp, DeviceName, ActionType, FileName, ProcessCommandLine

// check if tor was successfully installed on the disk
DeviceFileEvents
| where DeviceName == "j-win10-threat-"
| where FileName has_any ("tor.exe", "firefox.exe")
| project  Timestamp, DeviceName, RequestAccountName, ActionType, InitiatingProcessCommandLine

// see if tor browser or service was launched
DeviceProcessEvents
| where DeviceName == "j-win10-threat-"
| where ProcessCommandLine has_any("tor.exe","firefox.exe")
| project  Timestamp, DeviceName, AccountName, ActionType, ProcessCommandLine

// was the tor browser used and created network connections? 
DeviceNetworkEvents
| where DeviceName == "j-win10-threat-"
| where InitiatingProcessFileName in~ ("tor.exe", "firefox.exe")
| where RemotePort in (9001, 9030, 9040, 9050, 9051, 9150)
| project Timestamp, DeviceName, InitiatingProcessAccountName, InitiatingProcessFileName, RemoteIP, RemotePort, RemoteUrl
| order by Timestamp desc

// was shopping list created and, changed, or deleted?
DeviceFileEvents
| where DeviceName == "j-win10-threat-"
| where FileName contains "shopping-list.txt"
```

---

## Created By:
- **Author Name**: Josh Madakor
- **Author Contact**: https://www.linkedin.com/in/joshmadakor/
- **Date**: August 31, 2024

## Validated By:
- **Reviewer Name**: Jason Nguyen
- **Reviewer Contact**: https://github.com/jason-p-nguyen
- **Validation Date**: 20 June 2025

---

## Additional Notes:
- **updated Dread Forum Onion URL**
- **updated cmd line: ```tor-browser-windows-x86_64-portable-14.5.3.exe /S```**
- **added steps to delete TOR browser folder

---

## Revision History:
| **Version** | **Changes**                   | **Date**         | **Modified By**   |
|-------------|-------------------------------|------------------|-------------------|
| 1.0         | Initial draft                  | `September  6, 2024`  | `Josh Madakor` 
| 1.1         | Revised version 1.1                  | `June 20, 2025`  | `Jason Nguyen` 
