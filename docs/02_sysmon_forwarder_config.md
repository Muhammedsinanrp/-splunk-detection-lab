# 🖥️ Lab Guide 02: Windows Sysmon & Universal Forwarder Configuration

This guide details configuring high-fidelity endpoint monitoring on your Windows target VM.

---

## 1. Installing Microsoft Sysmon

1. Download Sysmon from Microsoft Sysinternals:
   - [Sysmon Download (Microsoft Learn)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
2. Download the battle-tested SwiftOnSecurity configuration:
   ```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile "sysmonconfig.xml"
   ```
3. Install Sysmon as a service:
   ```powershell
   .\Sysmon64.exe -accepteula -i sysmonconfig.xml
   ```
4. Verify Sysmon is capturing events:
   - Open **Event Viewer** > `Applications and Services Logs` > `Microsoft` > `Windows` > `Sysmon` > `Operational`.

---

## 2. Installing Splunk Universal Forwarder

1. Download the Universal Forwarder for Windows 64-bit from Splunk.
2. Run the MSI installer with administrator privileges:
   - Specify Splunk Indexer IP (e.g. `192.168.1.50`) and Ingestion Port `9997`.
3. Alternatively, copy the provided configuration files from `configs/`:
   - Copy `configs/inputs.conf` to `C:\Program Files\SplunkUniversalForwarder\etc\system\local\inputs.conf`
   - Copy `configs/outputs.conf` to `C:\Program Files\SplunkUniversalForwarder\etc\system\local\outputs.conf`
4. Restart the Universal Forwarder service:
   ```powershell
   Restart-Service SplunkForwarder
   ```

---

## 3. Verifying Log Shipping in Splunk

Run the following SPL query in the Splunk Search Head:
```spl
| metadata type=sourcetypes index=wineventlog OR index=sysmon
| table sourcetype, totalCount, lastTime
| eval lastTime=strftime(lastTime, "%Y-%m-%d %H:%M:%S")
```
You should see incoming events for `WinEventLog:Security` and `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.
