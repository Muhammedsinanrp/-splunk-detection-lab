# 💀 SOC Incident Report: LSASS Memory Credential Dumping (Mimikatz)

| Incident Metadata | Details |
|---|---|
| **Incident ID** | INC-20260821-003 |
| **Alert Name** | `Credential Dumping Detected (LSASS Access)` |
| **MITRE ATT&CK** | **T1003.001** (OS Credential Dumping: LSASS Memory) |
| **Severity** | 🔴 Critical |
| **Attacking Binary** | `C:\Users\Public\mimikatz.exe` (SHA256: `a93b4...`) |
| **Target Process** | `C:\Windows\System32\lsass.exe` (PID: 648) |
| **Granted Access Mask** | `0x1010` (`PROCESS_QUERY_LIMITED_INFORMATION` \| `PROCESS_VM_READ`) |
| **Target Host** | `DC-01.corp.local` |
| **Incident Status** | 🟢 Contained & Eradicated |

---

## 1. Executive Summary

At **10:06:55 UTC**, Sysmon Event ID **10** (Process Access) captured an unauthorized executable located in `C:\Users\Public\mimikatz.exe` opening a handle to `lsass.exe` with memory-read rights (`0x1010`). The adversary executed `sekurlsa::logonpasswords` in an attempt to dump plaintext passwords and Kerberos tickets from memory. Endpoint telemetry correlation detected the malicious handle within 4 seconds of execution.

---

## 2. Technical Evidence & Telemetry

### Sysmon Event 10 Extract:
```json
{
  "EventCode": "10",
  "EventDescription": "Process accessed",
  "SourceImage": "C:\\Users\\Public\\mimikatz.exe",
  "TargetImage": "C:\\Windows\\System32\\lsass.exe",
  "GrantedAccess": "0x1010",
  "CallTrace": "C:\\Windows\\SYSTEM32\\ntdll.dll+9fb54|C:\\Windows\\System32\\KERNELBASE.dll+25a40|C:\\Users\\Public\\mimikatz.exe+32d1",
  "SourceUser": "CORP\\john.doe",
  "Computer": "DC-01.corp.local"
}
```

### Forensic Analysis:
- The binary was dropped via an encoded PowerShell download cradle into `C:\Users\Public\`.
- The attacker invoked `privilege::debug` followed by `sekurlsa::logonpasswords`.
- Memory inspection confirmed LSASS handle access was granted due to elevated debug rights.

---

## 3. Splunk Threat Hunting Query

```spl
index=sysmon (sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" OR sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational")
EventCode=10 TargetImage="*\\lsass.exe"
| eval Access_Mask = GrantedAccess
| table _time, Computer, SourceImage, TargetImage, Access_Mask, SourceUser, CallTrace
```

---

## 4. Remediation & Hardening Actions

1. **Process Termination:** Terminated `mimikatz.exe` process tree and deleted malicious staging files in `C:\Users\Public\`.
2. **Enable LSA Protection (RunAsPPL):**
   - Configured registry key `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1` via GPO to prevent non-protected processes from reading LSASS memory.
3. **Enable Credential Guard:**
   - Enabled Windows Defender Credential Guard using Virtualization-based Security (VBS) to isolate NTLM/Kerberos secrets into an isolated virtual container.
4. **Disable WDigest Cleartext Caching:**
   - Enforced `HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0`.
