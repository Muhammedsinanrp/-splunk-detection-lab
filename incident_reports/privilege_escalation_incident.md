# 👑 SOC Incident Report: Unauthorized Privilege Escalation & Admin Group Tampering

| Incident Metadata | Details |
|---|---|
| **Incident ID** | INC-20260821-002 |
| **Alert Name** | `Privilege Escalation Detected` |
| **MITRE ATT&CK** | **T1078.002** (Domain Accounts), **T1098** (Account Manipulation), **T1068** |
| **Severity** | 🔴 Critical |
| **Target User** | `CORP\john.doe` (Standard Employee) |
| **Target Host** | `DC-01.corp.local` |
| **Incident Status** | 🟢 Contained & Eradicated |
| **Lead Analyst** | SOC Tier-3 Senior Threat Hunter |

---

## 1. Executive Summary

At **10:06:22 UTC**, Splunk alerted on a Critical security violation: Event ID **4672** (Special Privileges Assigned) was registered for user `john.doe`, an employee baseline-tagged as **Standard (Non-Admin)** in `user_privilege_lookup.csv`. Forty-three seconds later at **10:07:05 UTC**, an Event ID **4732** was recorded indicating `john.doe` had added themselves to the local `Administrators` security group on `DC-01`.

---

## 2. Attack Timeline

| Timestamp (UTC) | Event ID | Host | Details |
|---|---|---|---|
| **10:06:10** | 4624 (Logon) | `DC-01` | Successful logon for `john.doe` from `192.168.1.100`. |
| **10:06:22** | 4672 (Privilege Use) | `DC-01` | `SeDebugPrivilege`, `SeImpersonatePrivilege` assigned. |
| **10:06:40** | Sysmon 1 (Process) | `DC-01` | `powershell.exe` spawned with encoded token manipulation payload. |
| **10:06:55** | Sysmon 10 (ProcessAccess) | `DC-01` | `mimikatz.exe` accessed `lsass.exe` with GrantedAccess `0x1010`. |
| **10:07:05** | 4732 (Group Change) | `DC-01` | User `john.doe` added to group `BUILTIN\Administrators`. |

---

## 3. Threat Hunting & SPL Investigation

```spl
index=wineventlog (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Security") 
(EventCode=4672 OR EventCode=4732 OR EventCode=4728) ComputerName="DC-01*"
| lookup user_privilege_lookup Account_Name OUTPUT Department, Privilege_Level
| table _time, EventCode, Account_Name, MemberName, TargetUserName, PrivilegeList, Privilege_Level
```

---

## 4. Remediation & Hardening

1. **Group Membership Cleanup:** Removed `john.doe` from the `Administrators` and `Domain Admins` groups immediately.
2. **Token Revocation:** Purged all active sessions and forced ticket invalidation via PowerShell `Revoke-AzureADUserAllRefreshToken` and AD Kerberos ticket resets.
3. **Forensic Disk Capture:** Captured memory image (`DumpIt.exe`) and triage package (`KAPE`) on `DC-01` for deep rootkit inspection.
4. **Group Policy Audit:** Locked down Restricted Groups policy via GPO to enforce static members on all Domain Controller administrative groups.
