# 🚨 SOC Incident Report: Lateral Movement via Remote SMB Services

| Incident Metadata | Details |
|---|---|
| **Incident ID** | INC-20260821-001 |
| **Alert Name** | `Lateral Movement Detected` |
| **MITRE ATT&CK** | **T1021.002** (SMB/Windows Admin Shares), **T1078** (Valid Accounts) |
| **Severity** | 🔴 High |
| **Affected Account** | `CORP\john.doe` (Standard User) |
| **Compromised Host(s)** | `FILE-SRV-01` (192.168.1.50), `DC-01` (192.168.1.10) |
| **Attacker Source IP** | `192.168.1.100` (Kali Linux / Adversary VM) |
| **Incident Status** | 🟢 Contained & Eradicated |
| **Lead Analyst** | SOC Tier-2 Incident Responder |

---

## 1. Executive Summary

At **10:05:45 UTC**, the Splunk correlation engine triggered a high-severity alert for suspicious lateral movement. The alert was initiated when the account `john.doe` incurred authentication failures on `FILE-SRV-01` followed by rapid successful network logons (Event 4624 Logon Type 3) across multiple endpoints within 60 seconds from external IP `192.168.1.100`. Immediate host isolation and credential revocation prevented domain persistence.

---

## 2. Attack Timeline & Technical Reconstruction

| Timestamp (UTC) | Event ID / Source | Host / Target | Source IP | Description & Artifacts |
|---|---|---|---|---|
| **10:00:15** | Firewall / IDS | `FILE-SRV-01` | `192.168.1.100` | Port scan across TCP 135, 139, 445, 3389, 5985. |
| **10:05:12** | Event 4625 (Security) | `FILE-SRV-01` | `192.168.1.100` | Failed SMB logon attempt for `john.doe` (SubStatus `0xC000006A`). |
| **10:05:45** | Event 4624 (Security) | `FILE-SRV-01` | `192.168.1.100` | Successful SMB network logon for `john.doe` via NTLM auth. |
| **10:06:10** | Event 4624 (Security) | `DC-01` | `192.168.1.100` | Lateral jump: Successful authentication to Primary DC `DC-01`. |
| **10:06:22** | Event 4672 (Security) | `DC-01` | `192.168.1.100` | Special privileges assigned (`SeDebugPrivilege`). |
| **10:06:40** | Sysmon Event 1 | `DC-01` | — | Execution of encoded PowerShell cradle spawning from `cmd.exe`. |

---

## 3. Root Cause Analysis

The root cause was credential compromise of `john.doe` via an un-throttled SMB password spraying attack (`T1110.001`). Due to weak account lockout policies on SMB file shares, the attacker discovered the password `Summer2024!` and reused the credentials to authenticate laterally across Tier-1 servers and the Domain Controller.

---

## 4. Evidence & Splunk Queries Used

```spl
index=wineventlog (sourcetype="WinEventLog:Security" OR sourcetype="XmlWinEventLog:Security")
(EventCode=4625 OR EventCode=4624) Account_Name="john.doe"
| table _time, EventCode, ComputerName, IpAddress, Logon_Type, AuthenticationPackageName
| sort _time
```

---

## 5. Containment & Remediation Actions

1. **Identity Containment:** Disabled Active Directory account `john.doe` and revoked all active Kerberos TGT tickets (`klist purge`).
2. **Network Quarantine:** Isolated `FILE-SRV-01` and `DC-01` from the standard subnet via dynamic VLAN quarantine.
3. **Firewall Block:** Blocked attacker IP `192.168.1.100` at the internal network perimeter switch.
4. **Credential Rotation:** Reset the `krbtgt` password twice across the domain to invalidate potential Golden Tickets.

---

## 6. Lessons Learned & Detection Improvements

- Enforce **Kerberos Armoring (FAST)** and restrict NTLM authentication across the domain via Group Policy (`Network security: Restrict NTLM: Outgoing traffic to remote servers`).
- Implement the **Microsoft Tiered Administration Model** (Tier 0 / Tier 1 / Tier 2) so standard user credentials cannot authenticate to Domain Controllers.
- Deploy the newly created detection rule `pass_the_hash_detection.spl` to monitor NTLM Type 3 logons in real time.
