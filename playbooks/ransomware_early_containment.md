# 🚨 SOC Emergency Playbook: Ransomware Early Containment & Isolation

---

## 1. Trigger Conditions
- Mass file modification (Sysmon Event 11: FileCreate with `.locked`, `.enc` or rapid creation of ransom notes `README_RESTORE.txt`).
- Shadow copy deletion attempts (`vssadmin delete shadows /all /quiet` or `wmic shadowcopy delete`).
- Rapid cross-share SMB writes from single endpoint.

---

## 2. Emergency Isolation Steps (Immediate Execution)

### Step 1: Endpoint Network Quarantine
```powershell
# Instantly drop all network traffic except management subnet
netsh advfirewall set allprofiles state on
netsh advfirewall firewall add rule name="EMERGENCY_ISOLATION" dir=in action=block
netsh advfirewall firewall add rule name="EMERGENCY_ISOLATION_OUT" dir=out action=block
```

### Step 2: Disable SMB File Sharing
```powershell
# Stop Server service to prevent lateral encryption of shared storage
Stop-Service -Name LanmanServer -Force
Set-Service -Name LanmanServer -StartupType Disabled
```

### Step 3: Terminate Suspicious Process Trees
```powershell
# Hunt for active vssadmin / bcdedit / wmic processes
Get-Process | Where-Object { $_.ProcessName -match "vssadmin|bcdedit|powershell|wscript|cscript" } | Stop-Process -Force
```

---

## 3. Splunk Threat Hunting Query
```spl
(index=sysmon EventCode=1 (CommandLine="*vssadmin*delete*" OR CommandLine="*wmic*shadowcopy*delete*" OR CommandLine="*bcdedit*recoveryenabled*no*"))
OR
(index=sysmon EventCode=11 (TargetFilename="*README*.txt" OR TargetFilename="*.locked"))
| table _time, Computer, Image, CommandLine, TargetFilename, User
```
