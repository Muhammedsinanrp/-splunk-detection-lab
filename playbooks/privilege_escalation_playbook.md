# 📘 SOC Playbook: Privilege Escalation & Admin Rights Abuse (T1078 / T1068)

---

## 1. Alert Identification
- **Alert:** `Privilege Escalation - Unauthorized Admin Privilege`
- **Severity:** 🔴 Critical
- **Trigger:** Event 4672 or Event 4732/4728 involving accounts whose `user_privilege_lookup.csv` level is `Standard`.

---

## 2. Step-by-Step Response Workflow

### Step 1: Validate Against Authorized Change Requests
Check if a change ticket (RFC) or PAM temporary checkout exists for this user:
- Search ITSM / Change Calendar.
- If verified legitimate: update ticket and close as expected change.
- If **unauthorized**: escalate immediately to Tier-2 / Tier-3 incident response.

### Step 2: Query Splunk for Rights Assignment & Group Changes
```spl
index=wineventlog (EventCode=4672 OR EventCode=4732 OR EventCode=4728) Account_Name="<TARGET_USER>"
| table _time, EventCode, ComputerName, PrivilegeList, MemberName, TargetUserName, SubjectUserName
```

### Step 3: Immediate Containment Actions
1. **Remove from Privileged Groups:**
   ```powershell
   Remove-ADGroupMember -Identity "Administrators" -Members "<TARGET_USER>" -Confirm:$false
   Remove-ADGroupMember -Identity "Domain Admins" -Members "<TARGET_USER>" -Confirm:$false
   ```
2. **Terminate Process Hierarchy:**
   ```powershell
   Get-Process -IncludeUserName | Where-Object { $_.UserName -like "*<TARGET_USER>*" } | Stop-Process -Force
   ```
3. **Reset User Account Passwords and Invalidate AD Tokens:**
   ```powershell
   Set-ADUser -Identity "<TARGET_USER>" -ChangePasswordAtLogon $true
   ```

---

## 3. Post-Incident Root Cause Analysis
- Determine the vector of elevation (e.g. token stealing, unquoted service path, RottenPotato/PrintNightmare exploit).
- Patch vulnerable service or deploy registry lockdown (e.g. `EnableLUA = 1`, UAC elevation prompts for admin accounts).
