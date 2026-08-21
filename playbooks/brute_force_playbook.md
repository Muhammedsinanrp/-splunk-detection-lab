# 📘 SOC Playbook: Brute Force & Password Spraying Triage (T1110)

---

## 1. Alert Trigger
- **Alert:** `Brute Force Password Spraying Detected`
- **Severity:** 🟡 Medium to 🟠 High
- **Threshold:** > 5 failed logins for single user OR > 3 distinct users from single Source IP within 5 minutes.

---

## 2. Investigation Procedure

### Step 1: Query Ingress & Target Vectors
```spl
index=wineventlog EventCode=4625 IpAddress="<SOURCE_IP>"
| stats count by Account_Name, Sub_Status, ComputerName
```

### Step 2: Determine Source Origin
- **External IP:** Verify Geo-IP and threat intelligence reputation (VirusTotal, AbuseIPDB).
- **Internal IP:** Identify if the machine is a compromised workstation or automated scanning tool.

---

## 3. Containment & Mitigation
1. **Firewall Ban:** Add `<SOURCE_IP>` to the perimeter blackhole / edge ACL.
2. **Account Lockout Check:** Verify if target accounts are locked out:
   ```powershell
   Search-ADAccount -LockedOut | Select-Object Name, SamAccountName, LastBadPasswordAttempt
   ```
3. **Notify User:** If targeted password spray was successful (Event 4624 occurred immediately after 4625), initiate immediate password reset and step-up MFA challenge.
