# 📘 SOC Playbook: Lateral Movement Investigation & Response (T1021 / T1550)

```
                       ┌─────────────────────────┐
                       │   Alert: Lateral Move   │
                       └────────────┬────────────┘
                                    │
                                    ▼
                      [ Triage: Verify Source IP ]
                     /                            \
      [ Internal Host (Compromised) ]        [ External / VPN IP ]
                    │                                  │
                    ▼                                  ▼
      [ Check Destination Hosts (4624) ]       [ Enforce IP Block & MFA Revoke ]
                    │
                    ▼
      [ Isolate Affected Endpoints ]
                    │
                    ▼
      [ Kill Active Sessions & Reset PW ]
                    │
                    ▼
      [ Forensics: Check for Persistence ]
```

---

## 1. Alert Identification & Trigger Criteria
- **Alert Name:** `Lateral Movement Detected`
- **Criteria:** User account records Event 4625 followed by Event 4624 on a different machine within 10 minutes, or NTLM Type 3 logon without Kerberos baseline.

---

## 2. Phase 1: Rapid Triage (SLA: 15 minutes)

### Step 1: Identify Attacking & Target Assets
Run the following SPL query in Splunk Search & Reporting:
```spl
index=wineventlog (EventCode=4624 OR EventCode=4625) Account_Name="<COMPROMISED_USER>"
| table _time, EventCode, ComputerName, IpAddress, Logon_Type, AuthenticationPackageName
| sort _time
```

### Step 2: Determine Scope of Propagation
```spl
index=wineventlog EventCode=4624 Account_Name="<COMPROMISED_USER>" Logon_Type IN (3, 10)
| stats dc(ComputerName) as host_count, values(ComputerName) as host_list by IpAddress
```

---

## 3. Phase 2: Containment (SLA: 30 minutes)

1. **Disable User Account:**
   ```powershell
   Disable-ADAccount -Identity "<COMPROMISED_USER>"
   ```
2. **Revoke Kerberos & Active Sessions:**
   ```powershell
   # Purge active tickets on target hosts
   klist -li 0x3e7 purge
   ```
3. **Isolate Compromised Endpoints:**
   - Execute network quarantine via EDR (CrowdStrike / Defender for Endpoint / SentinelOne).
   - If no EDR, execute host firewall isolation:
     ```powershell
     netsh advfirewall set allprofiles state on
     netsh advfirewall firewall add rule name="SOC_Isolation_Block" dir=in action=block
     ```

---

## 4. Phase 3: Eradication & Remediation

1. Scan for scheduled tasks created within the last 2 hours:
   ```powershell
   Get-ScheduledTask | Where-Object { $_.Date -gt (Get-Date).AddHours(-2) }
   ```
2. Check for newly registered services (Event ID 7045 / Sysmon Event 1):
   ```spl
   index=wineventlog EventCode=7045 ComputerName IN (<HOST_LIST>)
   ```
3. Force password reset for all compromised accounts with a 16+ character complex passphrase.

---

## 5. Phase 4: Recovery & Closure
- Verify no secondary beaconing or failed logons for 24 hours.
- Document IoCs in ticketing system (Jira / ServiceNow).
- Close incident with root cause category: `Credential Compromise -> SMB Lateral Movement`.
