# 🛡️ SIEM Detection Lab — Splunk Enterprise

**A Hands-on Security Operations Center (SOC) Lab for Detection Engineering & Threat Monitoring**

![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-blue)
![GitHub](https://img.shields.io/badge/GitHub-Follow-black)

---

## 📌 Project Overview

This project demonstrates my ability to design, deploy, and operate a Security Information and Event Management (SIEM) environment using **Splunk Enterprise**. The lab simulates a real-world SOC environment where I:

- Ingested Windows Security Event Logs and Sysmon telemetry
- Developed custom Splunk correlation rules to detect **lateral movement** and **privilege escalation**
- Created real-time alerts and a security monitoring dashboard
- Simulated attacks using Kali Linux to validate detection rules

**The goal** was to bridge the gap between offensive knowledge (CEH, CPT) and defensive detection engineering — turning attacker TTPs into actionable Splunk alerts.

---

## 🏗️ Lab Architecture

| Component | Role | IP Address |
|---|---|---|
| **Splunk Enterprise** | SIEM / Indexer / Search Head | `192.168.x.x` (Ubuntu/Windows Host) |
| **Windows Target** | Log Source (Security Events + Sysmon) | `192.168.x.x` |
| **Kali Linux** | Attacker Machine (Simulation) | `192.168.x.x` |
| **Sysmon** | High-fidelity endpoint telemetry | Installed on Windows Target |
| **Splunk Universal Forwarder** | Log shipping to Splunk Indexer | Installed on Windows Target |

### Network Diagram (Conceptual)

```
┌─────────────────────────────────────────────────────────────┐
│                    VirtualBox / VMware                       │
│                                                               │
│  ┌──────────────┐     ┌──────────────────────────────┐       │
│  │  Kali Linux  │────▶│    Windows Target (Win10/11)  │       │
│  │  (Attacker)  │     │  • Security Event Logs        │       │
│  │              │     │  • Sysmon (SwiftOnSecurity)   │       │
│  └──────────────┘     │  • Splunk Universal Forwarder │       │
│         │              └──────────────┬───────────────┘       │
│         │                             │                       │
│         │                     ┌───────▼───────────────┐       │
│         │                     │   Splunk Enterprise    │       │
│         └────────────────────▶│   (Indexer + Search)   │       │
│                                │   Port 9997 (Ingest)   │       │
│                                │   Port 8000 (Web UI)   │       │
│                                └────────────────────────┘       │
└─────────────────────────────────────────────────────────────┘
```

---

## 🛠️ Tools & Technologies

| Category | Tools |
|---|---|
| **SIEM** | Splunk Enterprise (Free 60-day Trial) |
| **Virtualization** | VirtualBox / VMware |
| **Endpoint Logging** | Sysmon (SwiftOnSecurity config) |
| **Log Forwarding** | Splunk Universal Forwarder |
| **Attack Simulation** | Kali Linux (Nmap, Hydra, Mimikatz, Metasploit) |
| **Detection Queries** | SPL (Search Processing Language) |
| **Frameworks** | MITRE ATT&CK, Cyber Kill Chain |

---

## 🔍 Detection Rules Implemented

### 1. 🚨 Lateral Movement Detection
**Objective:** Detect attackers moving laterally across the domain using compromised credentials.
**MITRE Mapping:** `T1021` — Remote Services
**Logic:** Correlates a failed login (Event 4625) followed by a successful login (Event 4624) on a **different** machine within a short time window.
See [`detection_rules/lateral_movement_detection.spl`](detection_rules/lateral_movement_detection.spl)

**Alert Configuration:**
- **Name:** `Lateral Movement Detected`
- **Severity:** High
- **Action:** Send email alert + Create notable event
- **Suppression:** 1 hour (per user)

---

### 2. 👑 Privilege Escalation Detection
**Objective:** Detect when a user is assigned special privileges (potential admin access abuse).
**MITRE Mapping:** `T1078` — Valid Accounts
**Logic:** Alert when Event ID 4672 (Special Privileges Assigned) occurs immediately after a logon from a **non-standard** or **sensitive** account.
See [`detection_rules/privilege_escalation_detection.spl`](detection_rules/privilege_escalation_detection.spl)

**Alert Configuration:**
- **Name:** `Privilege Escalation Detected`
- **Severity:** Critical
- **Action:** Send email alert + Create notable event
- **Suppression:** 30 minutes (per user)

---

### 3. 🔓 Brute Force Attack Detection
**Objective:** Detect password spraying or brute-force attacks against domain accounts.
**MITRE Mapping:** `T1110` — Brute Force
See [`detection_rules/brute_force_detection.spl`](detection_rules/brute_force_detection.spl)

**Alert Configuration:**
- **Name:** `Brute Force Attempt Detected`
- **Severity:** Medium
- **Action:** Send email alert
- **Suppression:** 15 minutes (per source IP)

---

### 4. 💀 Credential Dumping (Mimikatz) Detection
**Objective:** Detect attackers using Mimikatz to dump credentials from memory.
**MITRE Mapping:** `T1003` — Credential Dumping
**Logic:** Alert on suspicious process access to LSASS (Sysmon Event 10).
See [`detection_rules/credential_dumping_detection.spl`](detection_rules/credential_dumping_detection.spl)

**Alert Configuration:**
- **Name:** `Potential Credential Dumping Detected`
- **Severity:** Critical
- **Action:** Send email alert + Create notable event

---

### 5. 🔌 Suspicious Outbound Traffic (C2 Beaconing)
**Objective:** Detect potential Command & Control (C2) beaconing from compromised hosts.
**MITRE Mapping:** `T1071` — Application Layer Protocol
See [`detection_rules/c2_beaconing_detection.spl`](detection_rules/c2_beaconing_detection.spl)

---

## 📊 Security Monitoring Dashboard

I built a custom **"Security Monitoring"** dashboard in Splunk providing real-time visibility into:

| Dashboard Panel | Purpose |
|---|---|
| **Failed Logins Over Time** | Track brute-force patterns |
| **Top Attack Sources** | Identify repeat offender IPs |
| **Lateral Movement Alerts** | View correlation rule hits |
| **Privilege Escalation Alerts** | View privilege abuse attempts |
| **Outbound Connections (Top 10)** | Spot suspicious egress traffic |
| **Event Code Distribution** | Overview of security events |

Dashboard export: [`dashboards/security_monitoring_dashboard.xml`](dashboards/security_monitoring_dashboard.xml)

---

## ⚔️ Attack Simulation

To validate my detection rules, I simulated real-world attacks against the Windows target:

| Attack | Tool | Generated Events | Detection |
|---|---|---|---|
| Network Reconnaissance | Nmap | Firewall Logs, Port Scan | Port Scan Alert |
| SMB Brute Force | Hydra | 4625 (Failed Login) | Brute Force Alert |
| RDP Brute Force | Hydra | 4625, 4740 | Brute Force Alert |
| Password Hash Dumping | Mimikatz | 4624, 4672 | Credential Dumping Alert |
| Remote Code Execution | Metasploit PSExec | 4624, 4672, 4688 | Lateral Movement Alert |
| Pass-the-Hash | Mimikatz | 4624 (NTLM) | Lateral Movement Alert |

---

## 🔎 Sample Investigation: Lateral Movement

**Alert Triggered:** `Lateral Movement Detected` for user `john.doe`

**Investigation Steps:**
1. **Check Source IP:** `192.168.1.100` (Kali Linux)
2. **Review Timeline:**
   - `10:05:12` — Failed login (4625) from `192.168.1.100` to `FILE-SRV-01`
   - `10:05:45` — Successful login (4624) from `192.168.1.100` to `FILE-SRV-01`
   - `10:06:10` — Successful login (4624) from `192.168.1.100` to `DC-01`
3. **Check Post-Compromise Activity:**
   - Event 4672 (Special Privileges) triggered on `DC-01`
   - Suspicious process (PowerShell) executed on `DC-01`
4. **Response Actions:**
   - Force password reset for `john.doe`
   - Block source IP `192.168.1.100`
   - Isolate `DC-01` for forensic review

Full write-up: [`incident_reports/lateral_movement_incident.md`](incident_reports/lateral_movement_incident.md)

---

## 📁 Repository Structure

```
splunk-detection-lab/
│
├── README.md                              # This file
├── detection_rules/
│   ├── lateral_movement_detection.spl
│   ├── privilege_escalation_detection.spl
│   ├── brute_force_detection.spl
│   ├── credential_dumping_detection.spl
│   └── c2_beaconing_detection.spl
│
├── dashboards/
│   └── security_monitoring_dashboard.xml
│
├── attack_simulations/
│   ├── hydra_brute_force_logs.txt
│   ├── nmap_scan_logs.txt
│   └── mimikatz_logs.txt
│
├── incident_reports/
│   ├── lateral_movement_incident.md
│   └── privilege_escalation_incident.md
│
└── configs/
    ├── inputs.conf
    └── outputs.conf
```

---

## 🧠 Skills Demonstrated

- **SIEM Deployment:** Installed and configured Splunk Enterprise
- **Log Ingestion:** Set up Splunk Universal Forwarder to stream Windows Event Logs and Sysmon
- **Detection Engineering:** Wrote custom SPL queries for threat detection
- **Alert Configuration:** Created real-time alerts with severity and suppression
- **Dashboarding:** Built a security monitoring dashboard
- **Attack Simulation:** Used Kali Linux to simulate real-world attacks
- **Incident Response:** Documented findings and response actions
- **MITRE ATT&CK Mapping:** Mapped detections to adversary TTPs

---

## 📚 References & Resources

- [Splunk Enterprise Documentation](https://docs.splunk.com/)
- [Sysmon — SwiftOnSecurity Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Splunk Security Content](https://github.com/splunk/security_content)
- [Lab-WriteUps — SIEM Use Case Development](https://github.com/Sweatzer/Lab-WriteUps)
