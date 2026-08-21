# 🛡️ SIEM Threat Detection & Incident Response Lab — Splunk Enterprise

[![Splunk Enterprise](https://img.shields.io/badge/SIEM-Splunk_Enterprise_9.2-black?style=for-the-badge&logo=splunk&logoColor=white)](https://www.splunk.com/)
[![MITRE ATT&CK](https://img.shields.io/badge/Framework-MITRE_ATT%26CK_v14-red?style=for-the-badge)](https://attack.mitre.org/)
[![Endpoint Telemetry](https://img.shields.io/badge/Endpoint-Sysmon_%2B_WinEventLog-blue?style=for-the-badge&logo=windows&logoColor=white)](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
[![Offensive Emulation](https://img.shields.io/badge/Offensive-Kali_Linux-557C94?style=for-the-badge&logo=kalilinux&logoColor=white)](https://www.kali.org/)
[![Docker Compose](https://img.shields.io/badge/Deployment-Docker_Compose-2496ED?style=for-the-badge&logo=docker&logoColor=white)](docker-compose.yml)

> **A production-grade Security Operations Center (SOC) Detection Engineering & Threat Monitoring Lab simulating real-world adversary TTPs, correlating Windows Security & Sysmon telemetry, and executing end-to-end incident response.**

---

## 📌 Project Overview

This project showcases the design, deployment, and operational execution of an enterprise **Security Information and Event Management (SIEM)** detection pipeline using **Splunk Enterprise**. 

Bridging offensive tradecraft with defensive detection engineering, this lab demonstrates:
1. **High-Fidelity Endpoint Telemetry Ingestion:** Windows Security Event Logs (4624, 4625, 4672, 4688, 4732) and Microsoft Sysmon (Events 1, 3, 10, 11) via Splunk Universal Forwarder.
2. **Detection Engineering & Threat Hunting:** Custom Search Processing Language (SPL) correlation searches with automated alert suppression, threshold calibration, and MITRE ATT&CK mapping.
3. **Real-Time SOC Dashboarding:** 6-panel real-time operational dashboard with KPI single-value status cards and MITRE coverage matrices.
4. **Adversary Emulation:** Controlled simulations of password spraying, lateral movement, LSASS memory dumping (Mimikatz), and C2 beaconing.
5. **NIST-Standard Incident Response:** Complete incident triage reports, forensic root-cause analysis, and actionable SOC analyst playbooks.

---

## 🏗️ Lab Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────────────┐
│                                 SOC Detection Lab Environment                           │
│                                                                                         │
│   ┌───────────────────────────┐                       ┌──────────────────────────────┐  │
│   │    Kali Linux Attacker    │                       │    Windows Target Server     │  │
│   │       192.168.1.100       │                       │        192.168.1.50          │  │
│   │  • Nmap Reconnaissance    │─────── Attack ───────▶│  • Windows Security Logs     │  │
│   │  • Hydra Password Spray   │      Simulation       │  • Sysmon (SwiftOnSecurity)  │  │
│   │  • CrackMapExec / SMB     │                       │  • Splunk Universal Fwd      │  │
│   │  • Mimikatz / Metasploit  │                       └──────────────┬───────────────┘  │
│   └───────────────────────────┘                                      │                  │
│                                                                      │ Ingest (Port 9997)
│                                                                      ▼                  │
│                                                       ┌──────────────────────────────┐  │
│                                                       │   Splunk Enterprise (SIEM)   │  │
│                                                       │        192.168.1.10          │  │
│                                                       │  • Indexes: winevent, sysmon │  │
│                                                       │  • SPL Correlation Searches  │  │
│                                                       │  • Real-Time Alert Engine    │  │
│                                                       │  • SOC Security Dashboard    │  │
│                                                       │    (Web Console Port 8000)   │  │
│                                                       └──────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔍 Detection Engineering Rules Matrix

All correlation searches are written in Splunk SPL, mapped to MITRE ATT&CK techniques, and configured with scheduled execution and alert suppression in [`configs/savedsearches.conf`](configs/savedsearches.conf).

| Detection Rule | MITRE ATT&CK | Log Source | Severity | Description & File |
|---|---|---|---|---|
| **Lateral Movement** | `T1021.002` Remote Services | `WinEventLog:Security` | 🔴 High | Correlates failed logon (4625) followed by multi-host success (4624) within 10m. [`lateral_movement_detection.spl`](detection_rules/lateral_movement_detection.spl) |
| **Privilege Escalation** | `T1078` Valid Accounts | `WinEventLog:Security` | 🔴 Critical | Flags Event 4672 (Special Privileges) for non-administrative accounts via lookup. [`privilege_escalation_detection.spl`](detection_rules/privilege_escalation_detection.spl) |
| **Brute Force / Password Spray** | `T1110.001` Brute Force | `WinEventLog:Security` | 🟡 Medium | Identifies velocity spikes (≥5 failed logons or ≥3 unique accounts per IP). [`brute_force_detection.spl`](detection_rules/brute_force_detection.spl) |
| **Credential Dumping** | `T1003.001` LSASS Memory | `Sysmon:Operational` | 🔴 Critical | Detects unapproved processes requesting handle access `0x1010` to `lsass.exe`. [`credential_dumping_detection.spl`](detection_rules/credential_dumping_detection.spl) |
| **C2 Network Beaconing** | `T1071.001` Web Protocols | `Sysmon:Operational` | 🟠 High | Discovers periodic outbound connections to external public IPs with low jitter. [`c2_beaconing_detection.spl`](detection_rules/c2_beaconing_detection.spl) |
| **Pass-the-Hash (PtH)** | `T1550.002` Pass the Hash | `WinEventLog:Security` | 🟠 High | Identifies NTLM Type 3 network authentications bypassing Kerberos armoring. [`pass_the_hash_detection.spl`](detection_rules/pass_the_hash_detection.spl) |
| **Scheduled Task Persistence** | `T1053.005` Scheduled Task | `Sysmon` / `Security` | 🟠 High | Detects task creation via `schtasks.exe /create` or Event 4698. [`persistence_scheduled_task.spl`](detection_rules/persistence_scheduled_task.spl) |
| **Obfuscated PowerShell** | `T1059.001` PowerShell | `Sysmon` / `PowerShell` | 🟠 High | Flags Base64 `-enc`, dynamic `IEX`, and remote `DownloadString` cradles. [`powershell_obfuscation_detection.spl`](detection_rules/powershell_obfuscation_detection.spl) |

---

## 📊 Security Dashboards

### 1. Splunk Simple XML Dashboard
The complete XML dashboard export is available in [`dashboards/security_monitoring_dashboard.xml`](dashboards/security_monitoring_dashboard.xml) and includes:
- **KPI Cards:** Ingested Security Events, Failed Logons, Active Alerts, Monitored Forwarders.
- **Failed Logons Over Time:** Velocity area chart tracking brute-force bursts.
- **Top Attack Sources:** Offender IP table with target account breakdown.
- **Notable Alert Queues:** Real-time correlation tables for lateral movement and privilege escalation.
- **Outbound C2 Connections:** Top external destinations by process.
- **Event Distribution:** Breakdown of Windows Event Codes.

### 2. Interactive Web-Based SOC Console Showcase
This repository includes a standalone web-based SOC SIEM Simulator located in [`web_showcase/`](web_showcase/):
- **Live Adversary Emulation:** Trigger simulated brute-force, lateral movement, Mimikatz, and full kill chain scenarios in real time.
- **Interactive SPL Search Bar:** Test and evaluate search queries directly in the browser against sample telemetry.
- **Incident Investigation Modals:** Inspect raw JSON logs, timeline reconstructions, and playbook response actions.

To launch the web showcase, simply open [`web_showcase/index.html`](web_showcase/index.html) in any modern browser.

---

## ⚔️ Adversary Emulation & Telemetry Datasets

To validate detection queries without standing up a physical lab, ingestible telemetry and simulation scripts are provided:

- **Automated Kali Attack Suite:** [`attack_simulations/run_simulations.sh`](attack_simulations/run_simulations.sh)
- **Windows Endpoint Telemetry Generator:** [`attack_simulations/simulate_attacks_windows.ps1`](attack_simulations/simulate_attacks_windows.ps1)
- **Ingestible Sample Logs:**
  - [`wineventlog_security_sample.json`](attack_simulations/sample_telemetry/wineventlog_security_sample.json) (Events 4624, 4625, 4672, 4732)
  - [`sysmon_operational_sample.json`](attack_simulations/sample_telemetry/sysmon_operational_sample.json) (Sysmon Events 1, 3, 10, 11)
- **Captured Attack Logs:**
  - [`hydra_brute_force_logs.txt`](attack_simulations/hydra_brute_force_logs.txt)
  - [`mimikatz_logs.txt`](attack_simulations/mimikatz_logs.txt)
  - [`nmap_scan_logs.txt`](attack_simulations/nmap_scan_logs.txt)

---

## 📁 Repository Structure

```
splunk-detection-lab/
├── README.md                                # Master documentation & architecture guide
├── docker-compose.yml                       # Splunk Enterprise 1-command container setup
│
├── configs/                                 # Production Splunk Configuration Stanzas
│   ├── inputs.conf                          # Windows Event Log, Sysmon & PowerShell inputs
│   ├── outputs.conf                         # Forwarder tcpout target configuration
│   ├── indexes.conf                         # Custom wineventlog and sysmon index definitions
│   ├── props.conf                           # CIM-compliant field aliases and sourcetype parsing
│   ├── transforms.conf                      # Lookup definitions (user privilege baseline)
│   ├── savedsearches.conf                   # Automated correlation alert definitions & schedules
│   └── lookups/
│       └── user_privilege_lookup.csv        # Baseline user privilege mapping table
│
├── detection_rules/                         # Production SPL Detection Rules
│   ├── lateral_movement_detection.spl       # T1021.002 - SMB/RDP Cross-Host Credential Reuse
│   ├── privilege_escalation_detection.spl   # T1078 / T1068 - Unauthorized Admin Elevation
│   ├── brute_force_detection.spl            # T1110.001 - Password Spray / Brute Force Thresholds
│   ├── credential_dumping_detection.spl     # T1003.001 - LSASS Memory Access (Sysmon Event 10)
│   ├── c2_beaconing_detection.spl           # T1071.001 - Network Beaconing & Egress Anomaly
│   ├── pass_the_hash_detection.spl          # T1550.002 - NTLM Logon Type 3 Anomaly
│   ├── persistence_scheduled_task.spl       # T1053.005 - Suspicious Schtasks Creation
│   └── powershell_obfuscation_detection.spl # T1059.001 - Encoded PowerShell & Remote Downloads
│
├── dashboards/                              # Splunk Simple XML Dashboards
│   ├── security_monitoring_dashboard.xml    # 6-panel real-time SOC monitoring dashboard
│   └── mitre_attack_matrix_dashboard.xml    # MITRE ATT&CK coverage and alert status matrix
│
├── attack_simulations/                      # Adversary Emulation Scripts & Datasets
│   ├── run_simulations.sh                   # Automated Kali attack execution runner
│   ├── simulate_attacks_windows.ps1         # Windows target attack telemetry generator
│   ├── hydra_brute_force_logs.txt           # Captured Hydra SMB/RDP logs
│   ├── mimikatz_logs.txt                    # Captured Mimikatz sekurlsa output
│   ├── nmap_scan_logs.txt                   # Captured Nmap reconnaissance logs
│   └── sample_telemetry/                    # Raw JSON event logs for instant lab validation
│       ├── wineventlog_security_sample.json
│       └── sysmon_operational_sample.json
│
├── incident_reports/                        # Real-World SOC Incident Reports (NIST SP 800-61r2)
│   ├── lateral_movement_incident.md         # Full IR report: T1021 SMB Lateral Movement
│   ├── privilege_escalation_incident.md     # Full IR report: T1078 Token Elevation & Admin Group
│   └── credential_dumping_incident.md       # Full IR report: T1003 Mimikatz LSASS Dump
│
├── playbooks/                               # SOC Analyst Standard Operating Procedures (SOP)
│   ├── lateral_movement_playbook.md         # Triage, Containment & Eradication Playbook
│   ├── privilege_escalation_playbook.md     # Triage & Privilege Revocation Playbook
│   ├── brute_force_playbook.md              # IP Blacklisting & Credential Lockout Playbook
│   └── ransomware_early_containment.md      # Emergency Endpoint Isolation Procedure
│
├── docs/                                    # Step-by-Step Lab Setup Guides
│   ├── 01_splunk_setup.md                   # Installing Splunk via Docker / Ubuntu / Windows
│   ├── 02_sysmon_forwarder_config.md        # Sysmon deployment & Universal Forwarder setup
│   ├── 03_attack_simulation_guide.md        # Kali Linux attack execution guide
│   └── 04_detection_tuning_guide.md         # Alert tuning, false positive mitigation & thresholding
│
└── web_showcase/                            # Interactive Web-Based SOC SIEM Dashboard
    ├── index.html                           # Modern dark-mode SOC Analyst Console & Threat Map
    ├── styles.css                           # Glassmorphism & High-tech SOC aesthetic design
    └── app.js                              # Interactive SPL Search Engine & Live Simulator
```

---

## 🚀 Quick Start Guide

### 1. Launch Splunk Enterprise via Docker
```bash
docker-compose up -d
```
- Open `http://localhost:8000` (Login: `admin` / `SplunkAdmin2026!`).

### 2. Ingest Sample Data
1. Navigate to **Settings > Add Data > Upload**.
2. Select [`wineventlog_security_sample.json`](attack_simulations/sample_telemetry/wineventlog_security_sample.json) with index `wineventlog`.
3. Select [`sysmon_operational_sample.json`](attack_simulations/sample_telemetry/sysmon_operational_sample.json) with index `sysmon`.

### 3. Load Dashboard
1. Go to **Dashboards > Create New Dashboard**.
2. Switch to **Source (XML)** and paste the contents of [`dashboards/security_monitoring_dashboard.xml`](dashboards/security_monitoring_dashboard.xml).

---

## 🧠 Core Competencies Demonstrated

- **SIEM Architecture & Administration:** Splunk Enterprise, Universal Forwarder, index design, data pipeline parsing, and distributed searching.
- **Detection Engineering:** Threat modeling, advanced SPL query construction, correlation rules, false positive tuning, and alert suppression.
- **Endpoint Forensics & Telemetry:** In-depth understanding of Windows Event IDs, Sysmon XML schemas, and process execution trees.
- **Offensive Security Emulation:** Kali Linux adversary simulation (Nmap, Hydra, CrackMapExec, Mimikatz, Metasploit).
- **Incident Response & Triage:** Root cause investigation, containment workflows, NIST SP 800-61r2 reporting, and SOC analyst playbooks.
- **Framework Mastery:** MITRE ATT&CK Enterprise Matrix, Cyber Kill Chain, and Common Information Model (CIM).

---

## 📚 References & Resources

- [Splunk Enterprise Documentation](https://docs.splunk.com/)
- [Microsoft Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Configuration](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Enterprise Framework](https://attack.mitre.org/)
- [NIST Computer Security Incident Handling Guide (SP 800-61r2)](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
