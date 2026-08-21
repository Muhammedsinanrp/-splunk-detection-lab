# 🛠️ Lab Guide 01: Splunk Enterprise SIEM Installation & Deployment

This guide covers deploying Splunk Enterprise using Docker or Standalone OS (Ubuntu/Windows).

---

## Option A: Docker Deployment (Recommended - Quickest)

You can launch a fully functional Splunk instance using the provided `docker-compose.yml`:

```bash
docker-compose up -d
```

- **Web UI:** `http://localhost:8000`
- **Default Username:** `admin`
- **Default Password:** `SplunkAdmin2026!`
- **Ingestion Port (Receiver):** `9997`

---

## Option B: Standalone Linux / Ubuntu Installation

1. **Download Splunk Enterprise .deb package:**
   ```bash
   wget -O splunk-9.2.0-linux-2.6-amd64.deb 'https://download.splunk.com/products/splunk/releases/9.2.0/linux/splunk-9.2.0-linux-2.6-amd64.deb'
   ```
2. **Install the package:**
   ```bash
   sudo dpkg -i splunk-9.2.0-linux-2.6-amd64.deb
   ```
3. **Start Splunk and accept the license:**
   ```bash
   sudo /opt/splunk/bin/splunk start --accept-license --answer-yes
   sudo /opt/splunk/bin/splunk enable boot-start
   ```
4. **Enable Ingestion Port 9997 (Receiver):**
   ```bash
   sudo /opt/splunk/bin/splunk enable listen 9997 -auth admin:YourPassword
   ```

---

## Option C: Creating Required Indexes

In Splunk Web, go to **Settings > Indexes > New Index**, or place `configs/indexes.conf` in `$SPLUNK_HOME/etc/system/local/`:

Create the following indexes:
1. `wineventlog` (for Windows Security, System, and PowerShell events)
2. `sysmon` (for Sysmon Operational telemetry)
3. `alerts` (for notable security correlation events)

---

## Ingesting the Sample Datasets for Instant Lab Testing

If you do not have active virtual machines running, you can upload the provided sample telemetry:
1. Go to **Settings > Add Data > Upload**.
2. Select `attack_simulations/sample_telemetry/wineventlog_security_sample.json`.
3. Set Sourcetype to `WinEventLog:Security` and Index to `wineventlog`.
4. Repeat for `sysmon_operational_sample.json` with Sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` and Index `sysmon`.
