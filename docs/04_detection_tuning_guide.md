# 🎛️ Lab Guide 04: Detection Engineering, Alert Tuning & False Positive Mitigation

Detection engineering requires continuous calibration to maintain a high signal-to-noise ratio and prevent alert fatigue.

---

## 1. Alert Fatigue & Threshold Calibration

### Baseline Calculation:
Before setting rigid numeric thresholds (e.g. `count > 5`), analyze the historical distribution of events in your environment:

```spl
index=wineventlog EventCode=4625
| bin _time span=1h
| stats count by _time, IpAddress
| stats avg(count) as mean, stdev(count) as sigma
| eval alert_threshold = mean + (3 * sigma)
```
Using the **3-Sigma Rule (Mean + 3*StdDev)** allows alerting only on statistical outliers without flagging standard user typos.

---

## 2. Maintaining White-lists & Lookups

To avoid hardcoding exclusions into SPL queries, maintain dedicated lookup tables:

### Example: Whitelisting Vulnerability Scanners
Create `configs/lookups/authorized_scanners.csv`:
```csv
Scanner_IP,Scanner_Name,Approved_By,Expiration_Date
192.168.1.250,Tenable Nessus,SecOps Lead,2027-12-31
192.168.1.251,Qualys Sensor,SecOps Lead,2027-12-31
```

Incorporate lookup in detection queries:
```spl
index=wineventlog EventCode=4625
| lookup authorized_scanners Scanner_IP AS IpAddress OUTPUT Scanner_Name
| where isnull(Scanner_Name)
```

---

## 3. Managing Alert Suppression

In `savedsearches.conf`, configure per-entity alert suppression:
- **Brute Force:** Suppress by `IpAddress` for 15 minutes to avoid duplicate tickets for the same burst.
- **Lateral Movement:** Suppress by `Account_Name` for 1 hour.
- **Privilege Escalation:** Suppress by `Account_Name` for 30 minutes.
