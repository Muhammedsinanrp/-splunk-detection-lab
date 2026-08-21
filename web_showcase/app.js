// ==============================================================================
// Splunk SOC Lab — Interactive SIEM & Telemetry Simulation Engine
// ==============================================================================

(function() {
  'use strict';

  // State Management
  const state = {
    totalEvents: 1428,
    failedLogons: 28,
    activeAlerts: 3,
    endpoints: 5,
    chartData: [4, 6, 3, 5, 2, 8, 28, 45, 12, 6, 8, 4],
    topSources: [
      { ip: "192.168.1.100", user: "john.doe", count: 42, risk: 95 },
      { ip: "192.168.1.105", user: "administrator", count: 18, risk: 72 },
      { ip: "10.0.5.24", user: "svc_backup", count: 7, risk: 35 },
      { ip: "172.16.2.80", user: "jane.smith", count: 3, risk: 15 }
    ],
    alerts: [
      {
        id: "INC-20260821-001",
        time: "10:05:45 UTC",
        rule: "Lateral Movement via SMB (T1021.002)",
        severity: "High",
        mitre: "T1021.002",
        source: "192.168.1.100 -> DC-01",
        user: "john.doe",
        status: "Investigating",
        details: "User 'john.doe' experienced failed authentication (4625) followed by successful authentications (4624 Logon Type 3) across FILE-SRV-01 and DC-01 within 60s.",
        rawLog: {
          EventCode: 4624,
          Account_Name: "john.doe",
          Logon_Type: 3,
          AuthenticationPackageName: "NTLM",
          IpAddress: "192.168.1.100",
          Target_Host: "DC-01.corp.local"
        },
        playbook: "1. Disable account 'john.doe' in AD.\n2. Purge Kerberos tickets via klist purge.\n3. Isolate DC-01 and FILE-SRV-01 from production subnet.\n4. Rotate krbtgt credentials."
      },
      {
        id: "INC-20260821-002",
        time: "10:06:22 UTC",
        rule: "Privilege Escalation - Special Rights Assigned (T1078)",
        severity: "Critical",
        mitre: "T1078",
        source: "DC-01 (Local / Console)",
        user: "john.doe",
        status: "Open",
        details: "Account 'john.doe' (baseline: Standard) was assigned SeDebugPrivilege / SeImpersonatePrivilege on DC-01 (EventCode 4672).",
        rawLog: {
          EventCode: 4672,
          Account_Name: "john.doe",
          PrivilegeList: "SeDebugPrivilege, SeSecurityPrivilege, SeTakeOwnershipPrivilege",
          ComputerName: "DC-01.corp.local",
          Privilege_Level: "Standard (Non-Admin)"
        },
        playbook: "1. Remove 'john.doe' from BUILTIN\\Administrators.\n2. Terminate all elevated PowerShell/cmd processes.\n3. Take memory image of DC-01 using DumpIt/KAPE.\n4. Reset domain admin passwords."
      },
      {
        id: "INC-20260821-003",
        time: "10:06:55 UTC",
        rule: "Credential Dumping via LSASS Handle (T1003.001)",
        severity: "Critical",
        mitre: "T1003.001",
        source: "C:\\Users\\Public\\mimikatz.exe",
        user: "CORP\\john.doe",
        status: "Open",
        details: "Sysmon Event 10: Suspicious process mimikatz.exe requested GrantedAccess 0x1010 against lsass.exe process memory.",
        rawLog: {
          EventCode: 10,
          SourceImage: "C:\\Users\\Public\\mimikatz.exe",
          TargetImage: "C:\\Windows\\System32\\lsass.exe",
          GrantedAccess: "0x1010",
          SourceUser: "CORP\\john.doe",
          Computer: "DC-01.corp.local"
        },
        playbook: "1. Terminate mimikatz.exe process tree.\n2. Delete staging directory C:\\Users\\Public\\.\n3. Enable LSA Protection (RunAsPPL = 1) via GPO.\n4. Enable Windows Defender Credential Guard."
      }
    ],
    sampleLogs: [
      { time: "10:05:12", host: "FILE-SRV-01", user: "john.doe", event: "4625", details: "Logon Failure: Bad password from 192.168.1.100 (SubStatus 0xC000006A)" },
      { time: "10:05:45", host: "FILE-SRV-01", user: "john.doe", event: "4624", details: "Logon Success: NTLM Network Logon from 192.168.1.100" },
      { time: "10:06:10", host: "DC-01", user: "john.doe", event: "4624", details: "Lateral Jump: Successful SMB Auth from 192.168.1.100" },
      { time: "10:06:22", host: "DC-01", user: "john.doe", event: "4672", details: "Special Privileges Assigned: SeDebugPrivilege, SeSecurityPrivilege" },
      { time: "10:06:40", host: "DC-01", user: "john.doe", event: "Sysmon 1", details: "Process Create: powershell.exe -nop -w hidden -enc SQBFA..." },
      { time: "10:06:55", host: "DC-01", user: "john.doe", event: "Sysmon 10", details: "Process Access: mimikatz.exe -> lsass.exe (GrantedAccess: 0x1010)" },
      { time: "10:07:05", host: "DC-01", user: "john.doe", event: "4732", details: "User added to security-enabled local group BUILTIN\\Administrators" },
      { time: "10:07:30", host: "DC-01", user: "john.doe", event: "Sysmon 3", details: "Network Connection: powershell.exe -> 198.51.100.45:443" }
    ]
  };

  // Queries map for SPL Preset select
  const splQueries = {
    lateral_movement: `index=wineventlog (EventCode=4625 OR EventCode=4624) Logon_Type IN (3, 10)\n| transaction Account_Name maxspan=10m\n| where mvcount(EventCode) > 1 AND mvcount(ComputerName) > 1\n| table _time, Account_Name, ComputerName, IpAddress`,
    privilege_escalation: `index=wineventlog EventCode=4672\n| lookup user_privilege_lookup Account_Name OUTPUT Department, Privilege_Level\n| where Privilege_Level != "DomainAdmin" AND Privilege_Level != "LocalAdmin"\n| table _time, Account_Name, Department, ComputerName, PrivilegeList`,
    brute_force: `index=wineventlog EventCode=4625\n| stats count as failed_attempts, dc(Account_Name) as distinct_users by IpAddress\n| where failed_attempts >= 5\n| sort - failed_attempts`,
    credential_dumping: `index=sysmon EventCode=10 TargetImage="*\\\\lsass.exe"\n| where NOT like(SourceImage, "%\\\\system32\\\\%")\n| table _time, Computer, SourceImage, TargetImage, GrantedAccess, SourceUser`,
    c2_beaconing: `index=sysmon EventCode=3 Initiated=true\n| stats count, earliest(_time) as first, latest(_time) as last by Image, DestinationIp\n| eval duration = last - first\n| where count >= 8 AND duration <= 300`
  };

  // DOM Elements
  const elKpiTotalEvents = document.getElementById("kpi-total-events");
  const elKpiFailedLogons = document.getElementById("kpi-failed-logons");
  const elKpiActiveAlerts = document.getElementById("kpi-active-alerts");
  const elAlertsTbody = document.getElementById("alerts-tbody");
  const elTopSourcesTbody = document.querySelector("#table-top-sources tbody");
  const elSplResultsBody = document.getElementById("spl-results-body");
  const elSplSelect = document.getElementById("spl-preset-select");
  const elSplInput = document.getElementById("spl-search-input");
  const elBtnRunSpl = document.getElementById("btn-run-spl");
  const elLiveClock = document.getElementById("live-clock");
  const elModal = document.getElementById("incident-modal");
  const elModalTitle = document.getElementById("modal-title");
  const elModalSubtitle = document.getElementById("modal-subtitle");
  const elModalContent = document.getElementById("modal-content");
  const elModalClose = document.getElementById("modal-close");
  const canvasChart = document.getElementById("chart-failed-logins");

  // Update Clock
  function updateClock() {
    const now = new Date();
    const utcString = now.toUTCString().split(" ")[4];
    elLiveClock.textContent = `UTC ${utcString}`;
  }
  setInterval(updateClock, 1000);
  updateClock();

  // Render Canvas Velocity Chart
  function renderVelocityChart() {
    if (!canvasChart) return;
    const ctx = canvasChart.getContext("2d");
    const dpr = window.devicePixelRatio || 1;
    const rect = canvasChart.getBoundingClientRect();
    canvasChart.width = rect.width * dpr;
    canvasChart.height = rect.height * dpr;
    ctx.scale(dpr, dpr);

    const w = rect.width;
    const h = rect.height;
    const padding = 30;
    const data = state.chartData;
    const maxVal = Math.max(...data, 50);

    ctx.clearRect(0, 0, w, h);

    // Draw Grid Lines
    ctx.strokeStyle = "rgba(255, 255, 255, 0.05)";
    ctx.lineWidth = 1;
    for (let i = 0; i <= 4; i++) {
      const y = padding + (i * (h - padding * 2) / 4);
      ctx.beginPath();
      ctx.moveTo(padding, y);
      ctx.lineTo(w - padding, y);
      ctx.stroke();

      ctx.fillStyle = "#64748b";
      ctx.font = "10px JetBrains Mono";
      ctx.fillText(Math.round(maxVal - (i * maxVal / 4)), 5, y + 3);
    }

    // Draw Area
    const stepX = (w - padding * 2) / (data.length - 1);
    ctx.beginPath();
    ctx.moveTo(padding, h - padding);

    for (let i = 0; i < data.length; i++) {
      const x = padding + (i * stepX);
      const y = (h - padding) - ((data[i] / maxVal) * (h - padding * 2));
      if (i === 0) ctx.lineTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.lineTo(padding + ((data.length - 1) * stepX), h - padding);
    ctx.closePath();

    const gradient = ctx.createLinearGradient(0, padding, 0, h - padding);
    gradient.addColorStop(0, "rgba(239, 68, 68, 0.45)");
    gradient.addColorStop(1, "rgba(239, 68, 68, 0.0)");
    ctx.fillStyle = gradient;
    ctx.fill();

    // Draw Line
    ctx.beginPath();
    for (let i = 0; i < data.length; i++) {
      const x = padding + (i * stepX);
      const y = (h - padding) - ((data[i] / maxVal) * (h - padding * 2));
      if (i === 0) ctx.moveTo(x, y);
      else ctx.lineTo(x, y);
    }
    ctx.strokeStyle = "#ef4444";
    ctx.lineWidth = 2.5;
    ctx.stroke();

    // Draw Data Points
    for (let i = 0; i < data.length; i++) {
      const x = padding + (i * stepX);
      const y = (h - padding) - ((data[i] / maxVal) * (h - padding * 2));
      ctx.beginPath();
      ctx.arc(x, y, 4, 0, Math.PI * 2);
      ctx.fillStyle = "#0a0d14";
      ctx.fill();
      ctx.strokeStyle = "#00f0ff";
      ctx.lineWidth = 2;
      ctx.stroke();
    }
  }

  // Render Top Attacking Sources
  function renderTopSources() {
    elTopSourcesTbody.innerHTML = state.topSources.map(s => `
      <tr>
        <td style="font-family:var(--font-mono); color:var(--accent-cyan); font-weight:600;">${s.ip}</td>
        <td><code>${s.user}</code></td>
        <td style="font-family:var(--font-mono);">${s.count}</td>
        <td>
          <span class="badge-sev ${s.risk > 80 ? 'sev-critical' : s.risk > 50 ? 'sev-high' : 'sev-medium'}">
            Risk ${s.risk}%
          </span>
        </td>
      </tr>
    `).join('');
  }

  // Render Notable Alerts Queue
  function renderAlertsQueue() {
    elAlertsTbody.innerHTML = state.alerts.map(a => {
      const sevClass = a.severity === "Critical" ? "sev-critical" : a.severity === "High" ? "sev-high" : "sev-medium";
      return `
        <tr data-alert-id="${a.id}">
          <td style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-muted);">${a.time}</td>
          <td style="font-weight:600;">${a.rule}</td>
          <td><span class="badge-sev ${sevClass}">${a.severity}</span></td>
          <td><span class="badge-mitre">${a.mitre}</span></td>
          <td style="font-family:var(--font-mono); font-size:0.78rem;">${a.source}</td>
          <td><span style="color:#10b981;">● ${a.status}</span></td>
          <td><button class="sim-btn" style="padding:0.25rem 0.6rem; font-size:0.72rem;" onclick="window.viewIncident('${a.id}')">Investigate</button></td>
        </tr>
      `;
    }).join('');
    document.getElementById("alerts-count-badge").textContent = `${state.alerts.length} Notable Events`;
  }

  // Render SPL Results
  function renderSplResults(filterText = "") {
    let logs = state.sampleLogs;
    if (filterText) {
      const lower = filterText.toLowerCase();
      logs = logs.filter(l => 
        l.host.toLowerCase().includes(lower) || 
        l.user.toLowerCase().includes(lower) || 
        l.event.toLowerCase().includes(lower) || 
        l.details.toLowerCase().includes(lower)
      );
    }
    elSplResultsBody.innerHTML = logs.map(l => `
      <tr>
        <td style="font-family:var(--font-mono); color:var(--text-muted); font-size:0.75rem;">${l.time}</td>
        <td style="font-weight:600; color:var(--accent-blue);">${l.host}</td>
        <td><code>${l.user}</code></td>
        <td><span class="badge-mitre">${l.event}</span></td>
        <td style="font-family:var(--font-mono); font-size:0.78rem; color:#cbd5e1;">${l.details}</td>
      </tr>
    `).join('');
  }

  // View Incident Modal
  window.viewIncident = function(id) {
    const alert = state.alerts.find(a => a.id === id);
    if (!alert) return;
    elModalTitle.textContent = `${alert.rule}`;
    elModalSubtitle.textContent = `Incident ID: ${alert.id} • Target User: ${alert.user} • Severity: ${alert.severity}`;

    elModalContent.innerHTML = `
      <div style="display:flex; flex-direction:column; gap:1rem;">
        <div>
          <h4 style="color:var(--accent-cyan); font-size:0.9rem; margin-bottom:0.35rem;">📌 Executive Incident Summary</h4>
          <p style="font-size:0.85rem; color:var(--text-secondary);">${alert.details}</p>
        </div>

        <div>
          <h4 style="color:var(--accent-cyan); font-size:0.9rem; margin-bottom:0.35rem;">🔍 Raw Ingested Telemetry (Splunk JSON)</h4>
          <pre><code>${JSON.stringify(alert.rawLog, null, 2)}</code></pre>
        </div>

        <div>
          <h4 style="color:var(--accent-cyan); font-size:0.9rem; margin-bottom:0.35rem;">🛠️ SOC Playbook Response Actions (SOP)</h4>
          <pre style="color:#86efac;"><code>${alert.playbook}</code></pre>
        </div>
      </div>
    `;
    elModal.classList.add("active");
  };

  elModalClose.addEventListener("click", () => elModal.classList.remove("active"));
  elModal.addEventListener("click", (e) => {
    if (e.target === elModal) elModal.classList.remove("active");
  });

  // SPL Presets & Search
  elSplSelect.addEventListener("change", (e) => {
    const query = splQueries[e.target.value] || "";
    elSplInput.value = query.replace(/\n/g, ' ');
    renderSplResults(e.target.value.replace("_", " "));
  });

  elBtnRunSpl.addEventListener("click", () => {
    const query = elSplInput.value;
    renderSplResults(query.length > 5 ? query.substring(0, 8) : "");
  });

  // Simulation Triggers
  document.getElementById("btn-sim-bruteforce").addEventListener("click", () => {
    state.totalEvents += 45;
    state.failedLogons += 15;
    state.chartData.push(state.chartData[state.chartData.length - 1] + 20);
    if (state.chartData.length > 12) state.chartData.shift();

    state.sampleLogs.unshift({
      time: new Date().toUTCString().split(" ")[4],
      host: "FILE-SRV-01",
      user: "john.doe",
      event: "4625",
      details: "Hydra Brute Force: Failed password attempt 1 of 10 (SubStatus 0xC000006A)"
    });

    updateUI();
  });

  document.getElementById("btn-sim-lateral").addEventListener("click", () => {
    state.totalEvents += 30;
    state.sampleLogs.unshift({
      time: new Date().toUTCString().split(" ")[4],
      host: "DC-01",
      user: "john.doe",
      event: "4624",
      details: "CrackMapExec: Lateral SMB Authentication across subnets from 192.168.1.100"
    });
    updateUI();
  });

  document.getElementById("btn-sim-mimikatz").addEventListener("click", () => {
    state.totalEvents += 15;
    state.activeAlerts += 1;
    state.sampleLogs.unshift({
      time: new Date().toUTCString().split(" ")[4],
      host: "DC-01",
      user: "CORP\\john.doe",
      event: "Sysmon 10",
      details: "Mimikatz: Process access to lsass.exe with GrantedAccess 0x1010"
    });
    updateUI();
  });

  document.getElementById("btn-sim-c2").addEventListener("click", () => {
    state.totalEvents += 25;
    state.sampleLogs.unshift({
      time: new Date().toUTCString().split(" ")[4],
      host: "DC-01",
      user: "CORP\\john.doe",
      event: "Sysmon 3",
      details: "C2 Beacon: Outbound TCP/443 connection to external IP 198.51.100.45"
    });
    updateUI();
  });

  document.getElementById("btn-sim-fullkillchain").addEventListener("click", () => {
    state.totalEvents += 150;
    state.failedLogons += 35;
    state.activeAlerts += 2;
    state.chartData.push(65);
    if (state.chartData.length > 12) state.chartData.shift();

    document.getElementById("soc-status-text").textContent = "DEFCON 1 — ACTIVE BREACH";
    document.getElementById("soc-health-dot").className = "status-dot dot-red";

    updateUI();
  });

  document.getElementById("btn-sim-reset").addEventListener("click", () => {
    state.totalEvents = 1428;
    state.failedLogons = 28;
    state.activeAlerts = 3;
    state.chartData = [4, 6, 3, 5, 2, 8, 28, 45, 12, 6, 8, 4];
    document.getElementById("soc-status-text").textContent = "DEFCON 4 — MONITORING";
    document.getElementById("soc-health-dot").className = "status-dot dot-green";
    updateUI();
  });

  function updateUI() {
    elKpiTotalEvents.textContent = state.totalEvents.toLocaleString();
    elKpiFailedLogons.textContent = state.failedLogons.toLocaleString();
    elKpiActiveAlerts.textContent = state.activeAlerts;
    renderVelocityChart();
    renderTopSources();
    renderAlertsQueue();
    renderSplResults();
  }

  // Initial Load
  window.addEventListener("resize", renderVelocityChart);
  updateUI();

})();
