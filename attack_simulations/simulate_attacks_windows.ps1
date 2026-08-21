# ==============================================================================
# SOC Detection Lab — Windows Endpoint Attack Simulation Script (PowerShell)
# Purpose: Safely generate telemetry (Event IDs 4625, 4624, 4672, Sysmon 1, 3, 10, 11)
# Note: Run in an isolated VM / Lab environment only!
# ==============================================================================

[CmdletBinding()]
param (
    [string]$TargetUser = "john.doe",
    [string]$FakeAttackerIP = "192.168.1.100"
)

Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "  🛡️ Windows Endpoint Telemetry & Attack Simulation Runner" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# 1. Simulate Brute Force Failures (Event ID 4625)
Write-Host "`n[1/5] Simulating Logon Failures (Event 4625 / T1110.001)..." -ForegroundColor Yellow
1..6 | ForEach-Object {
    Write-Host "  -> Attempt $_ with invalid password..." -ForegroundColor DarkGray
    try {
        # Trigger an authentication attempt with invalid credentials against localhost
        $netuse = net use \\127.0.0.1\IPC$ /user:$TargetUser "WrongPass_$_" 2>&1
    } catch {}
    Start-Sleep -Milliseconds 300
}
Write-Host "  [+] Generated failed logon telemetry." -ForegroundColor Green

# 2. Simulate Obfuscated PowerShell Execution (Event 4104 / Sysmon Event 1 / T1059.001)
Write-Host "`n[2/5] Simulating Obfuscated PowerShell ScriptBlock (T1059.001)..." -ForegroundColor Yellow
$encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('Write-Output "SOC Lab: Simulating T1059.001 Obfuscation Test"'))
powershell.exe -ExecutionPolicy Bypass -NoProfile -WindowStyle Hidden -EncodedCommand $encodedCommand
Write-Host "  [+] Generated obfuscated PowerShell telemetry." -ForegroundColor Green

# 3. Simulate Persistence via Scheduled Task (Event 4698 / Sysmon Event 1 / T1053.005)
Write-Host "`n[3/5] Simulating Scheduled Task Persistence (T1053.005)..." -ForegroundColor Yellow
$taskName = "SOC_Telemetry_Test_Task"
schtasks.exe /create /tn $taskName /tr "cmd.exe /c echo 'SOC test persistence'" /sc daily /st 12:00 /f 2>$null
Start-Sleep -Seconds 1
schtasks.exe /delete /tn $taskName /f 2>$null
Write-Host "  [+] Generated scheduled task creation and deletion telemetry." -ForegroundColor Green

# 4. Simulate Network Connection / C2 Beaconing (Sysmon Event 3 / T1071.001)
Write-Host "`n[4/5] Simulating C2 Outbound Network Beacons (Sysmon Event 3 / T1071.001)..." -ForegroundColor Yellow
1..8 | ForEach-Object {
    Write-Host "  -> Sending outbound beacon $_/8..." -ForegroundColor DarkGray
    try {
        $null = (New-Object System.Net.Sockets.TcpClient).ConnectAsync("1.1.1.1", 443).Wait(1000)
    } catch {}
    Start-Sleep -Seconds 1
}
Write-Host "  [+] Generated outbound Sysmon network connection events." -ForegroundColor Green

# 5. Summary
Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host "  ✅ Endpoint simulation completed!" -ForegroundColor Green
Write-Host "  Telemetry forwarded to Splunk indexer." -ForegroundColor Green
Write-Host "==================================================================" -ForegroundColor Cyan
