# install-watcher.ps1 - Instant local enforcement for Defender-Guard
# Registers a Scheduled Task that fires the moment Microsoft-Windows-Windows
# Defender Operational log records a state-change event (5001, 5010, 5012),
# re-running reenable-defender.ps1 without waiting for the Wazuh manager.
# Run elevated.

$ErrorActionPreference = "Stop"
$taskName = "Defender-Guard-Instant-ReEnable"
$psDir    = "C:\Program Files\Sysinternals"
$psScript = Join-Path $psDir "reenable-defender.ps1"

Write-Host "=== Defender-Guard Instant Re-Enable Watcher installer ===" -ForegroundColor Cyan

# 1. must be admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: run in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
    return
}

# 2. prereqs
if (-not (Test-Path $psScript)) {
    Write-Host "ERROR: $psScript not found. Run install.ps1 first." -ForegroundColor Red
    return
}

# 3. remove any prior registration (idempotent)
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    Write-Host "Removed prior task '$taskName'." -ForegroundColor Yellow
}

# 4. XML: triggers on Defender state-change events, runs as SYSTEM, hourly repeat.
$xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Defender-Guard Instant Re-Enable: force-re-enable real-time protection the moment Defender logs a state change.</Description></RegistrationInfo>
  <Triggers>
    <EventTrigger>
      <Subscription>Microsoft-Windows-Windows Defender/Operational</Subscription>
      <Delay>PT0S</Delay>
      <Enabled>true</Enabled>
    </EventTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>
    <Priority>5</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>powershell.exe</Command>
      <Arguments>-ExecutionPolicy Bypass -NoProfile -File "$psScript"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

try {
    Register-ScheduledTask -TaskName $taskName -Xml $xml -Force | Out-Null
} catch {
    Write-Host "Register-ScheduledTask failed: $($_.Exception.Message)" -ForegroundColor Red
    return
}

Write-Host ""
Write-Host "  [OK]  Scheduled Task '$taskName' registered (runs as SYSTEM)." -ForegroundColor Green
Write-Host "        Triggers on any event in 'Microsoft-Windows-Windows Defender/Operational'." -ForegroundColor Green
Write-Host "        First-time-disable will now trigger immediate re-enable (no manager round-trip)." -ForegroundColor Green
Write-Host ""
Write-Host "Test:" -ForegroundColor Cyan
Write-Host "  Set-MpPreference -DisableRealtimeMonitoring `$true   # forces a state-change event" -ForegroundColor Cyan
Write-Host "  (Get-MpComputerStatus).RealTimeProtectionEnabled    # expect: True (within ~1s)" -ForegroundColor Cyan
Write-Host "  Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' -Max 3" -ForegroundColor Cyan
