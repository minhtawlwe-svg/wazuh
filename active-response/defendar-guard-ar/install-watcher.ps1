# install-watcher.ps1 - Defender-Guard layered local enforcement installer
# Registers TWO Scheduled Tasks that run independent of the Wazuh manager:
#   1. Defender-Guard-Event-Watch   (event-trigger, fires on state change)
#   2. Defender-Guard-Service-Watch (always-on, 1s poll, keeps WinDefend alive)
# Run elevated. Idempotent.

$ErrorActionPreference = "Stop"
$psDir    = "C:\Program Files\Sysinternals"
$psEvent  = Join-Path $psDir "reenable-defender.ps1"
$psSvc    = Join-Path $psDir "watchdog-service.ps1"

Write-Host "=== Defender-Guard Watcher installer ===" -ForegroundColor Cyan

# 1. must be admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: run in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
    return
}

# 2. prereqs
if (-not (Test-Path $psEvent)) {
    Write-Host "ERROR: $psEvent not found. Run install.ps1 first." -ForegroundColor Red
    return
}
if (-not (Test-Path $psSvc)) {
    Write-Host "ERROR: $psSvc not found. Run install.ps1 first." -ForegroundColor Red
    return
}

function Register-GuardTask {
    param([string]$Name, [string]$Script, [string]$TriggerXml)

    $existing = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false
        Write-Host "  Removed prior task '$Name'." -ForegroundColor Yellow
    }

    $xml = @"
<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>Defender-Guard: $Name - local re-enforcement independent of the Wazuh manager.</Description></RegistrationInfo>
  <Triggers>$TriggerXml</Triggers>
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
      <Arguments>-ExecutionPolicy Bypass -NoProfile -File "$Script"</Arguments>
    </Exec>
  </Actions>
</Task>
"@

    Register-ScheduledTask -TaskName $Name -Xml $xml -Force | Out-Null
    Write-Host "  [OK] $Name registered." -ForegroundColor Green
}

# 3. Task 1: event-trigger (catches Set-MpPreference state-change events)
$eventTrigger = @'
<EventTrigger>
  <Subscription>Microsoft-Windows-Windows Defender/Operational</Subscription>
  <Delay>PT0S</Delay>
  <Enabled>true</Enabled>
</EventTrigger>'@
Register-GuardTask -Name "Defender-Guard-Event-Watch" -Script $psEvent -TriggerXml $eventTrigger

# 4. Task 2: always-on service watchdog (catches Stop-Service and flips NOT caught by event log)
$bootTrigger = @'
<BootTrigger><Enabled>true</Enabled></BootTrigger>'@
Register-GuardTask -Name "Defender-Guard-Service-Watch" -Script $psSvc -TriggerXml $bootTrigger

Write-Host ""
Write-Host "Both watchers are active. They run as SYSTEM with highest privileges." -ForegroundColor Green
Write-Host ""
Write-Host "Test:" -ForegroundColor Cyan
Write-Host "  Set-MpPreference -DisableRealtimeMonitoring `$true   # should re-enable within ~1s" -ForegroundColor Cyan
Write-Host "  Stop-Service WinDefend                              # should auto-start within ~1s" -ForegroundColor Cyan
Write-Host "  Get-ScheduledTask | Where-Object { `$_.TaskName -like 'Defender-Guard-*' }" -ForegroundColor Cyan
Write-Host ""
Write-Host "Uninstall:" -ForegroundColor Cyan
Write-Host "  Unregister-ScheduledTask 'Defender-Guard-Event-Watch','Defender-Guard-Service-Watch' -Confirm:`$false" -ForegroundColor Cyan
