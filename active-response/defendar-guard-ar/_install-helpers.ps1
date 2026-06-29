# _install-helpers.ps1 - shared installer helpers for Defender-Guard.
# Dot-sourced by install.ps1 and install-watcher.ps1; never run directly.

$script:GuardTaskRegistered = @()

function Assert-Admin {
    $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
              ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    if (-not $isAdmin) {
        Write-Host "ERROR: run in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
        exit 1
    }
}

function Assert-WazuhAgent {
    param([string]$BinDir)
    if (-not (Test-Path $BinDir)) {
        Write-Host "ERROR: Wazuh agent AR folder not found:`n  $BinDir" -ForegroundColor Red
        Write-Host "Install the Wazuh agent first, then re-run." -ForegroundColor Red
        exit 1
    }
}

function Get-GuardScript {
    <#
      Returns the local path to a Defender-Guard script under $psDir.
      Downloads from GitHub if missing (so this helper is also useful
      for first-time installs run interactively).
    #>
    param([string]$psDir, [string]$base, [string]$name)
    $path = Join-Path $psDir $name
    if (-not (Test-Path $path)) {
        if (-not (Test-Path $psDir)) { New-Item -ItemType Directory -Path $psDir -Force | Out-Null }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest "$base/$name" -OutFile $path -UseBasicParsing
    }
    return $path
}

function Register-GuardTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Script,
        [Parameter(Mandatory)][string]$TriggerXml
    )

    if (-not (Test-Path $Script)) {
        Write-Host "  [!!] script not found: $Script" -ForegroundColor Red
        return
    }

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
    Write-Host "  [OK] Scheduled Task '$Name' registered." -ForegroundColor Green
    $script:GuardTaskRegistered += $Name
}

function Install-GuardWatchers {
    <#
      Registers the two Defender-Guard Scheduled Tasks. Both run as SYSTEM
      with highest privileges; both auto-restart on reboot / crash.
    #>
    param([string]$psDir)

    $psEvent = Join-Path $psDir "reenable-defender.ps1"
    $psSvc   = Join-Path $psDir "watchdog-service.ps1"

    if (-not (Test-Path $psEvent)) { Write-Host "  [!!] missing: $psEvent" -ForegroundColor Red; return }
    if (-not (Test-Path $psSvc))   { Write-Host "  [!!] missing: $psSvc"   -ForegroundColor Red; return }

    Write-Host "Registering Defender-Guard watchers..." -ForegroundColor Yellow

    # Layer 1a: event-trigger (catches Set-MpPreference state-change events)
    $eventTrigger = @'
<EventTrigger>
  <Subscription>Microsoft-Windows-Windows Defender/Operational</Subscription>
  <Delay>PT0S</Delay>
  <Enabled>true</Enabled>
</EventTrigger>'@
    Register-GuardTask -Name "Defender-Guard-Event-Watch" -Script $psEvent -TriggerXml $eventTrigger

    # Layer 1b: always-on service watchdog (catches Stop-Service and flips NOT caught by event log)
    $bootTrigger = @'
<BootTrigger><Enabled>true</Enabled></BootTrigger>'@
    Register-GuardTask -Name "Defender-Guard-Service-Watch" -Script $psSvc -TriggerXml $bootTrigger
}

function Invoke-GuardTamperCheck {
    <#
      Runs the Layer-0 enforcement/audit script (idempotent). Surfaces
      Tamper Protection ON/OFF and lists the GUI/Intune/GPO path to enable.
    #>
    param([string]$psDir)

    $psEnforce = Join-Path $psDir "enforce-tamper-protection.ps1"
    if (-not (Test-Path $psEnforce)) {
        Write-Host "  [!!] missing: $psEnforce" -ForegroundColor Red
        return
    }
    Write-Host ""
    Write-Host "Running Layer-0 Tamper Protection audit..." -ForegroundColor Yellow
    & $psEnforce
}

function Show-GuardFinal {
    <#
      Common post-install banner: lists what was registered and the next steps.
    #>
    param([string]$binDir, [string]$psDir)

    Write-Host ""
    Write-Host "=== Defender-Guard: install summary ===" -ForegroundColor Cyan
    Write-Host ("  AR wrapper         : {0}\reenable-defender.cmd" -f $binDir)
    Write-Host ("  AR + standalone    : {0}\reenable-defender.ps1" -f $psDir)
    Write-Host ("  Service watchdog   : {0}\watchdog-service.ps1"  -f $psDir)
    Write-Host ("  Tamper enforcer    : {0}\enforce-tamper-protection.ps1" -f $psDir)
    Write-Host ("  Policy XML         : {0}\tamper-protection-policy.xml"   -f $psDir)
    Write-Host "  Scheduled Tasks    :"
    foreach ($t in $script:GuardTaskRegistered) { Write-Host ("    - {0}" -f $t) -ForegroundColor Green }

    Write-Host ""
    Write-Host "Test it works:" -ForegroundColor Cyan
    Write-Host "  Set-MpPreference -DisableRealtimeMonitoring `$true    # re-enable within ~1s"
    Write-Host "  Stop-Service WinDefend                                # auto-start within ~1s"
    Write-Host "  (Get-MpComputerStatus).RealTimeProtectionEnabled      # expect: True"
    Write-Host ""

    $mgrHint = if (Test-Path 'C:\Program Files (x86)\ossec-agent\active-response\bin\reenable-defender.cmd') {
                  "Reminder: add the <command>/<active-response> blocks on the Wazuh MANAGER (see README section 3) and Restart-Service WazuhSvc."
              } else { "" }
    if ($mgrHint) { Write-Host $mgrHint -ForegroundColor Yellow }
}
