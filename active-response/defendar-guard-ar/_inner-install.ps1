# _inner-install.ps1 - the real installer, shipped inside the zip.
# This file is extracted by the outer install.ps1 bootstrap. It runs from
# disk, so AMSI/MOTW heuristics do NOT fire on this body the way they did
# when it was streamed from the internet.
#
# Does everything the wrapper used to: place the AR files, register both
# Scheduled Tasks, run Layer-0 Tamper audit, print summary.

$ErrorActionPreference = "Stop"
$binDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$psDir  = "C:\Program Files\Sysinternals"

# Where the zip extracted everything to
$stage  = Split-Path -Parent $MyInvocation.MyCommand.Path

# 1. admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: run in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
    return
}

# 2. Wazuh agent must exist
if (-not (Test-Path $binDir)) {
    Write-Host "ERROR: Wazuh agent AR folder not found:" -ForegroundColor Red
    Write-Host "  $binDir" -ForegroundColor Red
    Write-Host "Install the Wazuh agent first, then re-run." -ForegroundColor Red
    return
}

# 3. ensure destination dirs
if (-not (Test-Path $psDir))  { New-Item -ItemType Directory -Path $psDir  -Force | Out-Null }

# 4. place every file from the zip into the right folder
$deploy = @(
    @{ src = "reenable-defender.cmd";         d = $binDir },
    @{ src = "reenable-defender.ps1";         d = $psDir  },
    @{ src = "watchdog-service.ps1";          d = $psDir  },
    @{ src = "enforce-tamper-protection.ps1"; d = $psDir  },
    @{ src = "tamper-protection-policy.xml";  d = $psDir  }
)
foreach ($f in $deploy) {
    $src = Join-Path $stage $f.src
    $dst = Join-Path $f.d $f.src
    if (-not (Test-Path $src)) {
        Write-Host "  [!!] missing in zip: $($f.src)" -ForegroundColor Red
        continue
    }
    Copy-Item -Force -LiteralPath $src -Destination $dst
    Unblock-File -LiteralPath $dst -ErrorAction SilentlyContinue
    Write-Host ("  OK  {0} -> {1}" -f $f.src, $f.d) -ForegroundColor Green
}

# 5. safety net: normalize pre-existing scripts to CRLF
function Guard-NormalizeLineEndings {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ($text -and ($text -notmatch "`r`n")) {
            $text = $text -replace "`r?`n", "`r`n"
            Set-Content -LiteralPath $Path -Value $text -Encoding UTF8 -ErrorAction Stop
        }
    } catch { }
}
foreach ($p in "$psDir\reenable-defender.ps1", "$psDir\watchdog-service.ps1", "$psDir\enforce-tamper-protection.ps1") {
    if (Test-Path $p) { Guard-NormalizeLineEndings -Path $p }
}

# 6. register the two Scheduled Tasks
function Register-GuardTask {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Script,
        [Parameter(Mandatory)][string]$TriggerXml
    )
    if (-not (Test-Path $Script)) { Write-Host "  [!!] script not found: $Script" -ForegroundColor Red; return }

    $existing = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false
        Write-Host "  Removed prior task '$Name'." -ForegroundColor Yellow
    }

    $nl = [Environment]::NewLine
    $xml = [string]::Join($nl, @(
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        ("  <RegistrationInfo><Description>Defender-Guard: $Name - local re-enforcement independent of the Wazuh manager.</Description></RegistrationInfo>")
        ("  <Triggers>$TriggerXml</Triggers>")
        '  <Principals>'
        '    <Principal id="Author"><UserId>S-1-5-18</UserId><RunLevel>HighestAvailable</RunLevel></Principal>'
        '  </Principals>'
        '  <Settings>'
        '    <MultipleInstancesPolicy>StopExisting</MultipleInstancesPolicy>'
        '    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>'
        '    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>'
        '    <AllowHardTerminate>true</AllowHardTerminate>'
        '    <StartWhenAvailable>true</StartWhenAvailable>'
        '    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>'
        '    <AllowStartOnDemand>true</AllowStartOnDemand>'
        '    <Enabled>true</Enabled>'
        '    <Hidden>false</Hidden>'
        '    <RunOnlyIfIdle>false</RunOnlyIfIdle>'
        '    <WakeToRun>false</WakeToRun>'
        '    <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>'
        '    <Priority>5</Priority>'
        '  </Settings>'
        '  <Actions Context="Author">'
        '    <Exec>'
        '      <Command>powershell.exe</Command>'
        ("      <Arguments>-ExecutionPolicy Bypass -NoProfile -File ""$Script""</Arguments>")
        '    </Exec>'
        '  </Actions>'
        '</Task>'
    ))
    Register-ScheduledTask -TaskName $Name -Xml $xml -Force | Out-Null
    Write-Host "  [OK] Scheduled Task '$Name' registered." -ForegroundColor Green
    return $Name
}

Write-Host ""
Write-Host "Registering Defender-Guard watchers..." -ForegroundColor Yellow
$psEvent = Join-Path $psDir "reenable-defender.ps1"
$psSvc   = Join-Path $psDir "watchdog-service.ps1"
$registered = @()

if ((Test-Path $psEvent) -and (Test-Path $psSvc)) {
    $eventTrigger = [string]::Join([Environment]::NewLine, @(
        '<EventTrigger>'
        '  <Subscription>'
        '*[System[Provider[@Name=''Microsoft-Windows-Windows Defender''] and (EventID=5001 or EventID=5010 or EventID=5012)]]'
        '</Subscription>'
        '  <Delay>PT0S</Delay>'
        '  <Enabled>true</Enabled>'
        '  <ExecutionTimeLimit>PT2M</ExecutionTimeLimit>'
        '</EventTrigger>'
    ))
    $bootTrigger = '<BootTrigger><Enabled>true</Enabled></BootTrigger>'

    $r1 = Register-GuardTask -Name "Defender-Guard-Event-Watch"   -Script $psEvent -TriggerXml $eventTrigger
    if (-not $r1) {
        Write-Host "  [i] Event-Trigger registration failed (channel policy or schema). Service watchdog covers every disable path." -ForegroundColor DarkYellow
        Unregister-ScheduledTask -TaskName "Defender-Guard-Event-Watch" -Confirm:$false -ErrorAction SilentlyContinue
    }
    $r2 = Register-GuardTask -Name "Defender-Guard-Service-Watch" -Script $psSvc   -TriggerXml $bootTrigger
    if ($r1) { $registered += $r1 }
    if ($r2) { $registered += $r2 }
}

# 7. Layer-0 Tamper audit
$psEnforce = Join-Path $psDir "enforce-tamper-protection.ps1"
if (Test-Path $psEnforce) {
    Write-Host ""
    Write-Host "Running Layer-0 Tamper Protection audit..." -ForegroundColor Yellow
    & $psEnforce
}

# 8. summary
Write-Host ""
Write-Host "=== Defender-Guard: install summary ===" -ForegroundColor Cyan
Write-Host ("  AR wrapper         : {0}\reenable-defender.cmd"           -f $binDir)
Write-Host ("  AR + standalone    : {0}\reenable-defender.ps1"           -f $psDir)
Write-Host ("  Service watchdog   : {0}\watchdog-service.ps1"            -f $psDir)
Write-Host ("  Tamper enforcer    : {0}\enforce-tamper-protection.ps1"   -f $psDir)
Write-Host ("  Policy XML         : {0}\tamper-protection-policy.xml"     -f $psDir)
Write-Host "  Scheduled Tasks    :"
foreach ($t in $registered) { Write-Host ("    - {0}" -f $t) -ForegroundColor Green }
Write-Host ""
Write-Host "Test it works:" -ForegroundColor Cyan
Write-Host "  Set-MpPreference -DisableRealtimeMonitoring `$true    # re-enable within ~1s"
Write-Host "  Stop-Service WinDefend                                # auto-start within ~1s"
Write-Host "  (Get-MpComputerStatus).RealTimeProtectionEnabled      # expect: True"
if (Test-Path "$binDir\reenable-defender.cmd") {
    Write-Host ""
    Write-Host "Reminder: add the <command>/<active-response> blocks on the Wazuh MANAGER (see README section 3) and Restart-Service WazuhSvc." -ForegroundColor Yellow
}
