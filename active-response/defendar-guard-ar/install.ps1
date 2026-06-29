# install.ps1 - Defender-Guard one-shot installer.
#
# Runs end-to-end with one command: place files, register the SYSTEM
# watcher task, register the Wazuh AR wrapper, audit Tamper Protection.
# Self-contained -- no helper files, no zip extraction.
#
# One-shot invocation (elevated PowerShell on the Wazuh agent):
#
#   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#   irm https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar/install.ps1 -OutFile $env:TEMP\install.ps1
#   Unblock-File $env:TEMP\install.ps1
#   & "$env:TEMP\install.ps1"

$ErrorActionPreference = "Stop"

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

$base   = "https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar"
$binDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$psDir  = "C:\Program Files\Sysinternals"

# ----------------------------------------------------------------------
# Guard-NormalizeLineEndings
# GitHub raw serves LF; normalize to CRLF before the file is run by
# the scheduler. Cheap text-only read/write.
# ----------------------------------------------------------------------
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

# ----------------------------------------------------------------------
# TLS 1.2 + Get-Script
# Downloads a script into $psDir (or $binDir for .cmd files) if missing.
# ----------------------------------------------------------------------
function Get-Script {
    param([string]$Name, [string]$Dir)
    $dest = Join-Path $Dir $Name
    if (Test-Path $dest) { return $dest }
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
    Write-Host "  -> $Name" -ForegroundColor Yellow
    try { Invoke-WebRequest "$base/$Name" -OutFile $dest -UseBasicParsing }
    catch { throw "Download failed for $Name : $($_.Exception.Message)" }
    Guard-NormalizeLineEndings -Path $dest
    return $dest
}

# ----------------------------------------------------------------------
# Register-GuardTask
# Registers a SYSTEM, highest-privilege Scheduled Task. The XML is built
# line-by-line so there are no here-strings (LF-only GitHub files won't
# break parsing).
# ----------------------------------------------------------------------
function Register-GuardTask {
    param([string]$Name, [string]$Script, [string]$TriggerXml)

    if (-not (Test-Path $Script)) {
        Write-Host "  [!!] script not found: $Script" -ForegroundColor Red
        return
    }

    $existing = Get-ScheduledTask -TaskName $Name -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $Name -Confirm:$false
        Write-Host "  Removed prior task '$Name'." -ForegroundColor Yellow
    }

    $nl = [Environment]::NewLine
    $xml = [string]::Join($nl, @(
        '<?xml version="1.0" encoding="UTF-16"?>'
        '<Task version="1.4" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">'
        ("  <RegistrationInfo><Description>Defender-Guard: $Name - local re-enforcement.</Description></RegistrationInfo>")
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

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

Write-Host "=== Defender-Guard one-shot installer ===" -ForegroundColor Cyan

# Admin check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: run in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
    return
}

# Wazuh agent must be installed
if (-not (Test-Path $binDir)) {
    Write-Host "ERROR: Wazuh agent AR folder not found:" -ForegroundColor Red
    Write-Host "  $binDir" -ForegroundColor Red
    Write-Host "Install the Wazuh agent first, then re-run." -ForegroundColor Red
    return
}

if (-not (Test-Path $psDir)) { New-Item -ItemType Directory -Path $psDir -Force | Out-Null }

# Download / place files. Order matters: ensure both the standalone
# scripts AND the Wazuh AR wrapper are present before task registration.
Write-Host "Placing files..." -ForegroundColor Yellow
$psEvent = Get-Script -Name "reenable-defender.ps1"     -Dir $psDir
$psSvc   = Get-Script -Name "watchdog-service.ps1"      -Dir $psDir
$psAudit = Get-Script -Name "enforce-tamper-protection.ps1" -Dir $psDir
$psXml   = Get-Script -Name "tamper-protection-policy.xml"  -Dir $psDir
$cmdWrap = Get-Script -Name "reenable-defender.cmd"     -Dir $binDir

# Normalize any pre-existing files so older LF copies self-heal.
foreach ($p in @($psEvent, $psSvc, $psAudit)) {
    if (Test-Path $p) { Guard-NormalizeLineEndings -Path $p }
}

# Register BOTH tasks. The service-watcher covers every disable path
# within <=1 s; the event-watcher is the latency-reduction layer. If the
# event one fails on a locked-down channel, service-watcher is enough.
Write-Host ""
Write-Host "Registering Scheduled Tasks..." -ForegroundColor Yellow
$registered = @()

# 1) Service-watcher: poll loop (BootTrigger) - covers Stop-Service and
#    preference flips that do NOT log an event. Always-on.
$bootTrigger = '<BootTrigger><Enabled>true</Enabled></BootTrigger>'
$r1 = Register-GuardTask -Name "Defender-Guard-Service-Watch" -Script $psSvc -TriggerXml $bootTrigger
if ($r1) { $registered += $r1 }

# 2) Event-watcher: fires on Defender state-change events (5001/5010/5012).
#    Uses xpath-style Subscription so the task schema accepts it on
#    modern Win10/11. Best-effort -- if it fails, service watchdog is
#    still the failsafe.
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
$r2 = Register-GuardTask -Name "Defender-Guard-Event-Watch" -Script $psEvent -TriggerXml $eventTrigger
if ($r2) { $registered += $r2 } else {
    Write-Host "  [i] Event-Trigger registration skipped (channel policy / locked schema)." -ForegroundColor DarkYellow
    Unregister-ScheduledTask -TaskName "Defender-Guard-Event-Watch" -Confirm:$false -ErrorAction SilentlyContinue
}

# Layer-0 Tamper audit
Write-Host ""
Write-Host "Running Layer-0 Tamper Protection audit..." -ForegroundColor Yellow
try {
    $status = Get-MpComputerStatus -ErrorAction Stop
    Write-Host ("  RealTimeProtectionEnabled : {0}" -f $status.RealTimeProtectionEnabled)
    Write-Host ("  TamperProtection          : {0}" -f $status.IsTamperProtected)
    Write-Host ("  CloudProtection           : {0}" -f $status.CloudProtectionEnabled)

    if ($status.IsTamperProtected) {
        Write-Host "  [OK] Tamper Protection is ON -- disable attempts will be REJECTED." -ForegroundColor Green
    } else {
        Write-Host "  [!!] Tamper Protection is OFF. Disable attempts succeed and the 1s watcher window applies." -ForegroundColor Red
        Write-Host "       Enable via GUI / Intune / GPO (see tamper-protection-policy.xml)." -ForegroundColor Yellow
    }

    # Re-enforce preferences immediately (idempotent).
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring  $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection     $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning     $false -ErrorAction SilentlyContinue
} catch {
    Write-Host "  [i] Get-MpComputerStatus failed (Defender not initialized yet?): $($_.Exception.Message)" -ForegroundColor DarkYellow
}

# Summary
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
Write-Host "  Set-MpPreference -DisableRealtimeMonitoring `$true    # re-enables within ~1s"
Write-Host "  Stop-Service WinDefend                                # auto-starts within ~1s"
Write-Host "  (Get-MpComputerStatus).RealTimeProtectionEnabled      # expect: True"

if (Test-Path "$binDir\reenable-defender.cmd") {
    Write-Host ""
    Write-Host "Reminder: add the <command>/<active-response> blocks on the Wazuh MANAGER (see README section 3) and Restart-Service WazuhSvc." -ForegroundColor Yellow
}
