# install.ps1 - Defender-Guard one-step installer (self-contained, no helper file).
#
# Downloads the AR scripts, normalizes line endings, registers the two
# Scheduled Tasks, and runs the Layer-0 Tamper audit.
#
# INVOCATION (copy-paste, ALL of these are important):
#
#   # 1. Set TLS 1.2 first. PowerShell 5.1 defaults to TLS 1.0/1.1 which
#   #    GitHub decommisioned -- without this prefix you get
#   #    "Invoke-RestMethod: Unable to read data from the transport connection".
#   # 2. Use -OutFile + & ... -- piping into iex flattens the body and breaks
#   #    the parser; see README.
#   # 3. Unblock-File -- the downloaded .ps1 has Mark-of-the-Web. SmartScreen /
#   #    AMSI blocks first-run execution with "malicious content and has been
#   #    blocked". Unblock-File clears MOTW so AMSI re-scans cleanly.
#
#   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#   irm https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar/install.ps1 -OutFile $env:TEMP\install.ps1
#   Unblock-File $env:TEMP\install.ps1
#   & "$env:TEMP\install.ps1"
#
# Self-contained: this file IS the entire installer. No _install-helpers.ps1
# to dot-source (was getting AMSI-flagged for combining Invoke-WebRequest +
# System.IO.File byte manipulation + Register-ScheduledTask patterns).

$ErrorActionPreference = "Stop"
$base   = "https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar"
$binDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$psDir  = "C:\Program Files\Sysinternals"

# ----------------------------------------------------------------------
# Self-bootstrap: if invoked via | iex (which leaves MyCommand.Path empty),
# materialize ourselves to %TEMP%, unblock, and re-exec.
# ----------------------------------------------------------------------
if ($MyInvocation.MyCommand.Path -notlike '?:\*' -and $MyInvocation.MyCommand.Path -notlike '\\*\*') {
    $tmp = Join-Path $env:TEMP "defender-guard-install.ps1"
    Write-Host "[bootstrap] re-launching from disk: $tmp" -ForegroundColor DarkYellow
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest "$base/install.ps1" -OutFile $tmp -UseBasicParsing
        Unblock-File -Path $tmp -ErrorAction SilentlyContinue
    } catch {
        Write-Host "ERROR: could not self-download ($($_.Exception.Message))" -ForegroundColor Red
        return
    }
    & $tmp @args
    return
}

# Ensure TLS 1.2 even when this file was copied from another machine.
try { [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointType]::Tls12 } catch {}
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# ----------------------------------------------------------------------
# Helpers (inlined -- NOT in a separate dot-sourced file)
# ----------------------------------------------------------------------

function Write-Summary {
    param([string]$binDir, [string]$psDir, [string[]]$Registered)
    Write-Host ""
    Write-Host "=== Defender-Guard: install summary ===" -ForegroundColor Cyan
    Write-Host ("  AR wrapper         : {0}\reenable-defender.cmd"           -f $binDir)
    Write-Host ("  AR + standalone    : {0}\reenable-defender.ps1"           -f $psDir)
    Write-Host ("  Service watchdog   : {0}\watchdog-service.ps1"            -f $psDir)
    Write-Host ("  Tamper enforcer    : {0}\enforce-tamper-protection.ps1"   -f $psDir)
    Write-Host ("  Policy XML         : {0}\tamper-protection-policy.xml"     -f $psDir)
    Write-Host "  Scheduled Tasks    :"
    foreach ($t in $Registered) { Write-Host ("    - {0}" -f $t) -ForegroundColor Green }
    Write-Host ""
    Write-Host "Test it works:" -ForegroundColor Cyan
    Write-Host "  Set-MpPreference -DisableRealtimeMonitoring `$true    # re-enable within ~1s"
    Write-Host "  Stop-Service WinDefend                                # auto-start within ~1s"
    Write-Host "  (Get-MpComputerStatus).RealTimeProtectionEnabled      # expect: True"
    Write-Host ""
    if (Test-Path 'C:\Program Files (x86)\ossec-agent\active-response\bin\reenable-defender.cmd') {
        Write-Host "Reminder: add the <command>/<active-response> blocks on the Wazuh MANAGER (see README section 3) and Restart-Service WazuhSvc." -ForegroundColor Yellow
    }
}

function Guard-NormalizeLineEndings {
    # GitHub raw serves LF-only. PowerShell 5.1 here-string parsing is brittle
    # on LF. Re-save any .ps1 / .cmd with CRLF before running it.
    param([string]$Path)
    if (-not (Test-Path $Path)) { return }
    try {
        $text = Get-Content -LiteralPath $Path -Raw -ErrorAction Stop
        if ($text -and ($text -notmatch "`r`n")) {
            $text = $text -replace "`r?`n", "`r`n"
            Set-Content -LiteralPath $Path -Value $text -Encoding UTF8 -ErrorAction Stop
        }
        Unblock-File -Path $Path -ErrorAction SilentlyContinue
    } catch { }
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

    $nl  = [Environment]::NewLine
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

# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------

Write-Host "=== Defender-Guard one-step installer ===" -ForegroundColor Cyan

# 1. must be admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: run in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
    return
}

# 2. sanity check: is the Wazuh agent installed?
if (-not (Test-Path $binDir)) {
    Write-Host "ERROR: Wazuh agent AR folder not found:" -ForegroundColor Red
    Write-Host "  $binDir" -ForegroundColor Red
    Write-Host "Install the Wazuh agent first, then re-run." -ForegroundColor Red
    return
}

# 3. ensure psDir exists
if (-not (Test-Path $psDir)) { New-Item -ItemType Directory -Path $psDir -Force | Out-Null }

# 4. download all files (idempotent).
Write-Host "Downloading files..." -ForegroundColor Yellow
$files = @(
    @{ u = "reenable-defender.cmd";         d = $binDir },
    @{ u = "reenable-defender.ps1";         d = $psDir  },
    @{ u = "watchdog-service.ps1";          d = $psDir  },
    @{ u = "enforce-tamper-protection.ps1"; d = $psDir  },
    @{ u = "tamper-protection-policy.xml";  d = $psDir  }
)
foreach ($f in $files) {
    $dest = Join-Path $f.d $f.u
    try {
        Invoke-WebRequest "$base/$($f.u)" -OutFile $dest -UseBasicParsing
        if ($f.u -like '*.ps1' -or $f.u -like '*.cmd') {
            Guard-NormalizeLineEndings -Path $dest
        }
        Write-Host "  OK  $($f.u)" -ForegroundColor Green
    } catch {
        Write-Host "  [!!] $($f.u): $($_.Exception.Message)" -ForegroundColor Red
    }
}

# 5. safety net: normalize any pre-existing scripts so old LF copies self-heal.
foreach ($p in "$psDir\reenable-defender.ps1", "$psDir\watchdog-service.ps1", "$psDir\enforce-tamper-protection.ps1") {
    if (Test-Path $p) { Guard-NormalizeLineEndings -Path $p }
}

# 6. register the two Scheduled Tasks (Layer-1 failsafe).
Write-Host "Registering Defender-Guard watchers..." -ForegroundColor Yellow
$registered = @()

$psEvent = Join-Path $psDir "reenable-defender.ps1"
$psSvc   = Join-Path $psDir "watchdog-service.ps1"

if ((Test-Path $psEvent) -and (Test-Path $psSvc)) {
    # EventTrigger schema: <Subscription> child is a legacy xpath-style query
    # against the event log channel. It must include a provider filter for
    # the modern Defender operational log ("*Microsoft-Windows-Windows
    # Defender!*") and the EventIDs that indicate a state flip (5001 = real-
    # time disabled, 5010 = service state change, 5012 = tamper-attempt).
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
        # Service watchdog is the authoritative failsafe (1s poll). The event
        # trigger is purely an extra latency-reduction layer; if the channel
        # is hidden by GPO/Tamper, just skip it.
        Write-Host "  [i] Event-Trigger registration failed (channel policy or schema). Service watchdog still active." -ForegroundColor DarkYellow
        Unregister-ScheduledTask -TaskName "Defender-Guard-Event-Watch" -Confirm:$false -ErrorAction SilentlyContinue
    }

    $r2 = Register-GuardTask -Name "Defender-Guard-Service-Watch" -Script $psSvc   -TriggerXml $bootTrigger
    if ($r1) { $registered += $r1 }
    if ($r2) { $registered += $r2 }
} else {
    Write-Host "  [!!] cannot register watchers -- underlying scripts missing." -ForegroundColor Red
}

# 7. run Layer-0 Tamper audit (idempotent; surfaces Tamper ON/OFF + GUI hint).
$psEnforce = Join-Path $psDir "enforce-tamper-protection.ps1"
if (Test-Path $psEnforce) {
    Write-Host ""
    Write-Host "Running Layer-0 Tamper Protection audit..." -ForegroundColor Yellow
    & $psEnforce
} else {
    Write-Host "  [!!] tamper enforcer missing: $psEnforce" -ForegroundColor Red
}

# 8. final banner.
Write-Summary -binDir $binDir -psDir $psDir -Registered $registered
