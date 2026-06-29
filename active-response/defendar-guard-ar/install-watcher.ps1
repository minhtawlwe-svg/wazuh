# install-watcher.ps1 - re-register only the two Scheduled Tasks.
# Self-contained (does NOT dot-source _install-helpers.ps1 -- that file is gone).
# Use this AFTER install.ps1 has been run once, e.g. after a registry reload or
# when task XML schemas need a refresh. Re-downloads the underlying scripts if
# missing.
#
# Run elevated.

$ErrorActionPreference = "Stop"
$base   = "https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar"
$binDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$psDir  = "C:\Program Files\Sysinternals"

# Self-bootstrap if invoked via | iex.
if ($MyInvocation.MyCommand.Path -notlike '?:\*' -and $MyInvocation.MyCommand.Path -notlike '\\*\*') {
    $tmp = Join-Path $env:TEMP "defender-guard-install-watcher.ps1"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest "$base/install-watcher.ps1" -OutFile $tmp -UseBasicParsing
        Unblock-File -Path $tmp -ErrorAction SilentlyContinue
    } catch {
        Write-Host "ERROR: self-download failed ($($_.Exception.Message))" -ForegroundColor Red
        return
    }
    & $tmp @args
    return
}

try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 } catch {}

# Must be admin
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: run in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
    return
}

if (-not (Test-Path $psDir)) { New-Item -ItemType Directory -Path $psDir -Force | Out-Null }
if (-not (Test-Path $binDir)) {
    Write-Host "ERROR: Wazuh agent AR folder not found: $binDir" -ForegroundColor Red
    return
}

function Guard-NormalizeLineEndings {
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
    if (-not (Test-Path $Script)) { Write-Host "  [!!] missing: $Script" -ForegroundColor Red; return }

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
}

Write-Host "=== Defender-Guard watcher re-registration ===" -ForegroundColor Cyan

# Ensure underlying scripts exist (download if missing, normalize endings).
$psEvent = Join-Path $psDir "reenable-defender.ps1"
$psSvc   = Join-Path $psDir "watchdog-service.ps1"
foreach ($p in @($psEvent, $psSvc)) {
    if (-not (Test-Path $p)) {
        $name = Split-Path -Leaf $p
        try {
            Invoke-WebRequest "$base/$name" -OutFile $p -UseBasicParsing
            Guard-NormalizeLineEndings -Path $p
            Write-Host "  Fetched + normalized: $name" -ForegroundColor Green
        } catch {
            Write-Host "  [!!] $name: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Guard-NormalizeLineEndings -Path $p
    }
}

if (-not ((Test-Path $psEvent) -and (Test-Path $psSvc))) {
    Write-Host "Cannot register -- underlying scripts missing." -ForegroundColor Red
    return
}

Write-Host "Registering Defender-Guard watchers..." -ForegroundColor Yellow
$eventTrigger = [string]::Join([Environment]::NewLine, @(
    '<EventTrigger>'
    '  <Subscription>Microsoft-Windows-Windows Defender/Operational</Subscription>'
    '  <Delay>PT0S</Delay>'
    '  <Enabled>true</Enabled>'
    '</EventTrigger>'
))
$bootTrigger = '<BootTrigger><Enabled>true</Enabled></BootTrigger>'
Register-GuardTask -Name "Defender-Guard-Event-Watch"   -Script $psEvent -TriggerXml $eventTrigger
Register-GuardTask -Name "Defender-Guard-Service-Watch" -Script $psSvc   -TriggerXml $bootTrigger

Write-Host ""
Write-Host "Done. Verify: Get-ScheduledTask | Where-Object { `$_.TaskName -like 'Defender-Guard-*' }" -ForegroundColor Cyan
