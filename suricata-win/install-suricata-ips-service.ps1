#Requires -RunAsAdministrator
# ============================================================================
# Register the Suricata IPS (WinDivert) build as a persistent Windows
# service - auto-starts on boot, runs continuously in the background
# ============================================================================
# build-suricata-ips.ps1 deliberately stops short of this - everything up
# to now has been a manual, supervised foreground test you can Ctrl+C
# instantly. THIS script is the deliberate step up to unattended, always-on
# inline traffic blocking. Read the warning this script prints before
# confirming - this is a materially bigger commitment than anything the
# build script itself does automatically.
#
#   iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/install-suricata-ips-service.ps1 -UseBasicParsing | iex
#
# Registered as its own distinct service name "SuricataIPS", NOT the
# generic "Suricata" name Suricata's own --service-install would use
# internally (PROG_NAME is a compile-time constant "Suricata", hardcoded,
# not configurable via CLI) - that name could collide with a regular
# IDS-mode Suricata service if one is ever installed on the same machine
# (agb-full-setup.ps1 doesn't currently register one as a service, but
# nothing stops a future setup from doing so). Using sc.exe directly with
# our own name avoids that collision entirely, at the cost of not using
# Suricata's built-in service control code path (its stop/shutdown signal
# handling in win32-service.c is generic Windows SCM API usage that works
# identically regardless of how the service was registered, so nothing is
# lost by doing it this way).
# ============================================================================
[CmdletBinding()]
param(
    [string]$DeployRoot   = "C:\SuricataIPS",
    [string]$WinDivertFilter = "outbound",   # same default the build script now suggests
    [string]$ServiceName  = "SuricataIPS",
    [switch]$Remove,                          # uninstall the service instead of installing it
    [switch]$Force                            # skip the interactive confirmation prompt
)

$ErrorActionPreference = "Stop"
function Log($m)  { Write-Host "[ips-service] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[ips-service] WARN: $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "[ips-service] FATAL: $m" -ForegroundColor Red; if (-not $Force) { Read-Host "Press Enter to close" | Out-Null }; exit 1 }

# ---------- Remove path ----------
if ($Remove) {
    Log "Removing service '$ServiceName'..."
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if (-not $svc) {
        Log "  not installed, nothing to do"
    } else {
        if ($svc.Status -eq 'Running') { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }
        & sc.exe delete $ServiceName | Out-Null
        Log "  removed"
    }
    if (-not $Force) { Read-Host "Press Enter to close" | Out-Null }
    exit 0
}

# ---------- Install path ----------
$exePath  = "$DeployRoot\suricata.exe"
$yamlPath = "$DeployRoot\suricata.yaml"
if (-not (Test-Path $exePath))  { Die "Suricata binary not found at $exePath - run build-suricata-ips.ps1 first" }
if (-not (Test-Path $yamlPath)) { Die "suricata.yaml not found at $yamlPath - run build-suricata-ips.ps1 without -SkipRulesSetup first" }

Write-Host ""
Write-Host "########################################################################" -ForegroundColor Red
Write-Host "#  WARNING: this registers a Windows SERVICE that auto-starts on boot   #" -ForegroundColor Red
Write-Host "#  and runs Suricata in REAL INLINE TRAFFIC-BLOCKING mode continuously, #" -ForegroundColor Red
Write-Host "#  in the background, with no window to watch or Ctrl+C.               #" -ForegroundColor Red
Write-Host "#                                                                      #" -ForegroundColor Red
Write-Host "#  Everything up to this point (build-suricata-ips.ps1) has been a     #" -ForegroundColor Red
Write-Host "#  manual, supervised test you could stop instantly. This is a real    #" -ForegroundColor Red
Write-Host "#  step up: a crash, a bad rule, or unexpected blocking behavior would #" -ForegroundColor Red
Write-Host "#  now affect this machine's network connectivity unattended, until   #" -ForegroundColor Red
Write-Host "#  you notice and run this script again with -Remove.                 #" -ForegroundColor Red
Write-Host "#                                                                      #" -ForegroundColor Red
Write-Host "#  Only do this on a machine you've already tested thoroughly, ideally #" -ForegroundColor Red
Write-Host "#  a disposable one - not a machine you depend on for daily use.       #" -ForegroundColor Red
Write-Host "########################################################################" -ForegroundColor Red
Write-Host ""
Write-Host "  Filter that will run continuously: --windivert `"$WinDivertFilter`"" -ForegroundColor Yellow
Write-Host "  Only agb-black-drop.rules' curated signatures can ever trigger a drop" -ForegroundColor Yellow
Write-Host "  (the full ET Open ruleset stays alert-only) - but this IS real, always-on" -ForegroundColor Yellow
Write-Host "  inline enforcement of whatever is in that file, refreshed daily from GitHub." -ForegroundColor Yellow
Write-Host ""

if (-not $Force) {
    $ans = Read-Host "Type YES (all caps) to confirm you understand and want to proceed"
    if ($ans -ne "YES") { Log "Not confirmed - exiting without changes."; exit 0 }
}

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($existing) {
    Log "Service '$ServiceName' already exists (status: $($existing.Status)) - removing it first for a clean reinstall"
    if ($existing.Status -eq 'Running') { Stop-Service -Name $ServiceName -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }
    & sc.exe delete $ServiceName | Out-Null
    Start-Sleep -Seconds 1
}

# sc.exe's "key= value" syntax requires the space after "=" - a well-known
# gotcha (this repo already hit binPath quoting issues once before with
# the regular MSI service, see feedback_suricata_windows_gotchas memory).
$binPath = "`"$exePath`" -c `"$yamlPath`" --windivert `"$WinDivertFilter`""
Log "Creating service '$ServiceName'..."
& sc.exe create $ServiceName binPath= $binPath start= auto DisplayName= "Suricata IPS (WinDivert, experimental)" | Out-Null
if ($LASTEXITCODE -ne 0) { Die "sc.exe create failed (exit $LASTEXITCODE) - see output above" }
& sc.exe description $ServiceName "Experimental inline-blocking Suricata build (WinDivert). Filter: $WinDivertFilter. Managed by build-suricata-ips.ps1 / install-suricata-ips-service.ps1 in minhtawlwe-svg/wazuh." | Out-Null
& sc.exe failure $ServiceName reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null

Log "Starting service..."
try {
    Start-Service -Name $ServiceName -ErrorAction Stop
    Start-Sleep -Seconds 3
    $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
    if ($svc -and $svc.Status -eq 'Running') {
        Log "SUCCESS - '$ServiceName' is running, auto-starts on boot."
        Write-Host ""
        Write-Host "To check on it:   Get-Service $ServiceName" -ForegroundColor Yellow
        Write-Host "To stop it:       Stop-Service $ServiceName" -ForegroundColor Yellow
        Write-Host "To remove it:     .\install-suricata-ips-service.ps1 -Remove" -ForegroundColor Yellow
        Write-Host "Logs still at:    $DeployRoot\log\ (fast.log / eve.json / suricata.log)" -ForegroundColor Yellow
    } else {
        Warn "Service created but did not come up Running (status: $($svc.Status)) - check $DeployRoot\log\suricata.log for why"
    }
} catch {
    Warn "Start-Service failed ($($_.Exception.Message)) - the service is registered but not running. Check $DeployRoot\log\suricata.log, then try: Start-Service $ServiceName"
}
if (-not $Force) { Read-Host "Press Enter to close" | Out-Null }
