# install-watcher.ps1 - thin wrapper that only re-registers the watchers.
# Use this if you already ran install.ps1 once and just want to re-register
# the two Scheduled Tasks (e.g., after task corruption or schema updates).
# For first-time install, use install.ps1 which calls everything.
#
# Run elevated.

$ErrorActionPreference = "Stop"
$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$helpers = Join-Path $here "_install-helpers.ps1"
$psDir   = "C:\Program Files\Sysinternals"

if (-not (Test-Path $helpers)) {
    Write-Host "ERROR: $helpers not found. Re-download from the repo." -ForegroundColor Red
    return
}
. $helpers

Write-Host "=== Defender-Guard watcher re-registration ===" -ForegroundColor Cyan
Assert-Admin

# Ensure the underlying scripts are present (fetch if missing).
$base = "https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar"
Get-GuardScript -psDir $psDir -base $base -name "reenable-defender.ps1" | Out-Null
Get-GuardScript -psDir $psDir -base $base -name "watchdog-service.ps1"  | Out-Null

Install-GuardWatchers -psDir $psDir
Show-GuardFinal -binDir "C:\Program Files (x86)\ossec-agent\active-response\bin" -psDir $psDir
