# install-watcher.ps1 - thin wrapper that only re-registers the watchers.
# Use this if you already ran install.ps1 once and just want to re-register
# the two Scheduled Tasks (e.g., after task corruption or schema updates).
# For first-time install, use install.ps1 which calls everything.
#
# Run elevated.
#
# Invoke safely (here-string parsing requires on-disk file):
#   irm .../install-watcher.ps1 -OutFile $env:TEMP\iw.ps1; & "$env:TEMP\iw.ps1"

$ErrorActionPreference = "Stop"
$script:GuardRepoUrl  = "https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar"
$psDir   = "C:\Program Files\Sysinternals"

# Streamed via iex? Materialize + re-exec.
if ($MyInvocation.MyCommand.Path -notlike '?:\*' -and $MyInvocation.MyCommand.Path -notlike '\\*\*') {
    $tmp = Join-Path $env:TEMP "defender-guard-install-watcher.ps1"
    Write-Host "[bootstrap] re-launching from disk: $tmp" -ForegroundColor DarkYellow
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest "$script:GuardRepoUrl/install-watcher.ps1" -OutFile $tmp -UseBasicParsing
    } catch {
        Write-Host "ERROR: self-download failed ($($_.Exception.Message))" -ForegroundColor Red
        return
    }
    & $tmp @args
    return
}

$here    = Split-Path -Parent $MyInvocation.MyCommand.Path
$helpers = Join-Path $here "_install-helpers.ps1"
if (-not (Test-Path $helpers)) {
    Write-Host "ERROR: $helpers not found. Re-download from the repo." -ForegroundColor Red
    return
}
. $helpers

Write-Host "=== Defender-Guard watcher re-registration ===" -ForegroundColor Cyan
Assert-Admin

# Ensure the underlying scripts are present (fetch if missing).
Get-GuardScript -psDir $psDir -base $script:GuardRepoUrl -name "reenable-defender.ps1" | Out-Null
Get-GuardScript -psDir $psDir -base $script:GuardRepoUrl -name "watchdog-service.ps1"  | Out-Null

Install-GuardWatchers -psDir $psDir
Show-GuardFinal -binDir "C:\Program Files (x86)\ossec-agent\active-response\bin" -psDir $psDir
