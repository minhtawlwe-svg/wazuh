# install.ps1 - Defender-Guard Active Response one-line installer
# Downloads the AR scripts from GitHub and places them in the correct folders.
#
# One-liner (run in an ELEVATED PowerShell):
#   irm https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar/install.ps1 | iex

$ErrorActionPreference = "Stop"
$base   = "https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar"
$binDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$psDir  = "C:\Program Files\Sysinternals"

Write-Host "=== Defender-Guard AR installer ===" -ForegroundColor Cyan

# 1. must be admin (writing under Program Files)
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: run this in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
    return
}

# 2. sanity check: is the Wazuh agent installed?
if (-not (Test-Path $binDir)) {
    Write-Host "ERROR: Wazuh agent AR folder not found:`n  $binDir" -ForegroundColor Red
    Write-Host "Install the Wazuh agent first, then re-run." -ForegroundColor Red
    return
}

# 3. ensure ps1 destination exists
if (-not (Test-Path $psDir)) { New-Item -ItemType Directory -Path $psDir -Force | Out-Null }

# 4. download the four files
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Write-Host "Downloading reenable-defender.cmd ..." -ForegroundColor Yellow
Invoke-WebRequest "$base/reenable-defender.cmd"   -OutFile "$binDir\reenable-defender.cmd"   -UseBasicParsing
Write-Host "Downloading reenable-defender.ps1 ..." -ForegroundColor Yellow
Invoke-WebRequest "$base/reenable-defender.ps1"   -OutFile "$psDir\reenable-defender.ps1"    -UseBasicParsing
Write-Host "Downloading watchdog-service.ps1 ..."  -ForegroundColor Yellow
Invoke-WebRequest "$base/watchdog-service.ps1"    -OutFile "$psDir\watchdog-service.ps1"     -UseBasicParsing
Write-Host "Downloading install-watcher.ps1 ..."   -ForegroundColor Yellow
Invoke-WebRequest "$base/install-watcher.ps1"     -OutFile "$psDir\install-watcher.ps1"      -UseBasicParsing

# 5. verify
$ok1 = Test-Path "$binDir\reenable-defender.cmd"
$ok2 = Test-Path "$psDir\reenable-defender.ps1"
$ok3 = Test-Path "$psDir\watchdog-service.ps1"
$ok4 = Test-Path "$psDir\install-watcher.ps1"
Write-Host ""
Write-Host ("  {0}  {1}\reenable-defender.cmd" -f $(if($ok1){"[OK]"}else{"[!!]"}), $binDir)
Write-Host ("  {0}  {1}\reenable-defender.ps1" -f $(if($ok2){"[OK]"}else{"[!!]"}), $psDir)
Write-Host ("  {0}  {1}\watchdog-service.ps1"  -f $(if($ok3){"[OK]"}else{"[!!]"}), $psDir)
Write-Host ("  {0}  {1}\install-watcher.ps1"   -f $(if($ok4){"[OK]"}else{"[!!]"}), $psDir)

if ($ok1 -and $ok2 -and $ok3 -and $ok4) {
    Write-Host "`nAgent side installed." -ForegroundColor Green
    Write-Host "Next:" -ForegroundColor Cyan
    Write-Host "  1. (recommended) Register instant watchers — fires on FIRST disable, no manager round-trip:" -ForegroundColor Cyan
    Write-Host "       powershell -ExecutionPolicy Bypass -File `"$psDir\install-watcher.ps1`"" -ForegroundColor Cyan
    Write-Host "       Registers TWO tasks: Defender-Guard-Event-Watch + Defender-Guard-Service-Watch" -ForegroundColor Cyan
    Write-Host "  2. Add the <command>/<active-response> blocks on the MANAGER (see README section 3)." -ForegroundColor Cyan
    Write-Host "  3. Restart-Service WazuhSvc" -ForegroundColor Cyan
} else {
    Write-Host "`nInstall incomplete - check the [!!] lines above." -ForegroundColor Red
}
