# ============================================================================
# AGB Suricata - FULL fleet setup (one command, any agent)
# ============================================================================
# Combines the base Suricata installer with the agb-white/agb-black rules
# auto-deploy setup. Run once, elevated, on any agent:
#
#   iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-setup.ps1 -UseBasicParsing | iex
#
# INTERACTIVE by default - prompts for capture interface AND HOME_NET (press
# Enter on either to auto-pick/keep the stock default instead of typing a
# value). Pass -NoPrompt to skip both prompts and auto-pick everything, or
# -CaptureInterfaceName/-HomeNet to pre-supply either value non-interactively.
#
# Order matters: suricata-install.ps1 (re)writes suricata.yaml's rule-files
# to just the base merged ruleset, so it must run FIRST. The agb rules
# installer then appends agb-white.rules/agb-black.rules and registers the
# daily 1:30 PM pull-deploy task.
# ============================================================================
param(
    [switch]$NoPrompt,
    [string]$CaptureInterfaceName = '',
    [string]$HomeNet = ''
)

$ErrorActionPreference = "Stop"
$Base = "https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win"
$Tmp  = "$env:TEMP\agb-suricata-setup"
New-Item -ItemType Directory -Path $Tmp -Force | Out-Null

Write-Host "===== STEP 1/2: Base Suricata install =====" -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$installer = "$Tmp\suricata-install.ps1"
Invoke-WebRequest -Uri "$Base/suricata-install.ps1" -OutFile $installer -UseBasicParsing

$installArgs = @()
if ($NoPrompt) { $installArgs += "-NoPrompt" }
if ($CaptureInterfaceName) { $installArgs += @("-CaptureInterfaceName", $CaptureInterfaceName) }
if ($HomeNet) { $installArgs += @("-HomeNet", $HomeNet) }

& powershell.exe -ExecutionPolicy Bypass -File $installer @installArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "[!] Base Suricata install reported a non-zero exit - continuing to agb rules setup anyway (check output above)" -ForegroundColor Yellow
}

Write-Host "`n===== STEP 2/2: AGB whitelist/blacklist rules + daily auto-deploy =====" -ForegroundColor Cyan
$agbInstaller = "$Tmp\install-agb-rules-task.ps1"
Invoke-WebRequest -Uri "$Base/install-agb-rules-task.ps1" -OutFile $agbInstaller -UseBasicParsing
& powershell.exe -ExecutionPolicy Bypass -File $agbInstaller

# The nested child powershell.exe above can occasionally lose the parent's
# elevation context (Windows-version-dependent), which used to make
# Register-ScheduledTask fail silently. Verify here and self-heal by
# re-running install-agb-rules-task.ps1 directly (not nested) if needed.
if (-not (Get-ScheduledTask -TaskName "AGB-Suricata-Rules-Deploy" -ErrorAction SilentlyContinue)) {
    Write-Host "[!] Scheduled task not found after step 2 - retrying directly (non-nested)..." -ForegroundColor Yellow
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "& '$agbInstaller'"
    if (-not (Get-ScheduledTask -TaskName "AGB-Suricata-Rules-Deploy" -ErrorAction SilentlyContinue)) {
        Write-Host "[!] Still not registered. Run this directly yourself in an elevated PowerShell:" -ForegroundColor Red
        Write-Host "    iwr $Base/install-agb-rules-task.ps1 -UseBasicParsing | iex" -ForegroundColor Red
    }
}

Write-Host "`n===== AGB full setup complete =====" -ForegroundColor Green
Write-Host "Suricata installed + agb-white.rules/agb-black.rules deploying daily at 1:30 PM from GitHub."
