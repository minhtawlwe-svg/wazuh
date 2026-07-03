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
# daily 1:30 PM pull-deploy task. Step 3 deploys the auto-kill Active
# Response script into the Wazuh agent's active-response\bin - the manager
# itself (rules + AR command/binding in ossec.conf) is configured
# separately, once, on the manager (see suricata-win/wazuh-manager/).
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

Write-Host "`n===== STEP 3/3: Active Response (auto-kill on confirmed blacklist hit) =====" -ForegroundColor Cyan
$ArBase = "$Base/wazuh-manager/active-response"
$AgentArBin = "C:\Program Files (x86)\ossec-agent\active-response\bin"
if (Test-Path $AgentArBin) {
    try {
        Invoke-WebRequest -Uri "$ArBase/agb-kill-block.ps1" -OutFile "$AgentArBin\agb-kill-block.ps1" -UseBasicParsing
        Invoke-WebRequest -Uri "$ArBase/agb-kill-block.cmd" -OutFile "$AgentArBin\agb-kill-block.cmd" -UseBasicParsing
        Write-Host "[+] agb-kill-block.ps1/.cmd deployed to $AgentArBin"
        Write-Host "[i] No agent restart needed - execd looks up the script by name at invocation time."
        Write-Host "[i] Manager-side (rules 100311/100313/100974/100316 + command/active-response binding in" -ForegroundColor DarkGray
        Write-Host "    ossec.conf) must still be configured ONCE on the manager - see suricata-win/wazuh-manager/" -ForegroundColor DarkGray
    } catch {
        Write-Host "[!] Failed to deploy AR scripts: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host "[!] Wazuh agent not found at $AgentArBin - skipping AR deployment (install/enroll the Wazuh agent first)" -ForegroundColor Yellow
}

Write-Host "`n===== AGB full setup complete =====" -ForegroundColor Green
Write-Host "Suricata installed + agb-white.rules/agb-black.rules deploying daily at 1:30 PM from GitHub."
Write-Host "Active Response scripts deployed (enforcement active once the manager-side rules/binding are configured)."
