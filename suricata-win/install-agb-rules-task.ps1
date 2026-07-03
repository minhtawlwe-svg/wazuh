# ============================================================================
# AGB Suricata rules - fleet install (run ONCE per agent, as Administrator)
# ============================================================================
# Self-contained: downloads deploy-agb-rules.ps1 from GitHub into a local
# folder, then registers a daily 1:30 PM Scheduled Task (as SYSTEM) that
# pulls the latest agb-white.rules/agb-black.rules and deploys them.
# No git, no credentials, no local repo clone needed on the target agent.
#
# One-liner to run this on ANY agent (elevated PowerShell):
#   iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/install-agb-rules-task.ps1 -UseBasicParsing | iex
# ============================================================================

$ErrorActionPreference = "Stop"
$ScriptsDir = "C:\ProgramData\Suricata\agb-scripts"
$ScriptUrl  = "https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/deploy-agb-rules.ps1"
$LocalScript = "$ScriptsDir\deploy-agb-rules.ps1"

if (-not (Test-Path $ScriptsDir)) { New-Item -ItemType Directory -Path $ScriptsDir -Force | Out-Null }

Write-Host "[*] Downloading deploy-agb-rules.ps1 from GitHub..."
Invoke-WebRequest -Uri $ScriptUrl -OutFile $LocalScript -UseBasicParsing
Write-Host "[+] Saved to $LocalScript"

$Action    = New-ScheduledTaskAction -Execute "powershell.exe" `
               -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$LocalScript`""
$Trigger   = New-ScheduledTaskTrigger -Daily -At 1:30PM
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd

Register-ScheduledTask -TaskName "AGB-Suricata-Rules-Deploy" `
    -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings `
    -Description "Daily 1:30 PM: pull agb-white.rules/agb-black.rules from GitHub and deploy to Suricata" `
    -Force | Out-Null

Write-Host "[+] Scheduled task 'AGB-Suricata-Rules-Deploy' registered - runs daily at 1:30 PM as SYSTEM"
Get-ScheduledTask -TaskName "AGB-Suricata-Rules-Deploy" | Select TaskName, State

Write-Host "`n[*] Running an initial deploy now to verify..."
& $LocalScript
