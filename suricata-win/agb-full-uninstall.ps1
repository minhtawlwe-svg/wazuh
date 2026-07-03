# ============================================================================
# AGB Suricata - FULL uninstall (one command, any agent)
# ============================================================================
# Counterpart to agb-full-setup.ps1: removes the agb-white/agb-black rules
# auto-deploy (scheduled task, local scripts, rule files) AND does a deep
# clean of the base Suricata install (service, MSI, configs, rules,
# eve.json, scheduled task, Defender/firewall rules).
#
#   iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-uninstall.ps1 -UseBasicParsing | iex
#
# Pass-through switches (same as uninstall.ps1):
#   -AlsoRemoveNpcap -RemoveWazuhAgent -WhatIfOnly
# ============================================================================
param([switch]$AlsoRemoveNpcap,[switch]$RemoveWazuhAgent,[switch]$WhatIfOnly)

$ErrorActionPreference = "Stop"
$Base = "https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win"
$Tmp  = "$env:TEMP\agb-suricata-uninstall"
New-Item -ItemType Directory -Path $Tmp -Force | Out-Null
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'

Write-Host "===== STEP 1/2: Remove AGB rules auto-deploy =====" -ForegroundColor Cyan
$agbUninstaller = "$Tmp\uninstall-agb-rules.ps1"
Invoke-WebRequest -Uri "$Base/uninstall-agb-rules.ps1" -OutFile $agbUninstaller -UseBasicParsing
if ($WhatIfOnly) {
    & powershell.exe -ExecutionPolicy Bypass -File $agbUninstaller -WhatIfOnly
} else {
    & powershell.exe -ExecutionPolicy Bypass -File $agbUninstaller
}

Write-Host "`n===== STEP 2/2: Deep-clean base Suricata install =====" -ForegroundColor Cyan
$baseUninstaller = "$Tmp\uninstall.ps1"
Invoke-WebRequest -Uri "$Base/uninstall.ps1" -OutFile $baseUninstaller -UseBasicParsing
$argsList = @()
if ($AlsoRemoveNpcap) { $argsList += "-AlsoRemoveNpcap" }
if ($RemoveWazuhAgent) { $argsList += "-RemoveWazuhAgent" }
if ($WhatIfOnly) { $argsList += "-WhatIfOnly" }
& powershell.exe -ExecutionPolicy Bypass -File $baseUninstaller @argsList

Write-Host "`n===== AGB full uninstall complete$(if($WhatIfOnly){' (preview only, nothing changed)'}) =====" -ForegroundColor Green
