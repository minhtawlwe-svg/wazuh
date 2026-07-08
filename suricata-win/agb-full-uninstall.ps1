#Requires -RunAsAdministrator
# ============================================================================
# AGB Suricata + Wazuh - FULL SELF-CONTAINED UNINSTALL (one file, one command)
# ============================================================================
# Removes EVERYTHING agb-full-setup.ps1 installed: Suricata (service, MSI,
# all directories including agb-white/agb-black rules and the daily
# deploy script, since they all live under the directories wiped below),
# BOTH scheduled tasks, the eve.json <localfile>, the Active Response
# scripts, Defender exclusions, and Suricata firewall rules.
#
#   iwr https://cdn.jsdelivr.net/gh/minhtawlwe-svg/wazuh@git-home/suricata-win/agb-full-uninstall.ps1 -UseBasicParsing | iex
#
# KEEPS by default: Npcap and the Wazuh AGENT itself.
#   -AlsoRemoveNpcap   also uninstall Npcap (interactive)
#   -RemoveWazuhAgent  also uninstall the Wazuh agent (rare)
#   -WhatIfOnly        list what WOULD be removed, change nothing
# ============================================================================
[CmdletBinding()]
param([switch]$AlsoRemoveNpcap,[switch]$RemoveWazuhAgent,[switch]$WhatIfOnly)
$ErrorActionPreference='Continue'
function Log($m){ Write-Host "[uninstall] $m" -ForegroundColor Cyan }
function Act($m){ if($WhatIfOnly){ Write-Host "  WOULD: $m" -ForegroundColor Yellow } else { Write-Host "  $m" } }

# 1. Suricata service ---------------------------------------------------
$svc = Get-Service Suricata -EA SilentlyContinue
if ($svc){ Act "stop+delete service Suricata (status $($svc.Status))"; if(-not $WhatIfOnly){ Stop-Service Suricata -Force -EA SilentlyContinue; Start-Sleep 2; & sc.exe delete Suricata | Out-Null } }
else { Log "no Suricata service" }

# 2. stray process --------------------------------------------------------
$proc = Get-Process suricata -EA SilentlyContinue
if ($proc){ Act "kill suricata.exe (pid $($proc.Id -join ','))"; if(-not $WhatIfOnly){ $proc | Stop-Process -Force -EA SilentlyContinue } }

# 3. MSI - every Suricata uninstall entry ----------------------------------
$uns = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue |
       Where-Object { $_.DisplayName -match 'Suricata' }
if ($uns){ foreach($u in $uns){
    $code = Split-Path $u.PSPath -Leaf
    Act "uninstall MSI '$($u.DisplayName)' ($code)"
    if(-not $WhatIfOnly){ Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait }
}} else { Log "no Suricata MSI uninstall entry" }

# 4. scheduled tasks (catches BOTH Suricata's own daily task AND
#    AGB-Suricata-Rules-Deploy - both names contain 'Suricata') -----------
Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.TaskName -match 'Suricata' } | ForEach-Object {
    Act "remove scheduled task '$($_.TaskName)'"; if(-not $WhatIfOnly){ Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -EA SilentlyContinue }
}

# 5. directories (this also removes agb-white.rules/agb-black.rules,
#    the agb-scripts\deploy-agb-rules.ps1 copy, and agb-deploy.log -
#    they all live under these paths, no separate cleanup needed) --------
$dirs = @(
  'C:\Program Files\Suricata',
  'C:\Program Files (x86)\Suricata',
  'C:\ProgramData\Suricata',
  "$env:USERPROFILE\AppData\Local\Programs\Suricata"
)
foreach($d in $dirs){ if (Test-Path -LiteralPath $d){
    $sz = (Get-ChildItem $d -Recurse -EA SilentlyContinue | Measure-Object Length -Sum).Sum
    Act "delete $d ($([math]::Round($sz/1MB,1)) MB)"
    if(-not $WhatIfOnly){ Remove-Item $d -Recurse -Force -EA SilentlyContinue; if(Test-Path $d){ Write-Host "    WARN: could not fully remove $d (in use)" -ForegroundColor Yellow } }
}}

# 6. Active Response scripts (NOT under the Suricata dirs above - live in
#    the Wazuh agent's own active-response\bin, must be removed separately) -
$arBin = "C:\Program Files (x86)\ossec-agent\active-response\bin"
foreach ($f in @("agb-kill-block.ps1","agb-kill-block.cmd")) {
    $p = Join-Path $arBin $f
    if (Test-Path $p) { Act "remove $p"; if(-not $WhatIfOnly){ Remove-Item $p -Force -EA SilentlyContinue } }
}

# 7. eve.json localfile out of ossec.conf ----------------------------------
# NOTE: this only cleans the LOCAL ossec.conf. If this agent is a member
# of a Wazuh manager GROUP that also defines an eve.json <localfile> in
# its shared agent.conf (check on the manager: agent_groups -s -i <id>),
# that group config will silently push the SAME eve.json binding right
# back on reconnect, and having it in BOTH places causes "Log file ... is
# duplicated" and unpredictable/broken log shipping (hit this for real
# 2026-07-03 - see project_c2_detection_engineering memory). This
# uninstaller has no access to the manager to fix that half.
$conf = @('C:\Program Files (x86)\ossec-agent\ossec.conf','C:\Program Files\ossec-agent\ossec.conf') | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($conf){
    $c = Get-Content -LiteralPath $conf -Raw
    $n = [regex]::Replace($c,"(?is)[ \t]*<localfile>(?:(?!</localfile>).)*?eve\.json(?:(?!</localfile>).)*?</localfile>\s*","`r`n")
    if ($n -ne $c){ Act "strip eve.json <localfile> from ossec.conf + restart WazuhSvc"
        if(-not $WhatIfOnly){ Copy-Item $conf "$conf.bak-deepclean-$(Get-Date -Format yyyyMMddHHmmss)" -Force; [IO.File]::WriteAllText($conf,$n,(New-Object Text.UTF8Encoding($false))); Restart-Service WazuhSvc -EA SilentlyContinue }
        Write-Host "[i] This only removed the LOCAL eve.json binding. If this agent belongs to a manager" -ForegroundColor Yellow
        Write-Host "    GROUP that also defines eve.json (check: agent_groups -s -i <id> on the manager)," -ForegroundColor Yellow
        Write-Host "    that shared config will push it right back on reconnect. Remove group membership" -ForegroundColor Yellow
        Write-Host "    on the manager too if you want it TRULY gone." -ForegroundColor Yellow
    } else { Log "no eve.json localfile in ossec.conf" }
}

# 8. Defender exclusions + firewall rules ----------------------------------
try {
    $exc = (Get-MpPreference -EA SilentlyContinue).ExclusionPath | Where-Object { $_ -match 'Suricata' }
    foreach($e in $exc){ Act "remove Defender exclusion $e"; if(-not $WhatIfOnly){ Remove-MpPreference -ExclusionPath $e -EA SilentlyContinue } }
} catch {}
Get-NetFirewallRule -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Suricata' } | ForEach-Object {
    Act "remove firewall rule '$($_.DisplayName)'"; if(-not $WhatIfOnly){ Remove-NetFirewallRule -Name $_.Name -EA SilentlyContinue }
}
# also remove any AGB auto-kill firewall blocks left by the Active Response
Get-NetFirewallRule -EA SilentlyContinue | Where-Object { $_.DisplayName -match '^AGB-BLOCK-' } | ForEach-Object {
    Act "remove AR firewall rule '$($_.DisplayName)'"; if(-not $WhatIfOnly){ Remove-NetFirewallRule -Name $_.Name -EA SilentlyContinue }
}

# 9. optional Npcap ---------------------------------------------------------
if ($AlsoRemoveNpcap){
    $np = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Npcap' } | Select-Object -First 1
    if ($np.UninstallString){ Act "uninstall Npcap (interactive)"; if(-not $WhatIfOnly){ Start-Process $np.UninstallString -Wait } }
} else { Log "keeping Npcap (pass -AlsoRemoveNpcap to remove)" }

# 10. optional Wazuh agent --------------------------------------------------
if ($RemoveWazuhAgent){
    $wa = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Wazuh' } | Select-Object -First 1
    if ($wa){ $code=Split-Path $wa.PSPath -Leaf; Act "uninstall Wazuh agent '$($wa.DisplayName)'"; if(-not $WhatIfOnly){ Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait } }
} else { Log "keeping Wazuh agent (pass -RemoveWazuhAgent to remove)" }

# 11. report ------------------------------------------------------------
Write-Host ""
Log "================ POST-CLEAN STATE ================"
"  Suricata service              : " + [bool](Get-Service Suricata -EA SilentlyContinue)
"  Program Files\Suricata        : " + (Test-Path 'C:\Program Files\Suricata')
"  Program Files (x86)\Suricata  : " + (Test-Path 'C:\Program Files (x86)\Suricata')
"  ProgramData\Suricata          : " + (Test-Path 'C:\ProgramData\Suricata')
"  Suricata MSI entry            : " + [bool](Get-ItemProperty 'HKLM:\SOFTWARE\*\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Suricata' })
"  AGB-Suricata-Rules-Deploy task: " + [bool](Get-ScheduledTask -TaskName 'AGB-Suricata-Rules-Deploy' -EA SilentlyContinue)
"  AR scripts in active-response : " + (Test-Path "$arBin\agb-kill-block.ps1")
"  Npcap kept                    : " + [bool](Get-Service npcap -EA SilentlyContinue)
"  Wazuh agent kept              : " + [bool](Get-Service WazuhSvc -EA SilentlyContinue)
if ($WhatIfOnly){ Log "WhatIf only - nothing was changed." } else { Log "FULL UNINSTALL DONE." }
