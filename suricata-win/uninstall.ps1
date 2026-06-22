#Requires -RunAsAdministrator
# =====================================================================
#  Remove-Suricata-DeepClean.ps1                        (2026-06-22)
#  DEEP removal of Suricata from this machine - everything:
#    - Suricata Windows service (stop + delete)
#    - any running suricata.exe
#    - the MSI (every "Suricata" uninstall entry in the registry)
#    - C:\Program Files\Suricata  AND  C:\Program Files (x86)\Suricata
#      (binaries, suricata.yaml, classification/reference configs, *.bak)
#    - C:\ProgramData\Suricata  (eve.json + rotated logs, ALL rules,
#      state, downloads, maintenance script, install/msi logs)
#    - the daily scheduled task
#    - the eve.json <localfile> from the Wazuh agent ossec.conf
#    - Suricata Defender exclusions + any Suricata firewall rules
#    - leftover Suricata folders under other common roots
#
#  KEEPS by default: Npcap (shared WinPcap driver) and the Wazuh AGENT.
#    -AlsoRemoveNpcap   also uninstall Npcap (interactive)
#    -RemoveWazuhAgent  also uninstall the Wazuh agent (rare)
#    -WhatIfOnly        list what WOULD be removed, change nothing
# =====================================================================
[CmdletBinding()]
param([switch]$AlsoRemoveNpcap,[switch]$RemoveWazuhAgent,[switch]$WhatIfOnly)
$ErrorActionPreference='Continue'
function Log($m){ Write-Host "[deep-clean] $m" -ForegroundColor Cyan }
function Act($m){ if($WhatIfOnly){ Write-Host "  WOULD: $m" -ForegroundColor Yellow } else { Write-Host "  $m" } }

# 1. service ----------------------------------------------------------
$svc = Get-Service Suricata -EA SilentlyContinue
if ($svc){ Act "stop+delete service Suricata (status $($svc.Status))"; if(-not $WhatIfOnly){ Stop-Service Suricata -Force -EA SilentlyContinue; Start-Sleep 2; & sc.exe delete Suricata | Out-Null } }
else { Log "no Suricata service" }

# 2. stray process ----------------------------------------------------
$proc = Get-Process suricata -EA SilentlyContinue
if ($proc){ Act "kill suricata.exe (pid $($proc.Id -join ','))"; if(-not $WhatIfOnly){ $proc | Stop-Process -Force -EA SilentlyContinue } }

# 3. MSI - every Suricata uninstall entry -----------------------------
$uns = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue |
       Where-Object { $_.DisplayName -match 'Suricata' }
if ($uns){ foreach($u in $uns){
    $code = Split-Path $u.PSPath -Leaf
    Act "uninstall MSI '$($u.DisplayName)' ($code)"
    if(-not $WhatIfOnly){ Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait }
}} else { Log "no Suricata MSI uninstall entry" }

# 4. scheduled task ---------------------------------------------------
foreach($tn in @('Suricata Daily Update And Log Rotation')){
    if (Get-ScheduledTask -TaskName $tn -EA SilentlyContinue){ Act "remove scheduled task '$tn'"; if(-not $WhatIfOnly){ Unregister-ScheduledTask -TaskName $tn -Confirm:$false } }
}
# any other task with 'Suricata' in the name
Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.TaskName -match 'Suricata' } | ForEach-Object {
    Act "remove scheduled task '$($_.TaskName)'"; if(-not $WhatIfOnly){ Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -EA SilentlyContinue }
}

# 5. directories ------------------------------------------------------
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

# 6. eve.json localfile out of ossec.conf -----------------------------
$conf = @('C:\Program Files (x86)\ossec-agent\ossec.conf','C:\Program Files\ossec-agent\ossec.conf') | Where-Object { Test-Path $_ } | Select-Object -First 1
if ($conf){
    $c = Get-Content -LiteralPath $conf -Raw
    $n = [regex]::Replace($c,"(?is)[ \t]*<localfile>(?:(?!</localfile>).)*?eve\.json(?:(?!</localfile>).)*?</localfile>\s*","`r`n")
    if ($n -ne $c){ Act "strip eve.json <localfile> from ossec.conf + restart WazuhSvc"
        if(-not $WhatIfOnly){ Copy-Item $conf "$conf.bak-deepclean-$(Get-Date -Format yyyyMMddHHmmss)" -Force; [IO.File]::WriteAllText($conf,$n,(New-Object Text.UTF8Encoding($false))); Restart-Service WazuhSvc -EA SilentlyContinue }
    } else { Log "no eve.json localfile in ossec.conf" }
}

# 7. Defender exclusions + firewall rules -----------------------------
try {
    $exc = (Get-MpPreference -EA SilentlyContinue).ExclusionPath | Where-Object { $_ -match 'Suricata' }
    foreach($e in $exc){ Act "remove Defender exclusion $e"; if(-not $WhatIfOnly){ Remove-MpPreference -ExclusionPath $e -EA SilentlyContinue } }
} catch {}
Get-NetFirewallRule -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Suricata' } | ForEach-Object {
    Act "remove firewall rule '$($_.DisplayName)'"; if(-not $WhatIfOnly){ Remove-NetFirewallRule -Name $_.Name -EA SilentlyContinue }
}

# 8. optional Npcap ---------------------------------------------------
if ($AlsoRemoveNpcap){
    $np = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Npcap' } | Select-Object -First 1
    if ($np.UninstallString){ Act "uninstall Npcap (interactive)"; if(-not $WhatIfOnly){ Start-Process $np.UninstallString -Wait } }
} else { Log "keeping Npcap (pass -AlsoRemoveNpcap to remove)" }

# 9. optional Wazuh agent --------------------------------------------
if ($RemoveWazuhAgent){
    $wa = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Wazuh' } | Select-Object -First 1
    if ($wa){ $code=Split-Path $wa.PSPath -Leaf; Act "uninstall Wazuh agent '$($wa.DisplayName)'"; if(-not $WhatIfOnly){ Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait } }
} else { Log "keeping Wazuh agent (pass -RemoveWazuhAgent to remove)" }

# 10. report ----------------------------------------------------------
Write-Host ""
Log "================ POST-CLEAN STATE ================"
"  Suricata service : " + [bool](Get-Service Suricata -EA SilentlyContinue)
"  Program Files\Suricata        : " + (Test-Path 'C:\Program Files\Suricata')
"  Program Files (x86)\Suricata  : " + (Test-Path 'C:\Program Files (x86)\Suricata')
"  ProgramData\Suricata          : " + (Test-Path 'C:\ProgramData\Suricata')
"  Suricata MSI entry            : " + [bool](Get-ItemProperty 'HKLM:\SOFTWARE\*\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Suricata' })
"  Npcap kept        : " + [bool](Get-Service npcap -EA SilentlyContinue)
"  Wazuh agent kept  : " + [bool](Get-Service WazuhSvc -EA SilentlyContinue)
if ($WhatIfOnly){ Log "WhatIf only - nothing was changed." } else { Log "DEEP CLEAN DONE." }
