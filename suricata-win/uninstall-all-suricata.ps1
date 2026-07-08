#Requires -RunAsAdministrator
# ============================================================================
# Uninstall EVERYTHING Suricata-related - both the IDS deployment and the
# experimental IPS (WinDivert) build
# ============================================================================
# Removes:
#   1. The regular IDS-mode Suricata install (agb-full-setup.ps1's work) -
#      by downloading and running agb-full-uninstall.ps1, so there is one
#      single source of truth for that logic rather than a duplicate copy.
#   2. The experimental IPS build (build-suricata-ips.ps1's work) - the
#      deploy folder, the MSYS2 build workspace, the Defender exclusion,
#      and the WinDivert kernel driver if it was ever registered (it only
#      registers the first time --windivert actually runs).
#
#   iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/uninstall-all-suricata.ps1 -UseBasicParsing | iex
#
# KEEPS by default: Npcap, MSYS2 itself (a general dev toolchain, not
# Suricata-specific), and the Wazuh agent.
#   -AlsoRemoveNpcap    also uninstall Npcap (interactive)
#   -AlsoRemoveMsys2    also delete C:\msys64 entirely (the WHOLE toolchain,
#                       not just the Suricata build workspace inside it -
#                       only pass this if you installed MSYS2 solely for
#                       this build and don't want it for anything else)
#   -RemoveWazuhAgent   also uninstall the Wazuh agent (rare)
#   -WhatIfOnly         list what WOULD be removed, change nothing
# ============================================================================
[CmdletBinding()]
param(
    [switch]$AlsoRemoveNpcap,
    [switch]$AlsoRemoveMsys2,
    [switch]$RemoveWazuhAgent,
    [switch]$WhatIfOnly,
    [string]$DeployRoot = "C:\SuricataIPS",
    [string]$IpsWorkRoot = "C:\msys64\suricata-ips-build"
)

# GOTCHA: the build workspace default path changed (2026-07-06) from
# C:\msys64\home\<username>\suricata-ips-build to the fixed
# C:\msys64\suricata-ips-build above, because autotools-based builds
# (Suricata's ./configure/make) break on paths containing spaces, and a
# Windows username with a space in it (a very ordinary real name, e.g.
# "Tin Aung Cho") silently broke the whole build. Check the OLD
# convention too so builds from before this fix still get cleaned up.
$IpsWorkRootLegacy = "C:\msys64\home\$env:USERNAME\suricata-ips-build"

$ErrorActionPreference = 'Continue'
function Log($m) { Write-Host "[uninstall-all] $m" -ForegroundColor Cyan }
function Act($m) { if ($WhatIfOnly) { Write-Host "  WOULD: $m" -ForegroundColor Yellow } else { Write-Host "  $m" } }
function Warn($m) { Write-Host "[uninstall-all] WARN: $m" -ForegroundColor Yellow }

# GOTCHA: Windows can't fully delete a directory that's the current
# process's working directory - if this script is run from inside
# $DeployRoot or $IpsWorkRoot (e.g. "cd C:\SuricataIPS" then running the
# uninstaller from there), Remove-Item -Recurse -Force silently only
# partially completes: file contents get removed but the top-level folder
# itself remains, and the final POST-CLEAN report still shows it present.
# cd out to somewhere safe first if that's the case.
$cwd = (Get-Location).Path
foreach ($protectedPath in @($DeployRoot, $IpsWorkRoot, $IpsWorkRootLegacy)) {
    if ($cwd -eq $protectedPath -or $cwd.StartsWith("$protectedPath\", [StringComparison]::OrdinalIgnoreCase)) {
        Warn "Current directory ($cwd) is inside a folder this script is about to delete - moving to $env:TEMP first so the delete can fully complete."
        Set-Location $env:TEMP
        break
    }
}

# ----------------------------------------------------------------------
# INLINE IDS-mode cleanup fallback - a self-contained mirror of the core
# of agb-full-uninstall.ps1, used ONLY when neither a local copy nor a
# fresh download of that script is available (e.g. offline, or GitHub
# rate-limiting the raw download with a 429 - which is exactly what left
# the IDS half silently un-cleaned before this was added). Kept as a
# subset deliberately: it covers every artifact agb-full-setup.ps1
# creates, so nothing is ever left behind even with no network at all.
# ----------------------------------------------------------------------
function Invoke-IdsCleanupInline {
    Log "running BUILT-IN IDS cleanup (no external script needed)"
    # 1. service
    $svc = Get-Service Suricata -EA SilentlyContinue
    if ($svc) { Act "stop+delete service Suricata (status $($svc.Status))"; if (-not $WhatIfOnly) { Stop-Service Suricata -Force -EA SilentlyContinue; Start-Sleep 2; & sc.exe delete Suricata | Out-Null } }
    # 2. stray process
    $proc = Get-Process suricata -EA SilentlyContinue
    if ($proc) { Act "kill suricata.exe (pid $($proc.Id -join ','))"; if (-not $WhatIfOnly) { $proc | Stop-Process -Force -EA SilentlyContinue } }
    # 3. MSI uninstall entries
    $uns = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Suricata' }
    foreach ($u in $uns) { $code = Split-Path $u.PSPath -Leaf; Act "uninstall MSI '$($u.DisplayName)' ($code)"; if (-not $WhatIfOnly) { Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait } }
    # 4. scheduled tasks (both Suricata's own + AGB-Suricata-Rules-Deploy)
    Get-ScheduledTask -EA SilentlyContinue | Where-Object { $_.TaskName -match 'Suricata' } | ForEach-Object { Act "remove scheduled task '$($_.TaskName)'"; if (-not $WhatIfOnly) { Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -EA SilentlyContinue } }
    # 5. directories (also removes agb-white/agb-black rules + deploy script + logs living under them)
    foreach ($d in @('C:\Program Files\Suricata','C:\Program Files (x86)\Suricata','C:\ProgramData\Suricata',"$env:USERPROFILE\AppData\Local\Programs\Suricata")) {
        if (Test-Path -LiteralPath $d) { $sz = (Get-ChildItem $d -Recurse -EA SilentlyContinue | Measure-Object Length -Sum).Sum; Act "delete $d ($([math]::Round($sz/1MB,1)) MB)"; if (-not $WhatIfOnly) { Remove-Item $d -Recurse -Force -EA SilentlyContinue } }
    }
    # 6. Active Response scripts in the Wazuh agent bin
    $arBin = "C:\Program Files (x86)\ossec-agent\active-response\bin"
    foreach ($f in @("agb-kill-block.ps1","agb-kill-block.cmd")) { $p = Join-Path $arBin $f; if (Test-Path $p) { Act "remove $p"; if (-not $WhatIfOnly) { Remove-Item $p -Force -EA SilentlyContinue } } }
    # 7. eve.json <localfile> out of ossec.conf (+ restart agent)
    $conf = @('C:\Program Files (x86)\ossec-agent\ossec.conf','C:\Program Files\ossec-agent\ossec.conf') | Where-Object { Test-Path $_ } | Select-Object -First 1
    if ($conf) {
        $c = Get-Content -LiteralPath $conf -Raw -EA SilentlyContinue
        if ($c) {
            $n = [regex]::Replace($c, "(?is)[ \t]*<localfile>(?:(?!</localfile>).)*?eve\.json(?:(?!</localfile>).)*?</localfile>\s*", "`r`n")
            if ($n -ne $c) { Act "strip eve.json <localfile> from ossec.conf + restart WazuhSvc"; if (-not $WhatIfOnly) { Copy-Item $conf "$conf.bak-deepclean-$(Get-Date -Format yyyyMMddHHmmss)" -Force; [IO.File]::WriteAllText($conf, $n, (New-Object Text.UTF8Encoding($false))); Restart-Service WazuhSvc -EA SilentlyContinue } }
        } else { Warn "could not read $conf (locked or permission) - skipping eve.json localfile strip" }
    }
    # 8. Defender exclusions + Suricata/AGB firewall rules
    try { (Get-MpPreference -EA SilentlyContinue).ExclusionPath | Where-Object { $_ -match 'Suricata' } | ForEach-Object { Act "remove Defender exclusion $_"; if (-not $WhatIfOnly) { Remove-MpPreference -ExclusionPath $_ -EA SilentlyContinue } } } catch {}
    Get-NetFirewallRule -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Suricata' -or $_.DisplayName -match '^AGB-BLOCK-' } | ForEach-Object { Act "remove firewall rule '$($_.DisplayName)'"; if (-not $WhatIfOnly) { Remove-NetFirewallRule -Name $_.Name -EA SilentlyContinue } }
    # 9/10. optional Npcap / Wazuh agent
    if ($AlsoRemoveNpcap) { $np = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Npcap' } | Select-Object -First 1; if ($np.UninstallString) { Act "uninstall Npcap (interactive)"; if (-not $WhatIfOnly) { Start-Process $np.UninstallString -Wait } } } else { Log "keeping Npcap (pass -AlsoRemoveNpcap to remove)" }
    if ($RemoveWazuhAgent) { $wa = Get-ItemProperty 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Wazuh' } | Select-Object -First 1; if ($wa) { $code = Split-Path $wa.PSPath -Leaf; Act "uninstall Wazuh agent '$($wa.DisplayName)'"; if (-not $WhatIfOnly) { Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait } } } else { Log "keeping Wazuh agent (pass -RemoveWazuhAgent to remove)" }
    Log "built-in IDS cleanup done"
}

Write-Host "===== PART 1/2: IDS-mode Suricata =====" -ForegroundColor Green
# Robust 3-tier strategy so the IDS half ALWAYS runs, even offline / when
# GitHub 429-rate-limits the raw download (which used to silently skip it):
#   1. a local copy of agb-full-uninstall.ps1 sitting next to this script
#      (i.e. run from a repo clone) - preferred, always current, no network
#   2. otherwise download it from GitHub, retrying a few times on transient
#      failures (429s clear quickly)
#   3. if BOTH fail, fall back to the self-contained Invoke-IdsCleanupInline
#      above - covers every IDS artifact with zero network dependency
$Base = "https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win"
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$idsArgs = @()
if ($AlsoRemoveNpcap) { $idsArgs += "-AlsoRemoveNpcap" }
if ($RemoveWazuhAgent) { $idsArgs += "-RemoveWazuhAgent" }
if ($WhatIfOnly) { $idsArgs += "-WhatIfOnly" }

# GOTCHA FIXED: $PSScriptRoot is EMPTY on an `iwr | iex` run (the script
# isn't a file on disk), and Join-Path throws "empty string" on it - which
# broke both the local-copy AND download tiers, forcing every piped run
# straight to the inline fallback. Only build the local path when
# $PSScriptRoot is actually set (a run-from-file / repo-clone invocation).
$localCopy = if ($PSScriptRoot) { Join-Path $PSScriptRoot 'agb-full-uninstall.ps1' } else { $null }
$ran = $false
if ($localCopy -and (Test-Path $localCopy)) {
    Log "using local agb-full-uninstall.ps1 next to this script (no download needed)"
    & powershell.exe -ExecutionPolicy Bypass -File $localCopy @idsArgs
    $ran = $true
} else {
    $Tmp = "$env:TEMP\agb-uninstall-all"; New-Item -ItemType Directory -Path $Tmp -Force | Out-Null
    $idsUninstaller = "$Tmp\agb-full-uninstall.ps1"
    for ($try = 1; $try -le 3 -and -not $ran; $try++) {
        try {
            Invoke-WebRequest -Uri "$Base/agb-full-uninstall.ps1" -OutFile $idsUninstaller -UseBasicParsing
            & powershell.exe -ExecutionPolicy Bypass -File $idsUninstaller @idsArgs
            $ran = $true
        } catch {
            Warn "download of agb-full-uninstall.ps1 failed (attempt $try/3): $($_.Exception.Message)"
            if ($try -lt 3) { Start-Sleep -Seconds 5 }
        }
    }
}
if (-not $ran) {
    Warn "could not obtain agb-full-uninstall.ps1 (offline / GitHub rate-limited) - using the BUILT-IN cleanup instead so the IDS half still fully runs"
    Invoke-IdsCleanupInline
}

Write-Host "`n===== PART 2/2: Experimental IPS (WinDivert) build =====" -ForegroundColor Green

# ---------- 0. daily rule-refresh scheduled tasks ----------
foreach ($taskName in @("AGB-Suricata-IPS-ET-Refresh", "AGB-Suricata-IPS-Rules-Deploy")) {
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        Act "remove scheduled task '$taskName'"
        if (-not $WhatIfOnly) { Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue }
    }
}

# ---------- 0.5. SuricataIPS Windows service, if ever installed (either via the
# standalone install-suricata-ips-service.ps1, or build-suricata-ips.ps1's
# -InstallService flag - both register under this same name) ----------
$ipsSvc = Get-Service -Name "SuricataIPS" -ErrorAction SilentlyContinue
if ($ipsSvc) {
    Act "stop + delete Windows service 'SuricataIPS' (status $($ipsSvc.Status)) - the always-on inline-blocking service"
    if (-not $WhatIfOnly) {
        if ($ipsSvc.Status -eq 'Running') { Stop-Service -Name "SuricataIPS" -Force -ErrorAction SilentlyContinue }
        & sc.exe delete "SuricataIPS" | Out-Null
    }
}

# ---------- 1. WinDivert kernel driver, if it was ever registered ----------
# WinDivert self-installs a kernel driver the FIRST time --windivert is
# actually run (not just built) - typically registered as service name
# "WinDivert" or "WinDivert1.4" depending on version. No-ops harmlessly if
# it was never used.
foreach ($svcName in @("WinDivert", "WinDivert1.4", "WinDivert1.2")) {
    $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
    if ($svc) {
        Act "stop + delete WinDivert kernel driver service '$svcName' (status $($svc.Status))"
        if (-not $WhatIfOnly) {
            # GOTCHA: Stop-Service can throw "Cannot open X service" for a
            # KERNEL_DRIVER-type service even with -ErrorAction
            # SilentlyContinue - the underlying exception isn't always
            # routed through PowerShell's normal error-record pipeline, so
            # the -ErrorAction parameter doesn't reliably suppress it.
            # sc.exe stop (used successfully elsewhere in this repo for
            # the same driver) handles kernel drivers correctly; try/catch
            # as a second layer of safety since deleting it right after
            # works regardless of whether the stop itself succeeded.
            try { & sc.exe stop $svcName 2>&1 | Out-Null } catch {}
            Start-Sleep -Milliseconds 500
            & sc.exe delete $svcName | Out-Null
        }
    }
}

# ---------- 1.5. Wazuh agent eve.json wiring, if build-suricata-ips.ps1 added it ----------
$ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
$eveLocation = "$DeployRoot\log\eve.json"
if (Test-Path $ossecConf) {
    $content = Get-Content $ossecConf -Raw
    if ($content -match [regex]::Escape($eveLocation)) {
        Act "remove the <localfile> entry for $eveLocation from ossec.conf and restart the Wazuh agent"
        if (-not $WhatIfOnly) {
            $backupPath = "$ossecConf.bak-ips-uninstall-$(Get-Date -Format yyyyMMdd-HHmmss)"
            Copy-Item $ossecConf $backupPath -Force
            $pattern = "(?s)\s*<localfile>\s*<log_format>json</log_format>\s*<location>$([regex]::Escape($eveLocation))</location>\s*</localfile>"
            $patched = [regex]::Replace($content, $pattern, "")
            Set-Content -Path $ossecConf -Value $patched -NoNewline
            try { Restart-Service -Name WazuhSvc -ErrorAction Stop } catch { Warn "could not restart WazuhSvc - restart it manually" }
        }
    } else {
        Log "no IPS eve.json wiring found in ossec.conf"
    }
} else {
    Log "no Wazuh agent found - nothing to unwire"
}

# ---------- 2. IPS deploy folder ----------
if (Test-Path $DeployRoot) {
    $sz = (Get-ChildItem $DeployRoot -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Act "delete $DeployRoot ($([math]::Round($sz/1MB,1)) MB) - the built suricata.exe, runtime DLLs, suricata.yaml, and drop-converted rules"
    if (-not $WhatIfOnly) { Remove-Item $DeployRoot -Recurse -Force -ErrorAction SilentlyContinue }
} else {
    Log "no IPS deploy folder at $DeployRoot"
}

# ---------- 3. IPS build workspace (source, WinDivert zip, Npcap SDK, Rust target dir) ----------
foreach ($workPath in @($IpsWorkRoot, $IpsWorkRootLegacy) | Select-Object -Unique) {
    if (Test-Path $workPath) {
        $sz = (Get-ChildItem $workPath -Recurse -ErrorAction SilentlyContinue -File | Measure-Object Length -Sum).Sum
        Act "delete $workPath ($([math]::Round($sz/1MB,1)) MB) - Suricata source tree, Rust build cache, WinDivert/Npcap SDK downloads"
        if (-not $WhatIfOnly) { Remove-Item $workPath -Recurse -Force -ErrorAction SilentlyContinue }
    } else {
        Log "no IPS build workspace at $workPath"
    }
}

# ---------- 4. MSYS2 itself (opt-in only - it's a general dev toolchain) ----------
if ($AlsoRemoveMsys2) {
    if (Test-Path 'C:\msys64') {
        Act "delete C:\msys64 entirely (the whole MSYS2 toolchain, not just the Suricata build)"
        if (-not $WhatIfOnly) { Remove-Item 'C:\msys64' -Recurse -Force -ErrorAction SilentlyContinue }
    }
} else {
    Log "keeping MSYS2 (C:\msys64) - pass -AlsoRemoveMsys2 to remove the whole toolchain"
}

# ---------- 5. Defender exclusion for C:\msys64 ----------
# Only remove this if MSYS2 itself is also being removed - if MSYS2 stays,
# the exclusion still has a legitimate reason to exist (rebuilding this or
# any other MSYS2 project would hit the same AV false positives again).
if ($AlsoRemoveMsys2) {
    try {
        $exclusions = (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath
        if ($exclusions -contains 'C:\msys64') {
            Act "remove Defender exclusion for C:\msys64"
            if (-not $WhatIfOnly) { Remove-MpPreference -ExclusionPath 'C:\msys64' -ErrorAction SilentlyContinue }
        }
    } catch {}
} else {
    Log "keeping Defender exclusion for C:\msys64 (MSYS2 itself was kept)"
}

# ---------- report ----------
Write-Host ""
Log "================ POST-CLEAN STATE ================"
"  IPS deploy folder ($DeployRoot)     : " + (Test-Path $DeployRoot)
"  IPS build workspace                 : " + ((Test-Path $IpsWorkRoot) -or (Test-Path $IpsWorkRootLegacy))
"  IPS scheduled tasks remaining       : " + ((@("AGB-Suricata-IPS-ET-Refresh","AGB-Suricata-IPS-Rules-Deploy") | Where-Object { Get-ScheduledTask -TaskName $_ -ErrorAction SilentlyContinue }) -join ', ')
"  MSYS2 (C:\msys64) kept              : " + (Test-Path 'C:\msys64')
"  WinDivert driver services remaining : " + ((@("WinDivert","WinDivert1.4","WinDivert1.2") | Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }) -join ', ')
"  SuricataIPS service kept            : " + [bool](Get-Service -Name "SuricataIPS" -ErrorAction SilentlyContinue)
"  Npcap kept                          : " + [bool](Get-Service npcap -ErrorAction SilentlyContinue)
"  Wazuh agent kept                    : " + [bool](Get-Service WazuhSvc -ErrorAction SilentlyContinue)
if ($WhatIfOnly) { Log "WhatIf only - nothing was changed." } else { Log "ALL SURICATA (IDS + IPS) UNINSTALL DONE." }
