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
    [string]$IpsWorkRoot = "C:\msys64\home\$env:USERNAME\suricata-ips-build"
)

$ErrorActionPreference = 'Continue'
function Log($m) { Write-Host "[uninstall-all] $m" -ForegroundColor Cyan }
function Act($m) { if ($WhatIfOnly) { Write-Host "  WOULD: $m" -ForegroundColor Yellow } else { Write-Host "  $m" } }
function Warn($m) { Write-Host "[uninstall-all] WARN: $m" -ForegroundColor Yellow }

Write-Host "===== PART 1/2: IDS-mode Suricata (agb-full-uninstall.ps1) =====" -ForegroundColor Green
# Downloaded and run rather than duplicated here, so this always matches
# whatever the real IDS uninstaller currently does - no risk of the two
# drifting apart over time.
$Base = "https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win"
$Tmp  = "$env:TEMP\agb-uninstall-all"
New-Item -ItemType Directory -Path $Tmp -Force | Out-Null
[Net.ServicePointManager]::SecurityProtocol = 'Tls12'
$idsUninstaller = "$Tmp\agb-full-uninstall.ps1"
try {
    Invoke-WebRequest -Uri "$Base/agb-full-uninstall.ps1" -OutFile $idsUninstaller -UseBasicParsing
    $idsArgs = @()
    if ($AlsoRemoveNpcap) { $idsArgs += "-AlsoRemoveNpcap" }
    if ($RemoveWazuhAgent) { $idsArgs += "-RemoveWazuhAgent" }
    if ($WhatIfOnly) { $idsArgs += "-WhatIfOnly" }
    & powershell.exe -ExecutionPolicy Bypass -File $idsUninstaller @idsArgs
} catch {
    Warn "Could not run agb-full-uninstall.ps1 ($($_.Exception.Message)) - skipping IDS-mode cleanup, continuing with IPS cleanup"
}

Write-Host "`n===== PART 2/2: Experimental IPS (WinDivert) build =====" -ForegroundColor Green

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
            Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue
            & sc.exe delete $svcName | Out-Null
        }
    }
}

# ---------- 2. IPS deploy folder ----------
if (Test-Path $DeployRoot) {
    $sz = (Get-ChildItem $DeployRoot -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum
    Act "delete $DeployRoot ($([math]::Round($sz/1MB,1)) MB) - the built suricata.exe + runtime DLLs"
    if (-not $WhatIfOnly) { Remove-Item $DeployRoot -Recurse -Force -ErrorAction SilentlyContinue }
} else {
    Log "no IPS deploy folder at $DeployRoot"
}

# ---------- 3. IPS build workspace (source, WinDivert zip, Npcap SDK, Rust target dir) ----------
if (Test-Path $IpsWorkRoot) {
    $sz = (Get-ChildItem $IpsWorkRoot -Recurse -ErrorAction SilentlyContinue -File | Measure-Object Length -Sum).Sum
    Act "delete $IpsWorkRoot ($([math]::Round($sz/1MB,1)) MB) - Suricata source tree, Rust build cache, WinDivert/Npcap SDK downloads"
    if (-not $WhatIfOnly) { Remove-Item $IpsWorkRoot -Recurse -Force -ErrorAction SilentlyContinue }
} else {
    Log "no IPS build workspace at $IpsWorkRoot"
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
"  IPS build workspace                 : " + (Test-Path $IpsWorkRoot)
"  MSYS2 (C:\msys64) kept              : " + (Test-Path 'C:\msys64')
"  WinDivert driver services remaining : " + ((@("WinDivert","WinDivert1.4","WinDivert1.2") | Where-Object { Get-Service -Name $_ -ErrorAction SilentlyContinue }) -join ', ')
"  Npcap kept                          : " + [bool](Get-Service npcap -ErrorAction SilentlyContinue)
"  Wazuh agent kept                    : " + [bool](Get-Service WazuhSvc -ErrorAction SilentlyContinue)
if ($WhatIfOnly) { Log "WhatIf only - nothing was changed." } else { Log "ALL SURICATA (IDS + IPS) UNINSTALL DONE." }
