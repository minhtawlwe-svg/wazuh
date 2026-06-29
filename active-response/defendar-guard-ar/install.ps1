# install.ps1 - Defender-Guard Active Response: one-step installer.
#
# Downloads all files, places them in the correct folders, registers the two
# Scheduled Tasks (event + service watcher), and runs the Layer-0 Tamper
# Protection audit. Runs end-to-end so the agent is fully defended in one shot.
#
# Works under BOTH invocation styles:
#   1. irm ... | iex                          (anti-malware blocks download write -- see note)
#   2. irm ... -OutFile install.ps1; .\install.ps1   (RECOMMENDED on hardened agents)
#   3. copy install.ps1 locally and run it
#
# Why option 2 is recommended when Tamper Protection is ON: SmartScreen /
# Defender may refuse Invoke-Expression on a streamed download. Saving the
# file first lets the .ps1 extension be trusted for one execution, then the
# body re-execs from disk so here-strings (@"..."@) parse correctly.
#
# One-liner:
#   irm https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar/install.ps1 -OutFile $env:TEMP\install.ps1; & "$env:TEMP\install.ps1"
#
# Local file:
#   powershell -ExecutionPolicy Bypass -File .\install.ps1

$ErrorActionPreference = "Stop"

# ----------------------------------------------------------------------
# Self-bootstrap: if our body has been streamed in via iex, MY command
# definitions are missing here-string terminators. Detect & re-exec from
# a real on-disk copy so the parser sees proper line endings.
# ----------------------------------------------------------------------
$script:GuardRepoUrl = "https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar"

if ($MyInvocation.MyCommand.Path -notlike '?:\*' -and $MyInvocation.MyCommand.Path -notlike '\\*\*') {
    # Streamed via iex -- no on-disk path. Materialize ourselves and re-run.
    $tmp = Join-Path $env:TEMP "defender-guard-install.ps1"
    Write-Host "[bootstrap] re-launching from disk: $tmp" -ForegroundColor DarkYellow
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest "$script:GuardRepoUrl/install.ps1" -OutFile $tmp -UseBasicParsing
    } catch {
        Write-Host "ERROR: could not self-download ($($_.Exception.Message))" -ForegroundColor Red
        return
    }
    & $tmp @args
    return
}

# ----------------------------------------------------------------------
# Real entry point: we are running from a .ps1 file on disk.
# ----------------------------------------------------------------------
$base   = $script:GuardRepoUrl
$binDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$psDir  = "C:\Program Files\Sysinternals"

Write-Host "=== Defender-Guard one-step installer ===" -ForegroundColor Cyan

# 1. helpers: download first so dot-source works after elevation check.
if (-not (Test-Path $psDir)) { New-Item -ItemType Directory -Path $psDir -Force | Out-Null }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$helpersLocal = Join-Path $psDir "_install-helpers.ps1"
$helpersUrl   = "$base/_install-helpers.ps1"

# Use the SAME on-disk copy that ships beside this installer, so here-string
# terminators parse correctly. Don't Invoke-Expression the downloaded body.
$installed = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) "_install-helpers.ps1"
if (Test-Path $installed) {
    Copy-Item -Force $installed $helpersLocal
} else {
    Write-Host "Downloading _install-helpers.ps1 ..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest $helpersUrl -OutFile $helpersLocal -UseBasicParsing
    } catch {
        Write-Host "ERROR: helper download failed ($($_.Exception.Message))" -ForegroundColor Red
        return
    }
}

# Dot-source from the on-disk copy.
. $helpersLocal

# 2. must be admin (writing under Program Files AND registering Scheduled Tasks).
Assert-Admin

# 3. sanity check: is the Wazuh agent installed?
Assert-WazuhAgent -BinDir $binDir

# 4. download all script files (idempotent: skips files that already match).
Write-Host "Downloading files..." -ForegroundColor Yellow
$files = @(
    @{ u = "reenable-defender.cmd";         d = $binDir },
    @{ u = "reenable-defender.ps1";         d = $psDir  },
    @{ u = "watchdog-service.ps1";          d = $psDir  },
    @{ u = "enforce-tamper-protection.ps1"; d = $psDir  },
    @{ u = "tamper-protection-policy.xml";  d = $psDir  }
)
foreach ($f in $files) {
    $dest = Join-Path $f.d $f.u
    if (-not (Test-Path $dest)) {
        Write-Host "  -> $($f.u)" -ForegroundColor Yellow
        try {
            Invoke-WebRequest "$base/$($f.u)" -OutFile $dest -UseBasicParsing
        } catch {
            Write-Host "  [!!] $($f.u): $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "  --  $($f.u) (exists, skipping)" -ForegroundColor DarkGray
    }
}

# 5. verify all files present, abort if not.
$required = @(
    "$binDir\reenable-defender.cmd",
    "$psDir\reenable-defender.ps1",
    "$psDir\watchdog-service.ps1",
    "$psDir\enforce-tamper-protection.ps1",
    "$psDir\tamper-protection-policy.xml"
)
$missing = $required | Where-Object { -not (Test-Path $_) }
if ($missing) {
    Write-Host ""
    Write-Host "ERROR: files missing after download:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
    return
}

# 6. register the two Scheduled Tasks (Layer-1 failsafe).
Install-GuardWatchers -psDir $psDir

# 7. run the Layer-0 Tamper audit (idempotent; surfaces Tamper ON/OFF + GUI hint).
Invoke-GuardTamperCheck -psDir $psDir

# 8. final banner.
Show-GuardFinal -binDir $binDir -psDir $psDir
