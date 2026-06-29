# install.ps1 - Defender-Guard Active Response: one-step installer.
#
# Downloads all files, places them in the correct folders, registers the two
# Scheduled Tasks (event + service watcher), and runs the Layer-0 Tamper
# Protection audit. Runs end-to-end so the agent is fully defended in one shot.
#
# One-liner (run in an ELEVATED PowerShell):
#   irm https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar/install.ps1 | iex

$ErrorActionPreference = "Stop"
$base   = "https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar"
$binDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"
$psDir  = "C:\Program Files\Sysinternals"

Write-Host "=== Defender-Guard one-step installer ===" -ForegroundColor Cyan

# 1. helpers: download first so dot-source works after elevation check.
if (-not (Test-Path $psDir)) { New-Item -ItemType Directory -Path $psDir -Force | Out-Null }
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

$helpers = "$psDir\_install-helpers.ps1"
Write-Host "Downloading _install-helpers.ps1 ..." -ForegroundColor Yellow
Invoke-WebRequest "$base/_install-helpers.ps1" -OutFile $helpers -UseBasicParsing
. $helpers

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
        Invoke-WebRequest "$base/$($f.u)" -OutFile $dest -UseBasicParsing
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
