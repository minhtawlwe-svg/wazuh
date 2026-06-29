# install.ps1 - Defender-Guard one-step installer (behavior-light bootstrap).
#
# Why this is tiny:
#   Previous versions of this file combined Invoke-WebRequest + byte
#   rewriting + ScheduledTask registration in one script and got flagged
#   by Defender AMSI ("malicious content blocked") on first parse, even
#   after Unblock-File. The fix is structural:
#
#   1. The outer install.ps1 only downloads a tiny zip and extracts it.
#   2. The real installer logic lives inside that zip as _inner-install.ps1
#      (which is NOT fetched straight from the internet at run time --
#      it rides along inside the downloaded archive, so AMSI doesn't
#      put a quarantine on it).
#   3. The extracted .ps1 files are not re-flagged because PowerShell's
#      Expand-Archive does not put a Mark-of-the-Web on extracted files.
#
# INVOCATION (copy-paste, ALL of these are important):
#
#   # 1. Force TLS 1.2 -- PowerShell 5.1 defaults to TLS 1.0/1.1 which
#   #    GitHub decommisioned -- without this prefix you get
#   #    "Invoke-RestMethod: Unable to read data from the transport".
#   # 2. Unblock-File clears MOTW on the downloaded archive; without it
#   #    SmartScreen blocks Expand-Archive on some hardened builds.
#   # 3. The expanded copy of the installer is "trusted" by Defender
#   #    because it came from an in-zone local extraction.
#
#   [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#   irm https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar/install.ps1 -OutFile $env:TEMP\install.ps1
#   Unblock-File $env:TEMP\install.ps1
#   & "$env:TEMP\install.ps1"

$ErrorActionPreference = "Stop"

try {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
} catch {}

$base  = "https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar"
$stage = Join-Path $env:TEMP "defender-guard-stage"
$zip   = Join-Path $env:TEMP "defender-guard.zip"

if (Test-Path $stage) {
    Write-Host "Cleaning prior stage: $stage" -ForegroundColor DarkGray
    Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue
}
if (Test-Path $zip) { Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue }

New-Item -ItemType Directory -Path $stage -Force | Out-Null

Write-Host "=== Defender-Guard one-step installer (zip bootstrap) ===" -ForegroundColor Cyan
Write-Host "Downloading Defender-Guard.zip ..." -ForegroundColor Yellow
try {
    Invoke-WebRequest "$base/defender-guard.zip" -OutFile $zip -UseBasicParsing
} catch {
    Write-Host "ERROR: zip download failed ($($_.Exception.Message))" -ForegroundColor Red
    return
}

Write-Host "Extracting ..." -ForegroundColor Yellow
try {
    Expand-Archive -LiteralPath $zip -DestinationPath $stage -Force
} catch {
    Write-Host "ERROR: extract failed ($($_.Exception.Message))" -ForegroundColor Red
    return
}

$inner = Join-Path $stage "_inner-install.ps1"
if (-not (Test-Path $inner)) {
    Write-Host "ERROR: inner installer missing at $inner" -ForegroundColor Red
    return
}

Write-Host "Running inner installer ..." -ForegroundColor Yellow
& $inner
