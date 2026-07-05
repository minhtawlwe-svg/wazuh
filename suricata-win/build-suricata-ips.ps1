#Requires -RunAsAdministrator
# ============================================================================
# Build Suricata IPS mode (WinDivert) from source - fully automated
# ============================================================================
# Reproduces, end-to-end, the from-source build validated 2026-07-04/05.
# The official Suricata Windows MSI (used by agb-full-setup.ps1) is IDS-only
# - it can only alert, never block, because Npcap is a PASSIVE capture
# driver. Real inline blocking (WinDivert) does not exist in the prebuilt
# MSI and requires compiling Suricata from source with WinDivert support
# explicitly enabled. This script does that whole build.
#
#   iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/build-suricata-ips.ps1 -UseBasicParsing | iex
#
# This is a SEPARATE, EXPERIMENTAL build - it does not touch or replace the
# existing IDS-mode Suricata install. Output lands in a standalone deploy
# folder for manual testing. See Suricata-IPS-Mode-Build-Guide.docx for the
# full narrative writeup (every error hit and why), or the "GOTCHAS FIXED
# BY THIS SCRIPT" comment blocks below for the condensed version.
#
# Requirements: Administrator PowerShell, ~5 GB free disk, internet access.
# Takes 20-60+ minutes depending on connection/CPU (largest cost: compiling
# ~250 Rust crates for Suricata's rust/ subsystem, plus the C source tree).
# ============================================================================
[CmdletBinding()]
param(
    [string]$SuricataVersion = "suricata-8.0.3",     # git tag to build
    [string]$WorkRoot        = "C:\msys64\home\$env:USERNAME\suricata-ips-build",
    [string]$DeployRoot      = "C:\SuricataIPS",       # final self-contained output
    [string]$NpcapUrl        = "https://npcap.com/dist/npcap-1.82.exe",
    [switch]$SkipMsys2Install,                          # if MSYS2 already installed
    [switch]$SkipPackageInstall,                       # if deps already installed
    [switch]$SkipNpcap                                 # if the Npcap DRIVER is already installed
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
function Log($m)  { Write-Host "[ips-build] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[ips-build] WARN: $m" -ForegroundColor Yellow }
function Die($m)  { Write-Host "[ips-build] FATAL: $m" -ForegroundColor Red; exit 1 }

$Msys2Bash = "C:\msys64\usr\bin\bash.exe"
$Bash = { param($cmd) & $Msys2Bash -lc $cmd }

# ---------- Step 0: Windows Defender exclusion (REQUIRED - see gotcha below) ----------
# GOTCHA FIXED: Windows Defender repeatedly quarantined freshly-built/downloaded
# files during this build (Rust's cargo.exe after every reinstall, and the
# WinDivert release zip) - both known AV false-positive targets. Without this
# exclusion, cargo.exe gets silently deleted within seconds of every install,
# causing confusing "file not found" errors on the very next command. This
# must happen BEFORE installing the rust package or downloading WinDivert.
Log "Step 0/10: Windows Defender exclusion for C:\msys64"
try {
    Add-MpPreference -ExclusionPath 'C:\msys64' -ErrorAction Stop
    Log "  exclusion added"
} catch {
    Warn "Could not add Defender exclusion ($($_.Exception.Message)). If cargo.exe or WinDivert.zip vanish moments after being written later in this script, add manually: Add-MpPreference -ExclusionPath 'C:\msys64'"
}

# ---------- Step 1: MSYS2 ----------
Log "Step 1/10: MSYS2 base install"
if (-not (Test-Path $Msys2Bash) -and -not $SkipMsys2Install) {
    $tmp = "$env:TEMP\msys2-base.sfx.exe"
    Log "  downloading MSYS2 base archive..."
    # GOTCHA FIXED: the first download attempt silently truncated (18 MB of a
    # real 53 MB file) and then failed to extract with "Unexpected end of
    # archive". Verify the downloaded size against the server's real
    # Content-Length before trusting a "completed" download.
    $expectedSize = (Invoke-WebRequest -Uri "https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-base-x86_64-latest.sfx.exe" -Method Head -UseBasicParsing).Headers.'Content-Length' | Select-Object -Last 1
    $attempt = 0
    do {
        $attempt++
        Invoke-WebRequest -Uri "https://github.com/msys2/msys2-installer/releases/download/nightly-x86_64/msys2-base-x86_64-latest.sfx.exe" -OutFile $tmp -UseBasicParsing
        $actualSize = (Get-Item $tmp).Length
        if ("$actualSize" -ne "$expectedSize") { Warn "  download size mismatch (got $actualSize, expected $expectedSize) - retrying ($attempt/3)" }
    } while ("$actualSize" -ne "$expectedSize" -and $attempt -lt 3)
    if ("$actualSize" -ne "$expectedSize") { Die "MSYS2 base archive would not download completely after 3 attempts" }
    Log "  extracting..."
    & $tmp -y -oC:\ | Out-Null
    if (-not (Test-Path $Msys2Bash)) { Die "MSYS2 extraction did not produce $Msys2Bash" }
    Log "  first-run initialization..."
    & $Bash "echo done" | Out-Null
    Log "  MSYS2 installed"
} else {
    Log "  already present, skipping"
}

# ---------- Step 2: build dependencies via pacman ----------
Log "Step 2/10: build dependencies (this can take a while + may need retries - see gotcha)"
if (-not $SkipPackageInstall) {
    # GOTCHA FIXED: several MSYS2 mirrors were unstable during this build
    # ("Operation too slow" / DNS resolution failures for specific mirrors).
    # pacman resumes from its local package cache on retry, so simply
    # re-running the same install command after a mirror failure works -
    # each retry needs less data than the last. Retry up to 5 times.
    & $Bash "sed -i 's/^ParallelDownloads.*/ParallelDownloads = 2/' /etc/pacman.conf" | Out-Null
    & $Bash "pacman -Syu --noconfirm" | Out-Null
    $pkgs = "autoconf automake git make mingw-w64-ucrt-x86_64-cbindgen mingw-w64-ucrt-x86_64-jansson " +
            "mingw-w64-ucrt-x86_64-libpcap mingw-w64-ucrt-x86_64-libtool mingw-w64-ucrt-x86_64-libyaml " +
            "mingw-w64-ucrt-x86_64-pcre2 mingw-w64-ucrt-x86_64-rust mingw-w64-ucrt-x86_64-toolchain unzip"
    $ok = $false
    for ($i = 1; $i -le 5; $i++) {
        Log "  pacman install attempt $i/5..."
        & $Bash "pacman -S --noconfirm $pkgs" 2>&1 | Tee-Object -Variable pacmanOut | Out-Null
        if ($pacmanOut -notmatch "error: failed to commit transaction") { $ok = $true; break }
        Warn "  mirror error(s) hit, retrying (pacman resumes from cache)..."
    }
    if (-not $ok) { Die "pacman install did not succeed after 5 attempts - check network/mirrors manually" }

    # GOTCHA FIXED: cargo.exe registered in the package DB but missing from
    # disk (Defender quarantine, see Step 0). Verify it actually exists and
    # runs; if not, the Step 0 exclusion likely didn't take effect in time -
    # reinstall just the rust package once more now that it's excluded.
    $cargoOk = $false
    try { & $Bash "cargo --version" 2>&1 | Out-Null; if ($LASTEXITCODE -eq 0) { $cargoOk = $true } } catch {}
    if (-not $cargoOk) {
        Warn "  cargo.exe missing/broken (likely AV quarantine) - reinstalling rust package"
        & $Bash "pacman -S --noconfirm mingw-w64-ucrt-x86_64-rust" | Out-Null
        & $Bash "cargo --version" 2>&1 | Out-Null
        if ($LASTEXITCODE -ne 0) { Die "cargo still not working after reinstall - check the Defender exclusion from Step 0 manually: Add-MpPreference -ExclusionPath 'C:\msys64'" }
    }
    Log "  dependencies installed and verified"
} else {
    Log "  skipped (-SkipPackageInstall)"
}

# ---------- Step 3: Npcap DRIVER (not just the SDK - the built binary needs this at runtime) ----------
Log "Step 3/10: Npcap driver"
if (-not $SkipNpcap) {
    $hasNpcap = (Get-Service npcap -ErrorAction SilentlyContinue) -or (Test-Path 'C:\Windows\System32\Npcap')
    if ($hasNpcap) {
        Log "  already installed, skipping"
    } else {
        $npInstaller = "$env:TEMP\npcap-installer.exe"
        Log "  downloading Npcap..."
        Invoke-WebRequest -Uri $NpcapUrl -OutFile $npInstaller -UseBasicParsing
        Warn "  Npcap's free build has NO silent-install mode - an interactive wizard will open now."
        Warn "  Tick 'Install Npcap in WinPcap API-compatible Mode', then Install, then Finish."
        Start-Process -FilePath $npInstaller -Wait
        if (-not ((Get-Service npcap -ErrorAction SilentlyContinue) -or (Test-Path 'C:\Windows\System32\Npcap'))) {
            Die "Npcap not detected after the wizard closed - re-run this script and complete the wizard fully"
        }
        Log "  Npcap installed"
    }
} else {
    Log "  skipped (-SkipNpcap)"
}

# ---------- Step 4: WinDivert 1.4.3 (NOT the latest version - see gotcha) ----------
Log "Step 4/10: WinDivert 1.4.3"
# GOTCHA FIXED: Suricata 8.0.3's source-windivert.c is written against the
# OLD WinDivert 1.x API. The current WinDivert release (2.2.2) has a
# materially different, incompatible API and will compile-fail with dozens
# of type-mismatch errors (wrong argument order/types, missing struct
# members, wrong argument counts). WinDivert 1.4.3 is what Suricata's own
# GitHub Actions CI pipeline uses to test this feature - use that exact
# version, not "latest".
& $Msys2Bash -lc "mkdir -p '$($WorkRoot -replace '\\','/')'" | Out-Null
$wdZip = "$WorkRoot\WinDivert-1.4.3-A.zip"
if (-not (Test-Path "$WorkRoot\WinDivert-1.4.3-A\include\windivert.h")) {
    Log "  downloading WinDivert 1.4.3..."
    Invoke-WebRequest -Uri "https://github.com/basil00/Divert/releases/download/v1.4.3/WinDivert-1.4.3-A.zip" -OutFile $wdZip -UseBasicParsing
    if (-not (Test-Path $wdZip)) { Die "WinDivert-1.4.3-A.zip failed to download or was removed immediately after (check Defender exclusion from Step 0)" }
    Expand-Archive -Path $wdZip -DestinationPath $WorkRoot -Force
    Log "  extracted"
} else {
    Log "  already present, skipping"
}
$WinDivertInclude   = "$WorkRoot\WinDivert-1.4.3-A\include"
$WinDivertLib       = "$WorkRoot\WinDivert-1.4.3-A\x86_64"

# ---------- Step 5: Npcap SDK ----------
Log "Step 5/10: Npcap SDK (headers/libs for linking)"
if (-not (Test-Path "$WorkRoot\npcap-sdk\Include\pcap.h")) {
    $npcapZip = "$WorkRoot\npcap-sdk-1.15.zip"
    Log "  downloading Npcap SDK..."
    try {
        Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-sdk-1.15.zip" -OutFile $npcapZip -UseBasicParsing
    } catch {
        Invoke-WebRequest -Uri "https://npcap.com/dist/npcap-sdk-1.15.zip" -OutFile $npcapZip -UseBasicParsing -SslProtocol Tls12
    }
    Expand-Archive -Path $npcapZip -DestinationPath "$WorkRoot\npcap-sdk" -Force
    Log "  extracted"
} else {
    Log "  already present, skipping"
}
$NpcapInclude = "$WorkRoot\npcap-sdk\Include"
$NpcapLib     = "$WorkRoot\npcap-sdk\Lib\x64"

# ---------- Step 6: Suricata source ----------
Log "Step 6/10: Suricata source ($SuricataVersion)"
$SrcDir = "$WorkRoot\suricata-src"
if (-not (Test-Path "$SrcDir\configure.ac")) {
    Log "  cloning..."
    & $Msys2Bash -lc "git clone --branch $SuricataVersion --depth 1 https://github.com/OISF/suricata.git '$($SrcDir -replace '\\','/')'" 2>&1 | Out-Null
    if (-not (Test-Path "$SrcDir\configure.ac")) { Die "Suricata source clone failed" }
} else {
    Log "  already present, skipping"
}

# ---------- Step 7: autogen + configure ----------
Log "Step 7/10: autogen.sh + configure (WinDivert + Npcap flags)"
$srcUnix       = $SrcDir -replace '\\','/' -replace '^C:','/c'
$wdIncludeUnix = $WinDivertInclude -replace '\\','/' -replace '^C:','/c'
$wdLibUnix     = $WinDivertLib -replace '\\','/' -replace '^C:','/c'
$npcapIncUnix  = $NpcapInclude -replace '\\','/' -replace '^C:','/c'
$npcapLibUnix  = $NpcapLib -replace '\\','/' -replace '^C:','/c'

$env:MSYSTEM = "UCRT64"
& $Msys2Bash -lc "cd '$srcUnix' && ./autogen.sh" 2>&1 | Out-Null
$configureCmd = "cd '$srcUnix' && ./configure --prefix=/usr/local " +
    "--with-libpcap-includes='$npcapIncUnix' --with-libpcap-libraries='$npcapLibUnix' " +
    "--enable-windivert=yes --with-windivert-include='$wdIncludeUnix' --with-windivert-libraries='$wdLibUnix'"
& $Msys2Bash -lc $configureCmd 2>&1 | Out-Null

$acHeader = "$SrcDir\src\autoconf.h"
if (-not (Test-Path $acHeader)) { Die "configure did not produce src/autoconf.h - it likely failed. Re-run manually to see the error: MSYSTEM=UCRT64 bash -lc `"$configureCmd`"" }
$acContent = Get-Content $acHeader -Raw
if ($acContent -notmatch "#define WINDIVERT 1" -or $acContent -notmatch "#define HAVE_LIBWINDIVERT 1") {
    Die "configure ran but did NOT detect WinDivert - check the include/library paths above. This is fatal: without it you'd just be rebuilding IDS-only Suricata."
}
Log "  WinDivert + Npcap both confirmed detected"

# ---------- Step 8: build ----------
Log "Step 8/10: make (this is the long step - Rust crate compile alone took ~10 min in testing)"
$cores = [Environment]::ProcessorCount
& $Msys2Bash -lc "cd '$srcUnix' && make -j$cores" 2>&1 | Tee-Object -Variable makeOut | Out-Null
$exitLine = $makeOut | Select-String "^make: \*\*\*" | Select-Object -Last 1
if ($exitLine) { Die "make failed: $exitLine`nFull log was very long - re-run manually to see it: MSYSTEM=UCRT64 bash -lc `"cd '$srcUnix' && make -j$cores`"" }
Log "  build completed"

# ---------- Step 9: find the REAL binary + assemble deploy folder ----------
Log "Step 9/10: locating real binary + assembling self-contained deploy folder"
# GOTCHA FIXED: the top-level src/suricata.exe is a libtool WRAPPER STUB
# (~36 KB) for a not-yet-installed binary that links against shared
# libraries - it fails to run standalone (DLL load errors / "not
# recognized" depending on how it's launched). The REAL, fully-linked
# binary (100+ MB) is in the hidden .libs/ subdirectory. Always deploy
# THAT one, never the top-level stub.
$realBinary = "$SrcDir\src\.libs\suricata.exe"
if (-not (Test-Path $realBinary)) { Die "Expected real binary not found at $realBinary - build may have failed silently" }
$realSize = (Get-Item $realBinary).Length
if ($realSize -lt 10MB) { Warn "  real binary is only $([math]::Round($realSize/1MB,1)) MB - smaller than expected (100+ MB), verify it actually works before trusting it" }

New-Item -ItemType Directory -Force -Path $DeployRoot | Out-Null
Copy-Item $realBinary "$DeployRoot\suricata.exe" -Force

# GOTCHA FIXED: this is a dynamically-linked MSYS2/UCRT64 build (unlike the
# statically-linked official MSI) - it needs several runtime DLLs alongside
# it. The api-ms-win-crt-* "API set" forwarder DLLs exist on Windows already
# but in a special downlevel/ folder not on the normal search path for
# arbitrary MinGW-built executables.
Get-ChildItem "C:\Windows\System32\downlevel\api-ms-win-crt-*.dll" -ErrorAction SilentlyContinue |
    Copy-Item -Destination $DeployRoot -Force
$ucrtLibs = @("libpcap.dll","libjansson-4.dll","libyaml-0-2.dll","libpcre2-8-0.dll","libpcre2-posix-3.dll",
              "libwinpthread-1.dll","libgcc_s_seh-1.dll","zlib1.dll","libzstd.dll","liblzma-5.dll")
foreach ($dll in $ucrtLibs) {
    $src = "C:\msys64\ucrt64\bin\$dll"
    if (Test-Path $src) { Copy-Item $src $DeployRoot -Force }
}
Copy-Item "$WinDivertLib\WinDivert.dll" $DeployRoot -Force
# wpcap.dll itself is intentionally NOT copied - it resolves from the
# system-wide Npcap driver installation, which must already be present.

Log "  deploy folder ready: $DeployRoot"

# ---------- Step 10: verify ----------
Log "Step 10/10: verify"
Push-Location $DeployRoot
try {
    $verOut = & ".\suricata.exe" -V 2>&1
    $biOut  = & ".\suricata.exe" --build-info 2>&1
} finally {
    Pop-Location
}
$versionLine = $verOut | Select-String "This is Suricata version"
$wdLine      = $biOut  | Select-String "WinDivert enabled"
$npcapLine   = $biOut  | Select-String "Npcap support"

Write-Host "`n===== VERIFY =====" -ForegroundColor Cyan
Write-Host ("  version      : " + $(if ($versionLine) { $versionLine.Line.Trim() } else { "FAILED TO RUN - see output above" }))
Write-Host ("  " + $(if ($wdLine) { $wdLine.Line.Trim() } else { "WinDivert status unknown" }))
Write-Host ("  " + $(if ($npcapLine) { $npcapLine.Line.Trim() } else { "Npcap status unknown" }))

if ($versionLine -and $wdLine -match "yes") {
    Write-Host "`n===== SUCCESS =====" -ForegroundColor Green
    Write-Host "Custom Suricata build with WinDivert IPS support is ready at: $DeployRoot"
    Write-Host ""
    Write-Host "This is a SEPARATE, EXPERIMENTAL build - it has NOT touched your existing" -ForegroundColor Yellow
    Write-Host "IDS-mode Suricata install (agb-full-setup.ps1). Remaining manual steps:" -ForegroundColor Yellow
    Write-Host "  1. Test inline capture (requires Administrator, installs a kernel driver" -ForegroundColor Yellow
    Write-Host "     on first use - run interactively, not automated):" -ForegroundColor Yellow
    Write-Host "       cd '$DeployRoot'; .\suricata.exe -c suricata.yaml --windivert true" -ForegroundColor Yellow
    Write-Host "  2. suricata.yaml needs a WinDivert-specific runmode config, not the" -ForegroundColor Yellow
    Write-Host "     Npcap/pcap capture config used by the IDS deployment." -ForegroundColor Yellow
    Write-Host "  3. Rules that should actually BLOCK need action 'drop', not 'alert' -" -ForegroundColor Yellow
    Write-Host "     'alert' rules still only log, even under WinDivert." -ForegroundColor Yellow
    Write-Host "  4. Test on a disposable machine before considering this for a" -ForegroundColor Yellow
    Write-Host "     production agent - inline mode sitting in the traffic path is a" -ForegroundColor Yellow
    Write-Host "     materially different risk profile than IDS-only." -ForegroundColor Yellow
} else {
    Die "Build produced a binary but verification failed - check the output above"
}
