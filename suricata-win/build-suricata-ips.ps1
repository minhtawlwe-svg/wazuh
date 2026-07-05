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
# full narrative writeup (every error hit and why), or the "GOTCHA FIXED"
# comment blocks below for the condensed version.
#
# Requirements: Administrator PowerShell, ~5 GB free disk, internet access.
# Takes 20-60+ minutes depending on connection/CPU (largest cost: compiling
# ~250 Rust crates for Suricata's rust/ subsystem, plus the C source tree).
#
# INTERACTIVE by default - prompts for capture interface and HOME_NET (press
# Enter on either to auto-pick/keep the stock default), matching
# agb-full-setup.ps1's UX. Pass -NoPrompt to skip both and auto-pick
# everything, or -CaptureInterfaceName/-HomeNet to pre-supply either value
# non-interactively (piping via | iex can't pass parameters - download the
# script first if you need this).
# ============================================================================
[CmdletBinding()]
param(
    [string]$SuricataVersion      = "suricata-8.0.3",     # git tag to build
    [string]$WorkRoot             = "C:\msys64\home\$env:USERNAME\suricata-ips-build",
    [string]$DeployRoot           = "C:\SuricataIPS",       # final self-contained output
    [string]$NpcapUrl             = "https://npcap.com/dist/npcap-1.82.exe",
    [string]$HomeNet              = "",                     # blank = keep stock RFC1918
    [string]$CaptureInterfaceName = "",                     # blank = auto-pick fastest UP adapter
    [switch]$NoPrompt,                                     # skip both interactive prompts
    [switch]$SkipMsys2Install,                              # if MSYS2 already installed
    [switch]$SkipPackageInstall,                           # if deps already installed
    [switch]$SkipNpcap,                                    # if the Npcap DRIVER is already installed
    [switch]$SkipRulesSetup,                               # skip Step 10 - leaves just the bare binary, no yaml/rules
    [switch]$SkipScheduledTask                             # skip Step 11 - no daily rule refresh
)

$ErrorActionPreference = "Stop"
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# GOTCHA FIXED: MSYSTEM defaults to plain "MSYS" for any bash invocation
# that doesn't set it explicitly, and MSYS2 only adds /ucrt64/bin (where
# cargo, rustc, and every mingw-w64-ucrt-x86_64-* package's binaries live)
# to PATH when MSYSTEM=UCRT64 is active. This was previously only set
# right before Step 7 (autogen/configure) - every earlier bash call,
# including the Step 2 cargo verification, ran under plain MSYS with no
# /ucrt64/bin on PATH, so `cargo --version` failed with "command not
# found" (exit 127) even though cargo.exe was correctly installed and
# working the whole time. Confirmed via `bash -lc "which cargo"` returning
# nothing while a direct full-path invocation succeeded immediately - this
# was misdiagnosed as AV quarantine for two full debugging rounds before
# the actual PATH/environment bug was found. Set it here, before ANY bash
# call happens.
$env:MSYSTEM = "UCRT64"
function Log($m)  { Write-Host "[ips-build] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[ips-build] WARN: $m" -ForegroundColor Yellow }
function Die($m)  {
    Write-Host "[ips-build] FATAL: $m" -ForegroundColor Red
    # GOTCHA FIXED: if this script is launched via a one-liner that spawns a
    # fresh elevated PowerShell window (e.g. right-click "Run as
    # Administrator" on a shortcut, or an iwr|iex from a non-elevated
    # session that triggers a new elevated process), that window closes the
    # INSTANT the script exits - the fatal message flashes and disappears
    # before it can be read. Pause unless running unattended (-NoPrompt).
    if (-not $NoPrompt) {
        Write-Host "[ips-build] (press Enter to close this window)" -ForegroundColor DarkGray
        Read-Host | Out-Null
    }
    exit 1
}

# GOTCHA FIXED: same window-disappears-before-you-can-read-it problem, but
# for an UNHANDLED exception anywhere in the script that never goes through
# Die() at all (e.g. a native command failure not wrapped by Invoke-Bash,
# or any other terminating error under $ErrorActionPreference='Stop'). This
# script-scope trap catches those too, prints the real exception, and
# pauses the same way before the window can close.
trap {
    Write-Host "[ips-build] UNHANDLED ERROR: $_" -ForegroundColor Red
    Write-Host $_.ScriptStackTrace -ForegroundColor DarkGray
    if (-not $NoPrompt) {
        Write-Host "[ips-build] (press Enter to close this window)" -ForegroundColor DarkGray
        Read-Host | Out-Null
    }
    exit 1
}

$Msys2Bash = "C:\msys64\usr\bin\bash.exe"

# GOTCHA FIXED: with $ErrorActionPreference='Stop' at script scope, calling a
# native executable that writes ANYTHING to stderr (even a harmless status
# line, e.g. pacman's own "is up to date -- reinstalling" notice) gets
# converted into a terminating NativeCommandError and kills the whole
# script - even though the command's real exit code was 0/success. Every
# bash invocation goes through this helper instead, which temporarily
# relaxes that preference and checks $LASTEXITCODE explicitly where it
# actually matters, rather than treating any stderr text as fatal.
function Invoke-Bash([string]$cmd) {
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $out = & $Msys2Bash -lc $cmd 2>&1
    } finally {
        $ErrorActionPreference = $prev
    }
    return $out
}

# ---------- Interactive prompts (ask when not supplied on the command line) ----------
if (-not $NoPrompt -and -not $CaptureInterfaceName) {
    Write-Host "`nAvailable physical network adapters that are UP:" -ForegroundColor Cyan
    Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' } |
        Format-Table -AutoSize Name, InterfaceDescription, LinkSpeed | Out-Host
    $ans = Read-Host "Capture interface name (press Enter to auto-pick the fastest UP adapter)"
    if ($ans) { $CaptureInterfaceName = $ans.Trim() }
}
if (-not $NoPrompt -and -not $HomeNet) {
    Write-Host "`nHOME_NET defines your local networks (rules fire EXTERNAL -> HOME_NET)." -ForegroundColor Cyan
    $ans = Read-Host "HOME_NET, e.g. [192.168.1.0/24]  (press Enter to keep stock RFC1918)"
    if ($ans) { $HomeNet = $ans.Trim() }
}
if ($CaptureInterfaceName) {
    $SelectedAdapter = Get-NetAdapter -Name $CaptureInterfaceName -ErrorAction SilentlyContinue
} else {
    $ex = '(?i)(virtual|vmware|virtualbox|hyper-v|veth|loopback|npcap loopback|wi-fi direct|bluetooth|tap|tun|wireguard|zerotier|tailscale|hamachi|isatap|teredo)'
    $SelectedAdapter = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.Name -notmatch $ex -and $_.InterfaceDescription -notmatch $ex } | Sort-Object LinkSpeed -Descending | Select-Object -First 1
}
if ($SelectedAdapter) {
    Log "capture interface: $($SelectedAdapter.Name) (ifIndex $($SelectedAdapter.ifIndex)) - $($SelectedAdapter.InterfaceDescription)"
} else {
    Warn "no capture adapter resolved - WinDivert's own filter language can still scope by ifIdx manually later if needed"
}

# ---------- Step 0: Windows Defender exclusions (REQUIRED - see gotcha below) ----------
# GOTCHA FIXED: Windows Defender repeatedly quarantined freshly-built/downloaded
# files during this build (Rust's cargo.exe after every reinstall, and the
# WinDivert release zip) - both known AV false-positive targets. Without this
# exclusion, cargo.exe gets silently deleted within seconds of every install,
# causing confusing "file not found" errors on the very next command. This
# must happen BEFORE installing the rust package or downloading WinDivert.
# $DeployRoot needs its own exclusion too - the final suricata.exe (112+ MB,
# unsigned, compiled from source, linked against a packet-interception
# driver) is exactly the profile Defender flags, and it lives OUTSIDE
# C:\msys64 entirely.
Log "Step 0/13: Windows Defender exclusions"
# GOTCHA FIXED: on machines with Tamper Protection ON, Add-MpPreference
# silently fails to actually enforce exclusion changes - Defender
# deliberately ignores/reverts exclusion edits made via PowerShell (or any
# non-UI method) while Tamper Protection is active, specifically so
# malware can't disable its own detection via script. This is NOT a bug -
# it's Tamper Protection working as designed - but it means the automated
# path below can silently do nothing on a protected machine, and the build
# fails later with cargo.exe/suricata.exe repeatedly quarantined despite
# the script reporting the exclusion as "added". Detect this up front and
# hand the exclusion step to the user via the trusted GUI path instead.
$tamperProtected = $false
try { $tamperProtected = [bool](Get-MpComputerStatus -ErrorAction Stop).IsTamperProtected } catch {}

if ($tamperProtected) {
    Warn "Tamper Protection is ON - Add-MpPreference cannot add real exclusions from a script on this machine (Defender ignores non-UI exclusion changes by design)."
    Write-Host ""
    Write-Host "  ACTION NEEDED - add these two folders as Defender exclusions yourself:" -ForegroundColor Yellow
    Write-Host "    1. C:\msys64" -ForegroundColor Yellow
    Write-Host "    2. $DeployRoot" -ForegroundColor Yellow
    Write-Host "  via Windows Security > Virus & threat protection > Manage settings >" -ForegroundColor Yellow
    Write-Host "  Exclusions > Add or remove exclusions > Add an exclusion > Folder." -ForegroundColor Yellow
    Write-Host "  (opening Windows Security now)" -ForegroundColor Yellow
    Start-Process "windowsdefender://threatsettings" -ErrorAction SilentlyContinue | Out-Null
    Write-Host ""
    Read-Host "Press Enter once both folders are added as exclusions"
}

foreach ($exPath in @('C:\msys64', $DeployRoot)) {
    if (-not $tamperProtected) {
        try {
            Add-MpPreference -ExclusionPath $exPath -ErrorAction Stop
        } catch {
            Warn "Could not add Defender exclusion for $exPath ($($_.Exception.Message)). If files vanish moments after being written later in this script, add manually: Add-MpPreference -ExclusionPath '$exPath'"
            continue
        }
    }
    # GOTCHA FIXED: Add-MpPreference can report success instantly while
    # Defender's real-time protection engine takes a moment to actually
    # pick up the new exclusion internally - a file written in that gap
    # still gets scanned (and potentially quarantined) as if unexcluded.
    # Poll until the path is confirmed present in the live exclusion list
    # before trusting it, instead of a fixed sleep or no wait at all.
    $confirmed = $false
    for ($i = 0; $i -lt 10; $i++) {
        $current = (Get-MpPreference -ErrorAction SilentlyContinue).ExclusionPath
        if ($current -contains $exPath) { $confirmed = $true; break }
        Start-Sleep -Milliseconds 500
    }
    if ($confirmed) { Log "  exclusion added and confirmed active: $exPath" }
    else { Warn "  exclusion for $exPath was added but not yet confirmed active after 5s - proceeding anyway, but AV quarantine is still possible for the next few seconds" }
}

# ---------- Step 1: MSYS2 ----------
Log "Step 1/13: MSYS2 base install"
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
    Invoke-Bash "echo done" | Out-Null
    Log "  MSYS2 installed"
} else {
    Log "  already present, skipping"
}

# ---------- Step 2: build dependencies via pacman ----------
Log "Step 2/13: build dependencies (this can take a while + may need retries - see gotcha)"
if (-not $SkipPackageInstall) {
    # GOTCHA FIXED: several MSYS2 mirrors were unstable during this build
    # ("Operation too slow" / DNS resolution failures for specific mirrors).
    # pacman resumes from its local package cache on retry, so simply
    # re-running the same install command after a mirror failure works -
    # each retry needs less data than the last. Retry up to 5 times.
    Invoke-Bash "sed -i 's/^ParallelDownloads.*/ParallelDownloads = 2/' /etc/pacman.conf" | Out-Null
    Invoke-Bash "pacman -Syu --noconfirm" | Out-Null
    $pkgs = "autoconf automake git make mingw-w64-ucrt-x86_64-cbindgen mingw-w64-ucrt-x86_64-jansson " +
            "mingw-w64-ucrt-x86_64-libpcap mingw-w64-ucrt-x86_64-libtool mingw-w64-ucrt-x86_64-libyaml " +
            "mingw-w64-ucrt-x86_64-pcre2 mingw-w64-ucrt-x86_64-rust mingw-w64-ucrt-x86_64-toolchain unzip"
    $ok = $false
    for ($i = 1; $i -le 5; $i++) {
        Log "  pacman install attempt $i/5..."
        $pacmanOut = Invoke-Bash "pacman -S --noconfirm $pkgs"
        if ($pacmanOut -notmatch "error: failed to commit transaction") { $ok = $true; break }
        Warn "  mirror error(s) hit, retrying (pacman resumes from cache)..."
    }
    if (-not $ok) { Die "pacman install did not succeed after 5 attempts - check network/mirrors manually" }

    # GOTCHA FIXED: `cargo --version` can transiently fail immediately after
    # pacman extracts it - Defender's real-time scanner briefly locks a
    # freshly-written exe the instant it appears on disk, even with an
    # exclusion in place (the exclusion stops it being REMOVED, not
    # necessarily the split-second on-write scan lock). Confirmed by
    # testing during development: `cargo --version` failed inside the
    # script, yet the exact same file ran fine seconds later run directly -
    # the file was never actually missing/corrupted, just momentarily busy.
    # Retry with short delays before concluding it's genuinely broken and
    # escalating to a full package reinstall.
    function Test-CargoOk {
        for ($i = 0; $i -lt 6; $i++) {
            Invoke-Bash "cargo --version" | Out-Null
            if ($LASTEXITCODE -eq 0) { return $true }
            Start-Sleep -Milliseconds 1000
        }
        return $false
    }
    if (-not (Test-CargoOk)) {
        Warn "  cargo.exe not responding after 6s of retries - reinstalling rust package (could be AV quarantine, or just a slower scan lock than usual)"
        Invoke-Bash "pacman -S --noconfirm mingw-w64-ucrt-x86_64-rust" | Out-Null
        if (-not (Test-CargoOk)) { Die "cargo still not working after reinstall + retries - check the Defender exclusion from Step 0 manually: Add-MpPreference -ExclusionPath 'C:\msys64'" }
    }
    Log "  dependencies installed and verified"
} else {
    Log "  skipped (-SkipPackageInstall)"
}

# ---------- Step 3: Npcap DRIVER (not just the SDK - the built binary needs this at runtime) ----------
Log "Step 3/13: Npcap driver"
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
Log "Step 4/13: WinDivert 1.4.3"
# GOTCHA FIXED: Suricata 8.0.3's source-windivert.c is written against the
# OLD WinDivert 1.x API. The current WinDivert release (2.2.2) has a
# materially different, incompatible API and will compile-fail with dozens
# of type-mismatch errors (wrong argument order/types, missing struct
# members, wrong argument counts). WinDivert 1.4.3 is what Suricata's own
# GitHub Actions CI pipeline uses to test this feature - use that exact
# version, not "latest".
Invoke-Bash "mkdir -p '$($WorkRoot -replace '\\','/')'" | Out-Null
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
$WinDivertInclude = "$WorkRoot\WinDivert-1.4.3-A\include"
$WinDivertLib     = "$WorkRoot\WinDivert-1.4.3-A\x86_64"

# ---------- Step 5: Npcap SDK ----------
Log "Step 5/13: Npcap SDK (headers/libs for linking)"
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
Log "Step 6/13: Suricata source ($SuricataVersion)"
$SrcDir = "$WorkRoot\suricata-src"
if (-not (Test-Path "$SrcDir\configure.ac")) {
    Log "  cloning..."
    Invoke-Bash "git clone --branch $SuricataVersion --depth 1 https://github.com/OISF/suricata.git '$($SrcDir -replace '\\','/')'" | Out-Null
    if (-not (Test-Path "$SrcDir\configure.ac")) { Die "Suricata source clone failed" }
} else {
    Log "  already present, skipping"
}

# ---------- Step 7: patch a real upstream bug - WinDivert never marks IPS mode ----------
Log "Step 7/13: patching known upstream bug (WinDivert eve.json action field)"
# GOTCHA FIXED: confirmed by reading Suricata's own source (not guessed).
# eve.json's alert.action field is computed in src/output-json-alert.c:
#   } else if ((pa->action & ACTION_DROP) && EngineModeIsIPS()) { action = "blocked"; }
# EngineModeIsIPS() is set true by EVERY OTHER inline runmode (NFQ/-q,
# IPFW/-d, af-packet, netmap, dpdk each call EngineModeSetIPS() from their
# own CLI-option or runmode-init code in src/suricata.c /
# src/runmode-*.c) - but grep confirms src/runmode-windivert.c and both
# --windivert / --windivert-forward branches in src/suricata.c never call
# it at all. So under WinDivert, EngineModeIsIPS() stays false forever,
# and eve.json reports "allowed" even when a rule's `drop` action DID
# fire and the packet WAS dropped (confirmed independently via fast.log's
# accurate "[wDrop]" tag and a real blocked connection during testing).
# This is a genuine gap in Suricata 8.0.3's own WinDivert support, not a
# config issue - the only fix is patching the two call sites to match
# every other IPS runmode, then rebuilding.
$suricataC = "$SrcDir\src\suricata.c"
$scContent = Get-Content $suricataC -Raw
if ($scContent -match [regex]::Escape("suri->run_mode = RUNMODE_WINDIVERT;`n                    EngineModeSetIPS();")) {
    Log "  already patched, skipping"
} elseif ($scContent -match [regex]::Escape("suri->run_mode = RUNMODE_WINDIVERT;")) {
    $patched = $scContent -replace [regex]::Escape("suri->run_mode = RUNMODE_WINDIVERT;"), "suri->run_mode = RUNMODE_WINDIVERT;`n                    EngineModeSetIPS();"
    [IO.File]::WriteAllText($suricataC, $patched, (New-Object Text.UTF8Encoding($false)))
    $count = ([regex]::Matches($patched, [regex]::Escape("RUNMODE_WINDIVERT;`n                    EngineModeSetIPS();"))).Count
    Log "  patched suricata.c ($count call site(s) added - matches the --windivert and --windivert-forward branches)"
} else {
    Warn "  expected RUNMODE_WINDIVERT assignment not found in suricata.c - Suricata's source may have changed upstream; eve.json action field will likely still say 'allowed' for dropped packets even though real blocking works (see fast.log)"
}

# ---------- Step 8: autogen + configure ----------
Log "Step 8/13: autogen.sh + configure (WinDivert + Npcap flags)"
$srcUnix       = $SrcDir -replace '\\','/' -replace '^C:','/c'
$wdIncludeUnix = $WinDivertInclude -replace '\\','/' -replace '^C:','/c'
$wdLibUnix     = $WinDivertLib -replace '\\','/' -replace '^C:','/c'
$npcapIncUnix  = $NpcapInclude -replace '\\','/' -replace '^C:','/c'
$npcapLibUnix  = $NpcapLib -replace '\\','/' -replace '^C:','/c'

Invoke-Bash "cd '$srcUnix' && ./autogen.sh" | Out-Null
$configureCmd = "cd '$srcUnix' && ./configure --prefix=/usr/local " +
    "--with-libpcap-includes='$npcapIncUnix' --with-libpcap-libraries='$npcapLibUnix' " +
    "--enable-windivert=yes --with-windivert-include='$wdIncludeUnix' --with-windivert-libraries='$wdLibUnix'"
Invoke-Bash $configureCmd | Out-Null

$acHeader = "$SrcDir\src\autoconf.h"
if (-not (Test-Path $acHeader)) { Die "configure did not produce src/autoconf.h - it likely failed. Re-run manually to see the error: MSYSTEM=UCRT64 bash -lc `"$configureCmd`"" }
$acContent = Get-Content $acHeader -Raw
if ($acContent -notmatch "#define WINDIVERT 1" -or $acContent -notmatch "#define HAVE_LIBWINDIVERT 1") {
    Die "configure ran but did NOT detect WinDivert - check the include/library paths above. This is fatal: without it you'd just be rebuilding IDS-only Suricata."
}
Log "  WinDivert + Npcap both confirmed detected"

# ---------- Step 8: build ----------
Log "Step 9/13: make (this is the long step - Rust crate compile alone took ~10 min in testing)"
$cores = [Environment]::ProcessorCount
$makeOut = Invoke-Bash "cd '$srcUnix' && make -j$cores"
$exitLine = $makeOut | Select-String "^make: \*\*\*" | Select-Object -Last 1
if ($exitLine) { Die "make failed: $exitLine`nFull log was very long - re-run manually to see it: MSYSTEM=UCRT64 bash -lc `"cd '$srcUnix' && make -j$cores`"" }
Log "  build completed"

# ---------- Step 9: find the REAL binary + assemble deploy folder ----------
Log "Step 10/13: locating real binary + assembling self-contained deploy folder"
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
# GOTCHA FIXED: WinDivert.dll alone is not enough - WinDivertOpen() loads
# an actual kernel driver (WinDivert64.sys / WinDivert32.sys) from disk
# the first time it's used, and looks for it next to the DLL. Missing this
# produced "WinDivertOpen failed, error 2 ... driver files WinDivert32.sys
# or WinDivert64.sys were not found" and a hard engine-init failure on the
# very first --windivert test run, despite the build itself having
# succeeded (WinDivert enabled: yes in --build-info only confirms it was
# compiled in, not that the runtime driver is present).
foreach ($sys in @("WinDivert64.sys", "WinDivert32.sys")) {
    $src = "$WinDivertLib\$sys"
    if (Test-Path $src) { Copy-Item $src $DeployRoot -Force }
}
# wpcap.dll itself is intentionally NOT copied - it resolves from the
# system-wide Npcap driver installation, which must already be present.

Log "  deploy folder ready: $DeployRoot"

# ---------- helper shared by Step 10 and Step 11's scheduled tasks ----------
# ET Open stays as-is (action alert) - it's the full ~50,000-signature
# ruleset, most of it tuned for visibility/alerting, not blocking. Only
# agb-black.rules (the curated, purpose-built blacklist) gets converted to
# drop, so IPS mode only ever actively blocks the same small, deliberate
# set of IOCs the IDS deployment already trusts for auto-kill - not the
# entire noisy IDS ruleset.
function Get-EtOpenRuleset([string]$suricataExe, [string]$destPath, [string]$workDir) {
    $ver = (& $suricataExe -V 2>&1 | Select-String -Pattern '(\d+\.\d+\.\d+)' | Select-Object -First 1).Matches.Groups[1].Value
    $mm = $ver.Substring(0, $ver.LastIndexOf('.'))
    $tarPath = "$workDir\emerging.rules.tar.gz"
    $urls = @("https://rules.emergingthreats.net/open/suricata-$ver/emerging.rules.tar.gz",
              "https://rules.emergingthreats.net/open/suricata-$mm.0/emerging.rules.tar.gz",
              "https://rules.emergingthreats.net/open/suricata-$mm/emerging.rules.tar.gz")
    $got = $false
    foreach ($u in $urls) { try { Invoke-WebRequest -Uri $u -OutFile $tarPath -UseBasicParsing; $got = $true; break } catch {} }
    if (-not $got) { return $false }
    $extractDir = "$workDir\rules-extract"
    if (Test-Path $extractDir) { Remove-Item $extractDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
    & tar.exe -xzf $tarPath -C $extractDir
    $rfiles = Get-ChildItem (Join-Path $extractDir 'rules') -Filter *.rules -ErrorAction SilentlyContinue
    if (-not $rfiles) { $rfiles = Get-ChildItem $extractDir -Recurse -Filter *.rules }
    $sb = New-Object Text.StringBuilder
    foreach ($f in $rfiles) { [void]$sb.AppendLine([IO.File]::ReadAllText($f.FullName)) }
    [IO.File]::WriteAllText($destPath, $sb.ToString(), (New-Object Text.UTF8Encoding($false)))
    return $true
}
function Get-AgbBlackDropRuleset([string]$destPath) {
    $tmpPath = "$env:TEMP\agb-black-source.rules"
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-black.rules" -OutFile $tmpPath -UseBasicParsing
    } catch { return $false }
    $text = [IO.File]::ReadAllText($tmpPath)
    $dropText = [regex]::Replace($text, '(?m)^alert\s', 'drop ')
    [IO.File]::WriteAllText($destPath, $dropText, (New-Object Text.UTF8Encoding($false)))
    return $true
}

# ---------- Step 10: config + rules (ET Open = alert, agb-black.rules = drop) ----------
Log "Step 11/13: suricata.yaml + rules (ET Open stays alert-only, agb-black.rules converted to drop)"
if (-not $SkipRulesSetup) {
    $RuleDir = "$DeployRoot\rules"
    $LogDir  = "$DeployRoot\log"
    New-Item -ItemType Directory -Force -Path $RuleDir, $LogDir | Out-Null

    # --- base suricata.yaml: prefer the build tree's own substituted copy,
    # fall back to the existing IDS install's copy if present (same repo,
    # already known-good), fail clearly if neither exists rather than
    # silently skipping config setup.
    # GOTCHA FIXED: the autotools-substituted suricata.yaml (from
    # suricata.yaml.in via AC_CONFIG_FILES) lands at the TOP LEVEL of the
    # source tree (src root, alongside suricata.yaml.in), not under etc/ -
    # etc/ only has classification.config/reference.config/schema.json/
    # logrotate/service files. Checking the wrong path silently skipped
    # rules setup entirely on the first real end-to-end run.
    $yamlSrc = $null
    foreach ($candidate in @("$SrcDir\suricata.yaml", "$SrcDir\etc\suricata.yaml", "C:\Program Files\Suricata\suricata.yaml")) {
        if (Test-Path $candidate) { $yamlSrc = $candidate; break }
    }
    if (-not $yamlSrc) {
        Warn "  no base suricata.yaml found (checked build tree and existing IDS install) - skipping config/rules setup. Run agb-full-setup.ps1 first, or pass a yaml manually, then re-run with -SkipMsys2Install -SkipPackageInstall -SkipNpcap to just redo this step."
    } else {
        Copy-Item $yamlSrc "$DeployRoot\suricata.yaml" -Force
        $utf8NoBom = New-Object Text.UTF8Encoding($false)
        $y = Get-Content "$DeployRoot\suricata.yaml" -Raw
        function Set-YamlKeyIps([string]$text,[string]$key,[string]$val){
            if($text -match "(?m)^(\s*)$([regex]::Escape($key)):.*$"){ return [regex]::Replace($text,"(?m)^(\s*)$([regex]::Escape($key)):.*$","`${1}${key}: $val",1) }
            return $text
        }
        $y = Set-YamlKeyIps $y 'default-log-dir'   ("'{0}'" -f $LogDir)
        $y = Set-YamlKeyIps $y 'default-rule-path' ("'{0}'" -f $RuleDir)
        if ($HomeNet) { $y = Set-YamlKeyIps $y 'HOME_NET' ('"{0}"' -f $HomeNet) }
        # GOTCHA FIXED: the stock yaml points classification-file/
        # reference-config-file at the official MSI's install path
        # (C:\Program Files\Suricata\...), which doesn't exist for this
        # standalone build - produced hard "could not open" errors on
        # every startup (non-fatal, but noisy and worth fixing since the
        # source files are right there in the build tree already).
        foreach ($cfgFile in @('classification.config', 'reference.config')) {
            $src = "$SrcDir\etc\$cfgFile"
            if (Test-Path $src) { Copy-Item $src $DeployRoot -Force }
        }
        $y = Set-YamlKeyIps $y 'classification-file'    ("'{0}\classification.config'" -f $DeployRoot)
        $y = Set-YamlKeyIps $y 'reference-config-file'  ("'{0}\reference.config'" -f $DeployRoot)
        # rule-files -> ET Open (alert) + agb-black-drop (drop)
        $ylines = $y -split "`r?`n"
        $rf=-1; for($i=0;$i -lt $ylines.Count;$i++){ if($ylines[$i] -match '^\s*rule-files:\s*$'){ $rf=$i; break } }
        if($rf -ge 0){
            $j=$rf+1; while($j -lt $ylines.Count -and $ylines[$j] -match '^\s*#?\s*-\s'){ $j++ }
            $ylines = @($ylines[0..$rf]) + @('  - suricata.rules','  - agb-black-drop.rules') + @($(if($j -le $ylines.Count-1){$ylines[$j..($ylines.Count-1)]}else{@()}))
            $y = $ylines -join "`r`n"
        }
        # same eve-log stats overflow fix as agb-full-setup.ps1 - see that
        # script's comments / README Troubleshooting for the full "why"
        $ylines = $y -split "`r?`n"
        $si=-1; for($i=0;$i -lt $ylines.Count;$i++){ if($ylines[$i] -match '^(\s*)-\s*stats:\s*$'){ $si=$i; break } }
        if($si -ge 0){
            $indent = ($ylines[$si] -replace '-.*$','').Length
            $j=$si+1; while($j -lt $ylines.Count -and $ylines[$j] -match '^\s+\S' -and (($ylines[$j] -replace '^(\s*).*$','$1').Length) -gt $indent){ $j++ }
            $pad = ' ' * ($indent + 4)
            $ylines = @($ylines[0..$si]) + @("$pad" + 'enabled: no') + @($(if($j -le $ylines.Count-1){$ylines[$j..($ylines.Count-1)]}else{@()}))
            $y = $ylines -join "`r`n"
        }
        [IO.File]::WriteAllText("$DeployRoot\suricata.yaml", $y, $utf8NoBom)
        Log "  suricata.yaml written ($DeployRoot\suricata.yaml)"

        Log "  downloading ET Open ruleset (action: alert, unconverted)..."
        $etOk = Get-EtOpenRuleset -suricataExe "$DeployRoot\suricata.exe" -destPath "$RuleDir\suricata.rules" -workDir $WorkRoot
        if ($etOk) {
            $sigCount = ([regex]::Matches([IO.File]::ReadAllText("$RuleDir\suricata.rules"), '(?m)^\s*alert\s')).Count
            Log "  wrote $RuleDir\suricata.rules ($sigCount alert signatures - visibility only, does not block)"
        } else {
            Warn "  could not download ET Open ruleset - proceeding with agb-black.rules only"
        }

        Log "  downloading agb-black.rules and converting to action drop..."
        $agbOk = Get-AgbBlackDropRuleset -destPath "$RuleDir\agb-black-drop.rules"
        if ($agbOk) {
            $dropCount = ([regex]::Matches([IO.File]::ReadAllText("$RuleDir\agb-black-drop.rules"), '(?m)^\s*drop\s')).Count
            Log "  wrote $RuleDir\agb-black-drop.rules ($dropCount signatures converted to drop - these ACTUALLY BLOCK)"
        } else {
            Warn "  could not download agb-black.rules - no rules will actually block until this is fixed"
        }
    }
} else {
    Log "  skipped (-SkipRulesSetup) - deploy folder has only the binary, no yaml/rules"
}

# ---------- Step 11: daily scheduled tasks (keep ET Open + agb-black.rules current) ----------
Log "Step 12/13: daily rule refresh scheduled tasks"
if (-not $SkipScheduledTask -and (Test-Path "$DeployRoot\suricata.yaml")) {
    # No Windows service is registered for the IPS build (it's meant to be
    # run interactively per-test, not continuously in the background - see
    # the safety notes in this script's final output and the README). So
    # these tasks only need to refresh the rule FILES on disk; there is no
    # running process to restart. If you later wire this up as a service
    # yourself, add a restart step here too.
    $IpsScriptsDir = "$WorkRoot\ips-scripts"
    New-Item -ItemType Directory -Force -Path $IpsScriptsDir | Out-Null

    # --- Task A: ET Open ruleset refresh, 13:00 daily (matches the IDS
    # deployment's "Suricata Daily Update And Log Rotation" timing) ---
    $etTaskScript = "$IpsScriptsDir\refresh-et-open.ps1"
    $etBody = @"
`$ErrorActionPreference = 'Continue'
function Get-EtOpenRuleset([string]`$suricataExe, [string]`$destPath, [string]`$workDir) {
    `$ver = (& `$suricataExe -V 2>&1 | Select-String -Pattern '(\d+\.\d+\.\d+)' | Select-Object -First 1).Matches.Groups[1].Value
    `$mm = `$ver.Substring(0, `$ver.LastIndexOf('.'))
    `$tarPath = "`$workDir\emerging.rules.tar.gz"
    `$urls = @("https://rules.emergingthreats.net/open/suricata-`$ver/emerging.rules.tar.gz","https://rules.emergingthreats.net/open/suricata-`$mm.0/emerging.rules.tar.gz","https://rules.emergingthreats.net/open/suricata-`$mm/emerging.rules.tar.gz")
    `$got = `$false
    foreach (`$u in `$urls) { try { Invoke-WebRequest -Uri `$u -OutFile `$tarPath -UseBasicParsing; `$got = `$true; break } catch {} }
    if (-not `$got) { return }
    `$extractDir = "`$workDir\rules-extract"
    if (Test-Path `$extractDir) { Remove-Item `$extractDir -Recurse -Force }
    New-Item -ItemType Directory -Force -Path `$extractDir | Out-Null
    & tar.exe -xzf `$tarPath -C `$extractDir
    `$rfiles = Get-ChildItem (Join-Path `$extractDir 'rules') -Filter *.rules -ErrorAction SilentlyContinue
    if (-not `$rfiles) { `$rfiles = Get-ChildItem `$extractDir -Recurse -Filter *.rules }
    `$sb = New-Object Text.StringBuilder
    foreach (`$f in `$rfiles) { [void]`$sb.AppendLine([IO.File]::ReadAllText(`$f.FullName)) }
    [IO.File]::WriteAllText(`$destPath, `$sb.ToString(), (New-Object Text.UTF8Encoding(`$false)))
}
Get-EtOpenRuleset -suricataExe '$DeployRoot\suricata.exe' -destPath '$RuleDir\suricata.rules' -workDir '$WorkRoot'
"@
    [IO.File]::WriteAllText($etTaskScript, $etBody, (New-Object Text.UTF8Encoding($false)))
    $etAction    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$etTaskScript`""
    $etTrigger   = New-ScheduledTaskTrigger -Daily -At '13:00'
    $etPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName 'AGB-Suricata-IPS-ET-Refresh' -Action $etAction -Trigger $etTrigger -Principal $etPrincipal -Force | Out-Null
    Log "  scheduled task 'AGB-Suricata-IPS-ET-Refresh' registered - daily 13:00 as SYSTEM"

    # --- Task B: agb-black.rules refresh + drop-conversion, 1:30 PM daily
    # (matches the IDS deployment's "AGB-Suricata-Rules-Deploy" timing) ---
    $agbTaskScript = "$IpsScriptsDir\refresh-agb-black-drop.ps1"
    $agbBody = @"
`$ErrorActionPreference = 'Continue'
`$tmpPath = "`$env:TEMP\agb-black-source.rules"
try {
    Invoke-WebRequest -Uri "https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-black.rules" -OutFile `$tmpPath -UseBasicParsing
    `$text = [IO.File]::ReadAllText(`$tmpPath)
    `$dropText = [regex]::Replace(`$text, '(?m)^alert\s', 'drop ')
    [IO.File]::WriteAllText('$RuleDir\agb-black-drop.rules', `$dropText, (New-Object Text.UTF8Encoding(`$false)))
} catch {}
"@
    [IO.File]::WriteAllText($agbTaskScript, $agbBody, (New-Object Text.UTF8Encoding($false)))
    $agbAction    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$agbTaskScript`""
    $agbTrigger   = New-ScheduledTaskTrigger -Daily -At '1:30PM'
    $agbPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName 'AGB-Suricata-IPS-Rules-Deploy' -Action $agbAction -Trigger $agbTrigger -Principal $agbPrincipal -Force | Out-Null
    Log "  scheduled task 'AGB-Suricata-IPS-Rules-Deploy' registered - daily 1:30 PM as SYSTEM"
} else {
    Log "  skipped (-SkipScheduledTask, or Step 10 rules setup did not complete)"
}

# ---------- Step 12: verify ----------
Log "Step 13/13: verify"
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
    Write-Host "This is a SEPARATE, EXPERIMENTAL build - it has NOT touched your existing IDS-mode install." -ForegroundColor Yellow

    $rulesReady = Test-Path "$DeployRoot\suricata.yaml"
    if ($rulesReady) {
        Write-Host ""
        Write-Host "suricata.yaml is ready. suricata.rules (ET Open, alert-only, visibility) and" -ForegroundColor Green
        Write-Host "agb-black-drop.rules (your curated blacklist, action drop - THIS actually blocks)" -ForegroundColor Green
        Write-Host "are both in place. Both refresh daily via the scheduled tasks (13:00 / 1:30 PM)." -ForegroundColor Green
        Write-Host ""
        Write-Host "  NEXT STEP - test (Administrator, interactive - installs a kernel driver on" -ForegroundColor Yellow
        Write-Host "  first use, so run this yourself, not unattended):" -ForegroundColor Yellow
        Write-Host "    cd '$DeployRoot'" -ForegroundColor Yellow
        Write-Host "    .\suricata.exe -c suricata.yaml --windivert `"ip.DstAddr == 152.42.235.124`"" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  Start narrow (one test IP, as above) before ever widening the filter -" -ForegroundColor Red
        Write-Host "  agb-black-drop.rules is small and curated so this is far safer than the" -ForegroundColor Red
        Write-Host "  earlier full-ET-Open-as-drop design, but it's still real inline blocking" -ForegroundColor Red
        Write-Host "  you haven't tested on this exact hardware yet." -ForegroundColor Red
    } else {
        Write-Host ""
        Write-Host "Rules/config setup was skipped or failed - deploy folder has only the bare" -ForegroundColor Yellow
        Write-Host "binary. Re-run without -SkipRulesSetup (or check the Step 10 warning above)" -ForegroundColor Yellow
        Write-Host "to get a testable suricata.yaml + rules." -ForegroundColor Yellow
    }
    Write-Host ""
    Write-Host "Also remember: test on a disposable machine before considering this for a" -ForegroundColor Yellow
    Write-Host "production agent - inline mode sitting in the traffic path is a materially" -ForegroundColor Yellow
    Write-Host "different risk profile than IDS-only." -ForegroundColor Yellow
    # same window-closes-before-you-can-read-it concern as Die() - pause on
    # the success path too if this was launched as a self-closing elevated
    # window (one-liner / shortcut), not just on failure.
    if (-not $NoPrompt) {
        Write-Host ""
        Write-Host "[ips-build] (press Enter to close this window)" -ForegroundColor DarkGray
        Read-Host | Out-Null
    }
} else {
    Die "Build produced a binary but verification failed - check the output above"
}
