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
# CHANGELOG 2026-07-07 (hardening review):
#   - NEW -RepoRef param: pin ALL repo downloads (rules + AR scripts) to a
#     commit SHA instead of the git-home branch (supply-chain protection)
#   - the two daily refresh tasks merged into ONE validated task: staged
#     download, per-file syntax whitelist, suricata -T check, auto-rollback,
#     single service restart (was: blind overwrite + 2 restarts/day)
#   - suricata -T config gate before the always-on service is installed
#   - WinSW wrapper fallback if the sc.exe-registered service hits the
#     classic console-app 1053 startup failure
#   - ET TOR direction-reversal regex now reports lines it could NOT
#     convert (ET format drift detection)
#   - SHA256 of deployed Active Response scripts logged for audit
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
    [string]$RepoRef              = "git-home",            # branch OR full commit SHA for ALL raw.githubusercontent downloads (agb rules + AR scripts). SECURITY: pass a pinned 40-char commit SHA here - a branch ref means anyone who ever compromises the repo can push new rule/AR content that every deployed machine pulls daily as SYSTEM. A pinned SHA freezes what gets pulled until you deliberately bump it.
    [string]$WorkRoot             = "C:\msys64\suricata-ips-build",
    [string]$DeployRoot           = "C:\SuricataIPS",       # final self-contained output
    [string]$NpcapUrl             = "https://npcap.com/dist/npcap-1.82.exe",
    [string]$HomeNet              = "",                     # blank = keep stock RFC1918
    [string]$CaptureInterfaceName = "",                     # blank = auto-pick fastest UP adapter
    [switch]$NoPrompt,                                     # skip both interactive prompts
    [switch]$SkipMsys2Install,                              # if MSYS2 already installed
    [switch]$SkipPackageInstall,                           # if deps already installed
    [switch]$SkipNpcap,                                    # if the Npcap DRIVER is already installed
    [switch]$SkipRulesSetup,                               # skip Step 11 - leaves just the bare binary, no yaml/rules
    [switch]$SkipScheduledTask,                            # skip Step 12 - no daily rule refresh
    [switch]$SkipWazuhWiring,                              # skip Step 13 - don't touch the Wazuh agent's ossec.conf
    [switch]$SkipService,                                  # skip Step 14 - by default this build registers as an always-on service (see the warning it prints; still requires a typed YES unless -NoPrompt)
    [string]$WinDivertFilter      = "true",                # WinDivert filter for the Step 14 service. "true" = capture BOTH directions of all traffic, which is REQUIRED for HTTP/TLS content inspection: Suricata must see the inbound response side of a TCP flow to reassemble the stream and run app-layer (HTTP/TLS) parsing. The old "outbound"-only default silently broke ALL HTTP-content signatures (confirmed live 2026-07-07: zero event_type:http for external sites, so User-Agent/URL/etc. rules never fired) while leaving IP/DNS/ICMP rules working (those match single packets, no reassembly). "true" is heavier (all traffic through userspace) but is the only way inline HTTP detection actually works - pass a scoped filter here (e.g. 'tcp.DstPort==80 or tcp.SrcPort==80') to trade coverage for lower overhead.
    [switch]$SkipTorBlock                                  # by default, ET TOR node-IP signatures are converted to drop (blocks Tor network access, not just .onion) - pass this to keep them alert-only instead
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
# single source of truth for every download out of this repo - see -RepoRef above
$RepoRawBase = "https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/$RepoRef/suricata-win"
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
Log "Step 0/15: Windows Defender exclusions"
# Pre-create both folders (empty) before asking for the exclusion, so the
# Windows Security "Add an exclusion > Folder" picker has a real, browsable
# path to select on a completely fresh machine - it existing empty doesn't
# weaken the protection ordering, since no actual content (MSYS2 packages,
# the compiled binary) gets written into either folder until later steps,
# well after the exclusion is confirmed active below.
New-Item -ItemType Directory -Force -Path 'C:\msys64' | Out-Null
New-Item -ItemType Directory -Force -Path $DeployRoot | Out-Null
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
Log "Step 1/15: MSYS2 base install"
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
Log "Step 2/15: build dependencies (this can take a while + may need retries - see gotcha)"
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
Log "Step 3/15: Npcap driver"
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
Log "Step 4/15: WinDivert 1.4.3"
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
Log "Step 5/15: Npcap SDK (headers/libs for linking)"
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
Log "Step 6/15: Suricata source ($SuricataVersion)"
$SrcDir = "$WorkRoot\suricata-src"
if (-not (Test-Path "$SrcDir\configure.ac")) {
    Log "  cloning..."
    Invoke-Bash "git clone --branch $SuricataVersion --depth 1 https://github.com/OISF/suricata.git '$($SrcDir -replace '\\','/')'" | Out-Null
    if (-not (Test-Path "$SrcDir\configure.ac")) { Die "Suricata source clone failed" }
} else {
    Log "  already present, skipping"
}

# ---------- Step 7: patch a real upstream bug - WinDivert never marks IPS mode ----------
Log "Step 7/15: patching known upstream bug (WinDivert eve.json action field)"
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
Log "Step 8/15: autogen.sh + configure (WinDivert + Npcap flags)"
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
Log "Step 9/15: make (this is the long step - Rust crate compile alone took ~10 min in testing)"
$cores = [Environment]::ProcessorCount
$makeOut = Invoke-Bash "cd '$srcUnix' && make -j$cores"
$exitLine = $makeOut | Select-String "^make: \*\*\*" | Select-Object -Last 1
if ($exitLine) { Die "make failed: $exitLine`nFull log was very long - re-run manually to see it: MSYSTEM=UCRT64 bash -lc `"cd '$srcUnix' && make -j$cores`"" }
Log "  build completed"

# ---------- Step 9: find the REAL binary + assemble deploy folder ----------
Log "Step 10/15: locating real binary + assembling self-contained deploy folder"
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
# GOTCHA FIXED: if a previous test run's suricata.exe used --windivert,
# the WinDivert1.4 kernel driver stays LOADED (State: Running) even after
# that process exits - Windows locks a .sys file while its driver is
# loaded, so overwriting it on a rebuild fails with "The process cannot
# access the file ... because it is being used by another process." Found
# via `driverquery /v` - it does NOT show up under Get-Service (it's a
# raw kernel driver, not a normal SCM-visible service), so a Get-Service
# check alone would miss it. Stop it first if present; harmless no-op if
# no prior test ever ran.
foreach ($svcName in @("WinDivert1.4", "WinDivert1.2", "WinDivert")) {
    try { & sc.exe stop $svcName 2>&1 | Out-Null; Start-Sleep -Milliseconds 500 } catch {}
}
foreach ($sys in @("WinDivert64.sys", "WinDivert32.sys")) {
    $src = "$WinDivertLib\$sys"
    if (Test-Path $src) {
        try {
            Copy-Item $src $DeployRoot -Force -ErrorAction Stop
        } catch {
            Die "Could not copy $sys - it's likely still locked by a running suricata.exe or its kernel driver. Close any window still running '.\suricata.exe ... --windivert' first, or run 'sc.exe stop WinDivert1.4' (elevated) manually, then re-run this script."
        }
    }
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
        Invoke-WebRequest -Uri "$RepoRawBase/agb-black.rules" -OutFile $tmpPath -UseBasicParsing
    } catch { return $false }
    $text = [IO.File]::ReadAllText($tmpPath)
    $dropText = [regex]::Replace($text, '(?m)^alert\s', 'drop ')
    [IO.File]::WriteAllText($destPath, $dropText, (New-Object Text.UTF8Encoding($false)))
    return $true
}

# ---------- Step 10: config + rules (ET Open = alert, agb-black.rules = drop) ----------
Log "Step 11/15: suricata.yaml + rules (ET Open stays alert-only, agb-black.rules converted to drop)"
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
        # GOTCHA FIXED: the stock yaml's ja3-fingerprints key is COMMENTED
        # OUT by default ("#ja3-fingerprints: auto"), not present as a live
        # "no" value - the original regex only matched an uncommented line
        # starting with whitespace, so it silently never found this key at
        # all on a real build. "auto" (the compiled-in default when the
        # line is absent/commented) is documented in the yaml itself as
        # "disabled by default, but enabled if rules require it" - meaning
        # agb-heuristics.rules' ja3.hash rules may already trigger it
        # automatically - but force it to an explicit "yes" anyway for
        # certainty rather than relying on that auto-detection.
        if ($y -match '(?m)^(\s*)#\s*ja3-fingerprints:.*$') {
            $y = [regex]::Replace($y, '(?m)^(\s*)#\s*ja3-fingerprints:.*$', '${1}ja3-fingerprints: yes', 1)
        } elseif ($y -match '(?m)^(\s*)ja3-fingerprints:.*$') {
            $y = Set-YamlKeyIps $y 'ja3-fingerprints' 'yes'
        } else {
            Warn "  ja3-fingerprints key not found (commented or not) in stock suricata.yaml - JA3 rules in agb-heuristics.rules may not match anything until this is enabled manually"
        }
        # GOTCHA FIXED (severe - broke all new outbound connections): the
        # stock yaml's stream.checksum-validation defaults to "yes" ("reject
        # incorrect csums"), which is correct for passive/IDS capture (a
        # tap/mirror sees packets AFTER the NIC has already computed the
        # real checksum) but wrong for WinDivert inline interception, which
        # catches packets BEFORE NIC hardware checksum offload fills in the
        # real value - Suricata sees the placeholder as "invalid" and drops
        # it. Confirmed live: nearly every packet (49 of 50 in one stats
        # interval) showed tcp.invalid_checksum, and new connections timed
        # out consistently. This had been silently masked for a long time by
        # a background VPN client's own kernel driver seemingly handling
        # some traffic differently - only surfaced as a full internet outage
        # once that VPN was uninstalled and real traffic hit WinDivert
        # directly. Force it off so every matching packet is judged on
        # content, not a checksum that was never going to be real at this
        # interception point.
        $y = Set-YamlKeyIps $y 'checksum-validation' 'no'
        # GOTCHA FIXED (same investigation as above): stock yaml's
        # exception-policy defaults to "auto", which its own doc comment
        # says resolves to drop-flow in IPS mode - any stream anomaly (e.g.
        # a flow misclassified as a "midstream" pickup) then drops the
        # WHOLE flow rather than just logging it, compounding the
        # checksum-validation problem above. Fixed to "ignore" - confirmed
        # live this was still causing timeouts even after the checksum fix
        # alone. NOTE: cannot use Set-YamlKeyIps here - "exception-policy:"
        # also appears as a bare, indented sub-key under the stats config
        # earlier in the file (empty value, unrelated section), and
        # Set-YamlKeyIps's (\s*) prefix would match that FIRST occurrence
        # instead of the real top-level setting. Match only the true
        # zero-indent top-level line instead.
        $y = [regex]::Replace($y, '(?m)^exception-policy:.*$', 'exception-policy: ignore', 1)
        # rule-files -> agb-white.rules (pass) + ET Open (alert) + agb-black-drop (drop)
        # GOTCHA FIXED: agb-white.rules (the pass-rule whitelist that
        # suppresses known-good noise like *.agb.mywire.org DYN_DNS alerts)
        # was never included here at all - only agb-full-setup.ps1's IDS
        # deployment loaded it. Confirmed on a live run: the exact pass
        # rule needed already existed in the repo (sid:1000010) but never
        # got a chance to apply since this build didn't download or list
        # the file. Suricata's action-order (pass before alert/drop by
        # default) means list position doesn't matter for precedence, only
        # that the file is actually loaded at all.
        $ylines = $y -split "`r?`n"
        $rf=-1; for($i=0;$i -lt $ylines.Count;$i++){ if($ylines[$i] -match '^\s*rule-files:\s*$'){ $rf=$i; break } }
        if($rf -ge 0){
            $j=$rf+1; while($j -lt $ylines.Count -and $ylines[$j] -match '^\s*#?\s*-\s'){ $j++ }
            $ruleFileList = @('  - agb-white.rules','  - suricata.rules','  - agb-black-drop.rules','  - agb-heuristics.rules')
            if (-not $SkipTorBlock) { $ruleFileList += '  - agb-tor-drop.rules' }
            $ylines = @($ylines[0..$rf]) + $ruleFileList + @($(if($j -le $ylines.Count-1){$ylines[$j..($ylines.Count-1)]}else{@()}))
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

        Log "  downloading agb-white.rules (pass rules, unmodified)..."
        try {
            Invoke-WebRequest -Uri "$RepoRawBase/agb-white.rules" -OutFile "$RuleDir\agb-white.rules" -UseBasicParsing
            $passCount = ([regex]::Matches([IO.File]::ReadAllText("$RuleDir\agb-white.rules"), '(?m)^\s*pass\s')).Count
            Log "  wrote $RuleDir\agb-white.rules ($passCount pass signatures)"
        } catch {
            Warn "  could not download agb-white.rules ($($_.Exception.Message)) - known-good traffic (e.g. *.agb.mywire.org) will alert/log normally instead of being suppressed"
        }

        Log "  downloading ET Open ruleset (action: alert, unconverted)..."
        $etOk = Get-EtOpenRuleset -suricataExe "$DeployRoot\suricata.exe" -destPath "$RuleDir\suricata.rules" -workDir $WorkRoot
        if ($etOk) {
            $sigCount = ([regex]::Matches([IO.File]::ReadAllText("$RuleDir\suricata.rules"), '(?m)^\s*alert\s')).Count
            Log "  wrote $RuleDir\suricata.rules ($sigCount alert signatures - visibility only, does not block)"

            if (-not $SkipTorBlock) {
                # GOTCHA: a DNS-query rule for .onion (agb-black.rules
                # sid:1000102) can NEVER catch real Tor Browser usage - Tor
                # resolves .onion internally through its own encrypted
                # circuit protocol, never generating a plain DNS query.
                # The only way to actually block Tor is to block the
                # CONNECTION to the Tor network itself. ET Open already
                # ships ~883 "ET TOR Known Tor Exit/Relay Node" signatures
                # matching a maintained list of real Tor node IPs -
                # extracted here and converted to drop, same "small
                # curated high-confidence subset" treatment as
                # agb-black-drop.rules, NOT the full 50K ruleset. Removed
                # from suricata.rules afterward so the same SID doesn't
                # load twice (once as alert, once as drop) across two rule
                # files, which Suricata would reject.
                # Default ON as of 2026-07-06 (was opt-in -BlockTor) - the
                # download-first invocation needed to pass a custom switch
                # was tripping people up who kept running the plain
                # iwr|iex one-liner instead, which can never pass
                # parameters. Pass -SkipTorBlock to keep Tor traffic
                # alert-only instead (e.g. for legitimate research use).
                Log "  extracting ET TOR node-IP signatures and converting to drop (pass -SkipTorBlock to disable)..."
                $allEt = [IO.File]::ReadAllText("$RuleDir\suricata.rules")
                $etLines = $allEt -split "`r?`n"
                $torLines = $etLines | Where-Object { $_ -match 'msg:"ET TOR (Known Tor Exit Node|Known Tor Relay/Router)' }
                if ($torLines.Count -gt 0) {
                    # GOTCHA FIXED: these ET signatures are written as
                    # "[TorIPs] any -> $HOME_NET any" - they only match a
                    # Tor node CONNECTING INTO the network (an
                    # inbound-scanning/attack detection use case), not a
                    # local host CONNECTING OUT to Tor, which is what
                    # actually needs to be blocked here (Tor Browser
                    # initiating a circuit). Confirmed live: a direct
                    # Test-NetConnection to a listed Tor IP succeeded
                    # (not blocked) with the rule in its original
                    # direction. Swap source/dest so it reads
                    # "$HOME_NET any -> [TorIPs] any" instead.
                    $torDropText = ($torLines -join "`r`n") -replace '(?m)^alert tcp (\[[^\]]+\]) any -> \$HOME_NET any', 'drop tcp $HOME_NET any -> $1 any'
                    # GOTCHA FIXED: the stock signature carries a
                    # "threshold: type limit, track by_src, seconds 60,
                    # count 1;" clause - meant to cap ALERT volume when this
                    # was alert-only, but it ALSO limits how often the DROP
                    # action fires. Confirmed live: the first SYN packet to
                    # a Tor IP got dropped (logged action:"blocked"), but
                    # Windows' own automatic TCP retransmission of that same
                    # SYN a moment later was NOT re-inspected/re-dropped
                    # (threshold already consumed for that source), reached
                    # the real Tor node, got a SYN-ACK, and the connection
                    # "succeeded" overall despite the alert firing correctly.
                    # Strip the threshold entirely so every matching packet
                    # is dropped, not just the first one per source per
                    # minute - the whole point of converting this to a
                    # blocking rule instead of leaving it alert-only.
                    $torDropText = $torDropText -replace 'threshold:\s*type limit,\s*track by_src,\s*seconds \d+,\s*count \d+;\s*', ''
                    # GOTCHA GUARD: the direction-reversal regex above only matches the
                    # exact "alert tcp [...] any -> $HOME_NET any" header shape ET uses
                    # today. If ET ever changes that format, non-matching lines silently
                    # stay alert-only inside this drop file - surface the count so the
                    # drift is visible instead of invisible.
                    $torStillAlert = ([regex]::Matches($torDropText, '(?m)^alert\s')).Count
                    if ($torStillAlert -gt 0) { Warn "  $torStillAlert ET TOR signature(s) did not match the expected header format and remain ALERT-only inside agb-tor-drop.rules - ET format may have drifted, review the file" }
                    [IO.File]::WriteAllText("$RuleDir\agb-tor-drop.rules", $torDropText, (New-Object Text.UTF8Encoding($false)))
                    $keptLines = $etLines | Where-Object { $_ -notmatch 'msg:"ET TOR (Known Tor Exit Node|Known Tor Relay/Router)' }
                    [IO.File]::WriteAllText("$RuleDir\suricata.rules", ($keptLines -join "`r`n"), (New-Object Text.UTF8Encoding($false)))
                    Log "  wrote $RuleDir\agb-tor-drop.rules ($($torLines.Count) Tor node-IP signatures converted to drop, direction reversed + rate-limit threshold stripped - blocks every matching connection attempt, not just .onion)"
                } else {
                    Warn "  no ET TOR signatures were found in the downloaded ruleset - nothing to convert"
                }
            }
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

        Log "  downloading agb-heuristics.rules (DGA/exfil/JA3 heuristics, alert-only)..."
        try {
            Invoke-WebRequest -Uri "$RepoRawBase/agb-heuristics.rules" -OutFile "$RuleDir\agb-heuristics.rules" -UseBasicParsing
            Log "  wrote $RuleDir\agb-heuristics.rules"
        } catch {
            Warn "  could not download agb-heuristics.rules ($($_.Exception.Message))"
        }
    }
} else {
    Log "  skipped (-SkipRulesSetup) - deploy folder has only the binary, no yaml/rules"
}

# ---------- Step 11: daily validated rule refresh (single task) ----------
Log "Step 12/15: daily rule refresh scheduled task (staged + validated + single restart)"
# GOTCHA FIXED (x3, all found in review):
#   1. The old refresh tasks downloaded rules and IMMEDIATELY restarted the
#      service - a truncated download or an ET rule this build rejects would
#      restart the service into a failed state at 13:00 with nobody watching.
#      Now: everything downloads into a STAGING dir, every file is
#      syntax-checked (only comments/blank/pass/alert/drop/reject lines
#      allowed - kills truncated files, HTML error pages, and injected
#      content), the swap happens atomically with a backup, the FULL config
#      is validated with `suricata.exe -T`, and on failure the old rules are
#      rolled back and the service is left alone.
#   2. Two separate tasks (13:00 + 1:30 PM) each restarted the service -
#      every restart is a brief fail-open blocking gap. Merged into ONE task
#      with ONE restart.
#   3. The agb-* downloads pulled from a branch ref as SYSTEM daily - a
#      repo compromise = arbitrary rule injection on every deployed machine.
#      The syntax whitelist limits blast radius to rule content only (no
#      code execution), and -RepoRef lets you pin a commit SHA to freeze it
#      completely.
if (-not $SkipScheduledTask -and (Test-Path "$DeployRoot\suricata.yaml")) {
    $IpsScriptsDir = "$WorkRoot\ips-scripts"
    New-Item -ItemType Directory -Force -Path $IpsScriptsDir | Out-Null
    $refreshScript = "$IpsScriptsDir\refresh-suricata-ips-rules.ps1"

    # written as a literal template + token replace, NOT an expandable
    # here-string - the old nested backtick-escaping approach was where the
    # previous version's bugs kept hiding.
    $refreshTemplate = @'
# refresh-suricata-ips-rules.ps1 - generated by build-suricata-ips.ps1
# Daily task: stage ET Open + agb rules, syntax-check every file, swap in
# with backup, validate full config via suricata -T, roll back on failure,
# restart the SuricataIPS service ONCE (only if it was already running).
$ErrorActionPreference = 'Continue'
$DeployRoot = '__DEPLOYROOT__'
$RuleDir    = '__RULEDIR__'
$WorkRoot   = '__WORKROOT__'
$RawBase    = '__RAWBASE__'
$BlockTor   = __BLOCKTOR__
$LogFile    = "$WorkRoot\ips-scripts\refresh.log"
function RLog([string]$m) { "$(Get-Date -Format s) $m" | Add-Content -Path $LogFile }
if ((Test-Path $LogFile) -and ((Get-Item $LogFile).Length -gt 1MB)) { Remove-Item $LogFile -Force }

# A rules file may contain ONLY blank lines, comments, and
# pass/alert/drop/reject signatures. Anything else (truncated download,
# HTML error page, injected content) rejects the WHOLE file - the previous
# known-good copy stays in place.
function Test-RulesSane([string]$path, [int]$minRules) {
    if (-not (Test-Path $path)) { return $false }
    $count = 0
    foreach ($l in [IO.File]::ReadLines($path)) {
        $t = $l.Trim()
        if ($t -eq '' -or $t.StartsWith('#')) { continue }
        if ($t -match '^(pass|alert|drop|reject)\s') { $count++; continue }
        RLog "REJECT $path - unexpected content: $($t.Substring(0, [Math]::Min(120, $t.Length)))"
        return $false
    }
    if ($count -lt $minRules) { RLog "REJECT $path - only $count rules (expected >= $minRules)"; return $false }
    return $true
}

$Staging = "$WorkRoot\rules-staging"
if (Test-Path $Staging) { Remove-Item $Staging -Recurse -Force }
New-Item -ItemType Directory -Force -Path $Staging | Out-Null
$updated = @()

# ---- ET Open (with Content-Length verification) ----
try {
    $ver = (& "$DeployRoot\suricata.exe" -V 2>&1 | Select-String -Pattern '(\d+\.\d+\.\d+)' | Select-Object -First 1).Matches.Groups[1].Value
    $mm  = $ver.Substring(0, $ver.LastIndexOf('.'))
    $tarPath = "$Staging\emerging.rules.tar.gz"
    $got = $false
    foreach ($u in @("https://rules.emergingthreats.net/open/suricata-$ver/emerging.rules.tar.gz",
                     "https://rules.emergingthreats.net/open/suricata-$mm.0/emerging.rules.tar.gz",
                     "https://rules.emergingthreats.net/open/suricata-$mm/emerging.rules.tar.gz")) {
        try {
            $expected = (Invoke-WebRequest -Uri $u -Method Head -UseBasicParsing).Headers.'Content-Length' | Select-Object -Last 1
            Invoke-WebRequest -Uri $u -OutFile $tarPath -UseBasicParsing
            if ($expected -and ("$((Get-Item $tarPath).Length)" -ne "$expected")) { RLog "SIZE MISMATCH from $u - retrying next mirror"; continue }
            $got = $true; break
        } catch { RLog "ET download failed from $u : $($_.Exception.Message)" }
    }
    if ($got) {
        $extractDir = "$Staging\rules-extract"
        New-Item -ItemType Directory -Force -Path $extractDir | Out-Null
        & tar.exe -xzf $tarPath -C $extractDir
        $rfiles = Get-ChildItem (Join-Path $extractDir 'rules') -Filter *.rules -ErrorAction SilentlyContinue
        if (-not $rfiles) { $rfiles = Get-ChildItem $extractDir -Recurse -Filter *.rules }
        $sb = New-Object Text.StringBuilder
        foreach ($f in $rfiles) { [void]$sb.AppendLine([IO.File]::ReadAllText($f.FullName)) }
        [IO.File]::WriteAllText("$Staging\suricata.rules", $sb.ToString(), (New-Object Text.UTF8Encoding($false)))

        if ($BlockTor) {
            $etLines  = [IO.File]::ReadAllText("$Staging\suricata.rules") -split "`r?`n"
            $torLines = $etLines | Where-Object { $_ -match 'msg:"ET TOR (Known Tor Exit Node|Known Tor Relay/Router)' }
            if ($torLines.Count -gt 0) {
                $torDropText = ($torLines -join "`r`n") -replace '(?m)^alert tcp (\[[^\]]+\]) any -> \$HOME_NET any', 'drop tcp $HOME_NET any -> $1 any'
                $torDropText = $torDropText -replace 'threshold:\s*type limit,\s*track by_src,\s*seconds \d+,\s*count \d+;\s*', ''
                $stillAlert = ([regex]::Matches($torDropText, '(?m)^alert\s')).Count
                if ($stillAlert -gt 0) { RLog "WARN $stillAlert ET TOR line(s) did not match the direction-reversal pattern and remain alert-only (ET format drift?)" }
                [IO.File]::WriteAllText("$Staging\agb-tor-drop.rules", $torDropText, (New-Object Text.UTF8Encoding($false)))
                $kept = $etLines | Where-Object { $_ -notmatch 'msg:"ET TOR (Known Tor Exit Node|Known Tor Relay/Router)' }
                [IO.File]::WriteAllText("$Staging\suricata.rules", ($kept -join "`r`n"), (New-Object Text.UTF8Encoding($false)))
                if (Test-RulesSane "$Staging\agb-tor-drop.rules" 100) { $updated += 'agb-tor-drop.rules' }
            }
        }
        if (Test-RulesSane "$Staging\suricata.rules" 10000) { $updated += 'suricata.rules' }
    }
} catch { RLog "ET refresh error: $($_.Exception.Message)" }

# ---- agb rules from the repo (frozen if -RepoRef was a pinned commit SHA) ----
try {
    Invoke-WebRequest -Uri "$RawBase/agb-black.rules" -OutFile "$Staging\agb-black-src.rules" -UseBasicParsing
    $dropText = [regex]::Replace([IO.File]::ReadAllText("$Staging\agb-black-src.rules"), '(?m)^alert\s', 'drop ')
    [IO.File]::WriteAllText("$Staging\agb-black-drop.rules", $dropText, (New-Object Text.UTF8Encoding($false)))
    if (Test-RulesSane "$Staging\agb-black-drop.rules" 1) { $updated += 'agb-black-drop.rules' }
} catch { RLog "agb-black download failed: $($_.Exception.Message)" }
foreach ($rf in @('agb-white.rules', 'agb-heuristics.rules')) {
    try {
        Invoke-WebRequest -Uri "$RawBase/$rf" -OutFile "$Staging\$rf" -UseBasicParsing
        if (Test-RulesSane "$Staging\$rf" 1) { $updated += $rf }
    } catch { RLog "$rf download failed: $($_.Exception.Message)" }
}

if ($updated.Count -eq 0) { RLog "nothing passed validation - current rules left untouched"; exit 0 }

# ---- swap with backup + suricata -T validation + rollback ----
$BackupDir = "$WorkRoot\rules-backup"
if (Test-Path $BackupDir) { Remove-Item $BackupDir -Recurse -Force }
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
foreach ($f in $updated) {
    if (Test-Path "$RuleDir\$f") { Copy-Item "$RuleDir\$f" "$BackupDir\$f" -Force }
    Copy-Item "$Staging\$f" "$RuleDir\$f" -Force
}
& "$DeployRoot\suricata.exe" -c "$DeployRoot\suricata.yaml" -T 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    RLog "suricata -T FAILED with new rules (exit $LASTEXITCODE) - rolling back: $($updated -join ', ')"
    foreach ($f in $updated) {
        if (Test-Path "$BackupDir\$f") { Copy-Item "$BackupDir\$f" "$RuleDir\$f" -Force }
        else { Remove-Item "$RuleDir\$f" -Force -ErrorAction SilentlyContinue }
    }
    exit 1
}
RLog "validated OK - applied: $($updated -join ', ')"

# ---- single service restart, only if it was already running ----
$svc = Get-Service -Name 'SuricataIPS' -ErrorAction SilentlyContinue
if ($svc -and $svc.Status -eq 'Running') {
    Restart-Service -Name 'SuricataIPS' -Force -ErrorAction SilentlyContinue
    RLog "SuricataIPS restarted with refreshed rules"
}
'@

    $refreshBody = $refreshTemplate.
        Replace('__DEPLOYROOT__', $DeployRoot).
        Replace('__RULEDIR__',    $RuleDir).
        Replace('__WORKROOT__',   $WorkRoot).
        Replace('__RAWBASE__',    $RepoRawBase).
        Replace('__BLOCKTOR__',   $(if ($SkipTorBlock) { '$false' } else { '$true' }))
    [IO.File]::WriteAllText($refreshScript, $refreshBody, (New-Object Text.UTF8Encoding($false)))

    $rAction    = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$refreshScript`""
    $rTrigger   = New-ScheduledTaskTrigger -Daily -At '13:00'
    $rPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName 'AGB-Suricata-IPS-Rules-Refresh' -Action $rAction -Trigger $rTrigger -Principal $rPrincipal -Force | Out-Null
    # clean up the two legacy tasks from earlier versions of this script so
    # a machine that ran the old build doesn't end up triple-refreshing
    foreach ($legacy in @('AGB-Suricata-IPS-ET-Refresh', 'AGB-Suricata-IPS-Rules-Deploy')) {
        Unregister-ScheduledTask -TaskName $legacy -Confirm:$false -ErrorAction SilentlyContinue
    }
    Log "  scheduled task 'AGB-Suricata-IPS-Rules-Refresh' registered - daily 13:00 as SYSTEM (staged, syntax-checked, suricata -T validated, auto-rollback, single restart; log: $IpsScriptsDir\refresh.log)"
} else {
    Log "  skipped (-SkipScheduledTask, or Step 11 rules setup did not complete)"
}

# ---------- Step 13: wire the IPS build's eve.json into the Wazuh agent ----------
Log "Step 13/15: Wazuh agent wiring (eve.json localfile + netsh Active Response)"
$ossecConf = "C:\Program Files (x86)\ossec-agent\ossec.conf"
if ($SkipWazuhWiring) {
    Log "  skipped (-SkipWazuhWiring)"
} elseif (-not (Test-Path $ossecConf)) {
    Log "  no Wazuh agent found at $ossecConf - skipping (this build works standalone without Wazuh too)"
} elseif (-not (Test-Path "$DeployRoot\log\eve.json") -and -not (Test-Path "$DeployRoot\rules")) {
    Log "  skipped - rules/log setup (Step 11) didn't complete, nothing to wire up yet"
} else {
    # GOTCHA: this build's eve.json is a SEPARATE file from any existing
    # IDS-mode Suricata's eve.json (agb-full-setup.ps1) - they don't
    # collide, but Wazuh needs its OWN <localfile> entry for this one, it
    # won't pick it up automatically just because a similar entry may
    # already exist for the other Suricata instance.
    $eveLocation = "$DeployRoot\log\eve.json"
    $content = Get-Content $ossecConf -Raw
    if ($content -match [regex]::Escape($eveLocation)) {
        Log "  already wired up, skipping"
    } else {
        $backupPath = "$ossecConf.bak-ips-$(Get-Date -Format yyyyMMdd-HHmmss)"
        Copy-Item $ossecConf $backupPath -Force
        Log "  backed up ossec.conf -> $backupPath"

        $newBlock = "  <localfile>`r`n    <log_format>json</log_format>`r`n    <location>$eveLocation</location>`r`n  </localfile>`r`n`r`n"
        # Insert before the LAST </ossec_config> close tag - more robust
        # than matching any specific existing block's exact formatting,
        # since that varies machine to machine (confirmed the hard way:
        # this laptop had no prior Suricata localfile entry to pattern-
        # match against at all).
        $lastClose = $content.LastIndexOf("</ossec_config>")
        if ($lastClose -lt 0) {
            Warn "  no </ossec_config> found in ossec.conf - this file may be malformed. Skipping wiring; restore from $backupPath if needed."
        } else {
            $patched = $content.Substring(0, $lastClose) + $newBlock + $content.Substring($lastClose)
            Set-Content -Path $ossecConf -Value $patched -NoNewline
            Log "  added <localfile> for $eveLocation"

            try {
                Restart-Service -Name WazuhSvc -ErrorAction Stop
                Start-Sleep -Seconds 3
                $svc = Get-Service -Name WazuhSvc -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq 'Running') {
                    Log "  Wazuh agent restarted and running - IPS eve.json now shipping to your manager"
                } else {
                    Warn "  Wazuh agent restart did not come back Running - check manually: Get-Service WazuhSvc. Restore $backupPath and restart again if it won't start."
                }
            } catch {
                Warn "  could not restart WazuhSvc ($($_.Exception.Message)) - restart it manually: Restart-Service WazuhSvc"
            }
        }
    }

    # --- deploy the netsh-based Active Response script, so this agent can
    # ALSO run the existing kill+block AR as a redundant backup layer
    # behind WinDivert's instant inline block. This is the hybrid design
    # this whole IPS project has been building toward: WinDivert drops the
    # packet immediately (zero dependency on Wazuh), while the same event
    # still ships to Wazuh -> matches the same manager rule (86601 ->
    # 100802, tagged c2_autokill) -> the manager dispatches AR back to
    # THIS agent -> agb-kill-block.ps1 fires a few seconds later,
    # netsh-blocking the IP and killing the offending process too.
    # GOTCHA: this only deploys the SCRIPT FILES to the agent's AR bin
    # folder (a client-side requirement - execd looks up the executable by
    # name here). The manager-side <command>/<active-response> wiring that
    # maps the AR name to this script and triggers it for rules_group
    # c2_autokill is a ONE-TIME, group-wide manager config already set up
    # earlier for other agents - not something this Windows-side script
    # can or needs to configure per-agent. If AR still doesn't fire after
    # this, check the agent is in the right Wazuh group on the manager.
    $arBinDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"
    if (Test-Path $arBinDir) {
        Log "  deploying agb-kill-block.ps1/.cmd (netsh Active Response) to $arBinDir"
        try {
            Invoke-WebRequest -Uri "$RepoRawBase/wazuh-manager/active-response/agb-kill-block.ps1" -OutFile "$arBinDir\agb-kill-block.ps1" -UseBasicParsing
            Invoke-WebRequest -Uri "$RepoRawBase/wazuh-manager/active-response/agb-kill-block.cmd" -OutFile "$arBinDir\agb-kill-block.cmd" -UseBasicParsing
            # SECURITY: log the SHA256 of what was actually deployed - these
            # files EXECUTE as SYSTEM when AR fires, so having the hash in the
            # build log gives an audit trail to compare against the repo (and a
            # reason to pin -RepoRef to a commit SHA instead of a branch).
            foreach ($arFile in @("$arBinDir\agb-kill-block.ps1", "$arBinDir\agb-kill-block.cmd")) {
                try { Log ("  SHA256 " + (Split-Path $arFile -Leaf) + ": " + (Get-FileHash $arFile -Algorithm SHA256).Hash) } catch {}
            }
            Log "  deployed - this agent can now run the netsh kill+block AR alongside WinDivert's instant inline block"
        } catch {
            Warn "  could not deploy agb-kill-block AR script ($($_.Exception.Message)) - IPS blocking still works, just without the redundant netsh/kill backup layer"
        }
    } else {
        Log "  no active-response\bin folder found - skipping AR script deployment"
    }
}

# ---------- Step 14: install as an always-on Windows service (default-on) ----------
Log "Step 14/15: Windows service"
if ($SkipService) {
    Log "  skipped (-SkipService) - build stops at the manual/foreground-test stage"
} else {
    # GOTCHA: Suricata's own --service-install hardcodes the service name
    # as "Suricata" (PROG_NAME, a compile-time constant in suricata.h, not
    # configurable via CLI) - registering under that name risks a
    # collision with a regular IDS-mode Suricata service if one's ever
    # added on the same machine. Register directly via sc.exe under a
    # distinct name instead. Same logic as the standalone
    # install-suricata-ips-service.ps1, inlined here for a one-command
    # build+run-as-service flow; that script still exists separately for
    # adding the service to an already-built deployment later.
    #
    # This step is ON by default (pass -SkipService to opt out), but still
    # requires a typed YES confirmation unless -NoPrompt was also passed -
    # this script is published in a shared repo other people may run, and
    # continuous unattended inline blocking is a materially bigger
    # commitment than the manual/supervised test every other step leads
    # to, so a human still has to explicitly confirm it, every time,
    # regardless of the default.
    Write-Host ""
    Write-Host "########################################################################" -ForegroundColor Red
    Write-Host "#  WARNING: this step registers a Windows SERVICE that auto-starts on   #" -ForegroundColor Red
    Write-Host "#  boot and runs Suricata in REAL INLINE TRAFFIC-BLOCKING mode           #" -ForegroundColor Red
    Write-Host "#  continuously, in the background, with no window to watch or Ctrl+C.   #" -ForegroundColor Red
    Write-Host "#  A crash, a bad rule, or unexpected blocking behavior would now affect  #" -ForegroundColor Red
    Write-Host "#  this machine's connectivity unattended, until you notice and stop it.  #" -ForegroundColor Red
    Write-Host "#  Only do this on a machine you've already tested thoroughly.            #" -ForegroundColor Red
    Write-Host "#  Pass -SkipService to build without this step instead.                  #" -ForegroundColor Red
    Write-Host "########################################################################" -ForegroundColor Red
    Write-Host ""
    $svcConfirmed = $NoPrompt
    if (-not $svcConfirmed) {
        # GOTCHA FIXED: a silent Start-Sleep before Read-Host doesn't
        # protect against anything typed DURING the sleep - the console
        # still queues those keystrokes, and Read-Host can immediately
        # consume that queued input the instant it starts, instead of
        # waiting for a fresh keypress. Looks exactly like the prompt
        # "auto-dropped" before there was time to type YES. Fixed by
        # showing a visible countdown (so it's clear when to start typing)
        # AND explicitly flushing the input buffer right before Read-Host,
        # so anything typed too early is discarded rather than consumed.
        for ($i = 8; $i -ge 1; $i--) {
            Write-Host "`r  (prompt appears in $i...)  " -NoNewline -ForegroundColor DarkGray
            Start-Sleep -Seconds 1
        }
        Write-Host "`r                              `r" -NoNewline
        try { $Host.UI.RawUI.FlushInputBuffer() } catch {}
        $ans = Read-Host "Type YES to confirm you understand and want the always-on service (anything else skips it)"
        $svcConfirmed = ($ans -eq "YES")
    }
    if (-not $svcConfirmed) {
        Log "  not confirmed - skipping service install (build itself is unaffected; re-run with -SkipService to skip this prompt entirely, or -NoPrompt to auto-confirm everything)"
    } else {
        # GOTCHA FIXED (review finding): nothing ever ran `suricata -T`
        # before registering an always-on, auto-start service - a config or
        # rules problem would only surface as an unattended failed service
        # at the next boot. Validate the full config HERE, visibly, and
        # refuse to install the service if it can't load.
        Log "  validating full config with suricata -T before installing the service..."
        # GOTCHA FIXED (crashed the whole build on 2026-07-08): suricata -T on
        # Windows ALWAYS exits non-zero and prints "E: ... unknown rule keyword
        # 'file.magic'" for ~9 ET Open signatures - the Windows build ships no
        # libmagic, so those rules are harmlessly SKIPPED at runtime while
        # everything else loads fine. The original gate had two bugs:
        #  (a) `& suricata.exe ... 2>&1` let that stderr become a TERMINATING
        #      error under the script-wide $ErrorActionPreference='Stop',
        #      aborting the entire build with "UNHANDLED ERROR: ... file.magic"
        #  (b) it treated ANY non-zero exit as fatal, so it could NEVER pass on
        #      Windows even without the crash.
        # Fix: capture output with EAP relaxed, then fail ONLY on errors that
        # are NOT the known-harmless file.magic ones - exactly the rule
        # deploy-agb-rules.ps1 already applies.
        $testOut = $null
        Push-Location $DeployRoot
        $savedEAP = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
        try { $testOut = & ".\suricata.exe" -c "suricata.yaml" -T 2>&1 } catch { $testOut = "$($_.Exception.Message)" } finally { $ErrorActionPreference = $savedEAP; Pop-Location }
        $errLines   = @($testOut | Where-Object { "$_" -match '^E:' })
        $realErrors = @($errLines | Where-Object { "$_" -notmatch "file\.magic" })
        if ($realErrors.Count -gt 0) {
            Warn "  suricata -T found REAL errors (not just the harmless file.magic ones) - refusing to install an always-on service on a config that will not load. Debug it: cd '$DeployRoot'; .\suricata.exe -c suricata.yaml -T -v"
            $realErrors | Select-Object -First 5 | ForEach-Object { Warn "    $_" }
        } else {
        if ($errLines.Count -gt 0) { Log "  config test passed (ignored $($errLines.Count) expected file.magic errors - those ET rules skip, everything else loads)" } else { Log "  config test passed" }
        $svcName = "SuricataIPS"
        $existingSvc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
        if ($existingSvc) {
            if ($existingSvc.Status -eq 'Running') { Stop-Service -Name $svcName -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 2 }
            & sc.exe delete $svcName | Out-Null
            Start-Sleep -Seconds 1
        }
        $binPath = "`"$DeployRoot\suricata.exe`" -c `"$DeployRoot\suricata.yaml`" --windivert `"$WinDivertFilter`""
        & sc.exe create $svcName binPath= $binPath start= auto DisplayName= "Suricata IPS (WinDivert, experimental)" | Out-Null
        if ($LASTEXITCODE -ne 0) {
            Warn "  sc.exe create failed (exit $LASTEXITCODE) - service not installed, build itself still succeeded"
        } else {
            & sc.exe description $svcName "Experimental inline-blocking Suricata build (WinDivert). Filter: $WinDivertFilter. Managed by build-suricata-ips.ps1 in minhtawlwe-svg/wazuh." | Out-Null
            & sc.exe failure $svcName reset= 86400 actions= restart/5000/restart/30000/restart/60000 | Out-Null
            try {
                Start-Service -Name $svcName -ErrorAction Stop
                Start-Sleep -Seconds 3
                $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                if ($svc -and $svc.Status -eq 'Running') {
                    Log "  '$svcName' installed and running (filter: $WinDivertFilter) - auto-starts on boot. Stop-Service $svcName / .\install-suricata-ips-service.ps1 -Remove to undo."
                } else {
                    # GOTCHA FIXED (review finding): suricata.exe is a console
                    # binary - registering it directly via sc.exe relies on it
                    # implementing the SCM handshake, which classically fails
                    # with error 1053 ("did not respond in a timely fashion")
                    # even though the process itself works fine. It DID come up
                    # Running in the validated 2026-07-04/05 build, but if it
                    # ever doesn't, fall back to the WinSW service wrapper,
                    # which handles the SCM protocol itself and just supervises
                    # suricata.exe as a child process.
                    Warn "  service not Running via plain sc.exe (status: $(if ($svc) { $svc.Status } else { 'missing' })) - likely the classic console-app/SCM 1053 issue. Retrying with the WinSW service wrapper..."
                    & sc.exe delete $svcName | Out-Null
                    Start-Sleep -Seconds 1
                    $winswExe = "$DeployRoot\SuricataIPS-winsw.exe"
                    $winswXmlPath = "$DeployRoot\SuricataIPS-winsw.xml"
                    try {
                        Invoke-WebRequest -Uri "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe" -OutFile $winswExe -UseBasicParsing
                        $winswXml = @"
<service>
  <id>$svcName</id>
  <name>Suricata IPS (WinDivert, experimental)</name>
  <description>Experimental inline-blocking Suricata build (WinDivert). Filter: $WinDivertFilter. Managed by build-suricata-ips.ps1 (WinSW-wrapped).</description>
  <executable>$DeployRoot\suricata.exe</executable>
  <arguments>-c "$DeployRoot\suricata.yaml" --windivert "$WinDivertFilter"</arguments>
  <workingdirectory>$DeployRoot</workingdirectory>
  <startmode>Automatic</startmode>
  <onfailure action="restart" delay="5 sec"/>
  <onfailure action="restart" delay="30 sec"/>
  <onfailure action="restart" delay="60 sec"/>
  <log mode="roll"></log>
</service>
"@
                        [IO.File]::WriteAllText($winswXmlPath, $winswXml, (New-Object Text.UTF8Encoding($false)))
                        & $winswExe install $winswXmlPath 2>&1 | Out-Null
                        & $winswExe start   $winswXmlPath 2>&1 | Out-Null
                        Start-Sleep -Seconds 3
                        $svc = Get-Service -Name $svcName -ErrorAction SilentlyContinue
                        if ($svc -and $svc.Status -eq 'Running') {
                            Log "  '$svcName' installed and running via WinSW wrapper (filter: $WinDivertFilter) - auto-starts on boot. Remove: & '$winswExe' uninstall '$winswXmlPath'"
                        } else {
                            Warn "  still not Running even via WinSW - check $DeployRoot\log\suricata.log and the WinSW wrapper log next to $winswExe"
                        }
                    } catch {
                        Warn "  WinSW fallback failed ($($_.Exception.Message)) - no service installed. The build itself is fine; test in the foreground instead: cd '$DeployRoot'; .\suricata.exe -c suricata.yaml --windivert `"$WinDivertFilter`""
                    }
                }
            } catch {
                Warn "  Start-Service failed ($($_.Exception.Message)) - service is registered but not started"
            }
        }
        }
    }
}

# ---------- Step 15: verify ----------
Log "Step 15/15: verify"
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
    $svcNowRunning = (Get-Service -Name "SuricataIPS" -ErrorAction SilentlyContinue).Status -eq 'Running'
    if ($rulesReady -and $svcNowRunning) {
        Write-Host ""
        Write-Host "suricata.yaml + rules are ready, and the 'SuricataIPS' service is installed and" -ForegroundColor Green
        Write-Host "RUNNING NOW (filter: $WinDivertFilter) - it auto-starts on boot from here on." -ForegroundColor Green
        Write-Host "Check on it:   Get-Service SuricataIPS" -ForegroundColor Yellow
        Write-Host "Stop it:       Stop-Service SuricataIPS" -ForegroundColor Yellow
        Write-Host "Remove it:     .\install-suricata-ips-service.ps1 -Remove  (or -SkipService next build)" -ForegroundColor Yellow
    } elseif ($rulesReady) {
        Write-Host ""
        Write-Host "suricata.yaml is ready. agb-white.rules (pass, suppresses known-good noise)," -ForegroundColor Green
        Write-Host "suricata.rules (ET Open, alert-only, visibility), and agb-black-drop.rules" -ForegroundColor Green
        Write-Host "(your curated blacklist, action drop - THIS actually blocks) are all in place." -ForegroundColor Green
        Write-Host "All refresh daily at 13:00 via ONE validated task (staged download, syntax" -ForegroundColor Green
        Write-Host "check, suricata -T, auto-rollback, single service restart)." -ForegroundColor Green
        if (Test-Path "$RuleDir\agb-tor-drop.rules") {
            Write-Host "agb-tor-drop.rules is also in place - blocks connections to known Tor relay/exit" -ForegroundColor Green
            Write-Host "nodes, not just .onion DNS queries (which real Tor Browser traffic never" -ForegroundColor Green
            Write-Host "generates in the first place). Pass -SkipTorBlock next build to disable this." -ForegroundColor Green
        }
        Write-Host ""
        Write-Host "  The always-on service was skipped (declined at the prompt, or -SkipService)." -ForegroundColor Yellow
        Write-Host "  NEXT STEP - test manually instead (Administrator, interactive - installs a" -ForegroundColor Yellow
        Write-Host "  kernel driver on first use, so run this yourself, not unattended):" -ForegroundColor Yellow
        Write-Host "    cd '$DeployRoot'" -ForegroundColor Yellow
        Write-Host "    .\suricata.exe -c suricata.yaml --windivert `"true`"" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "  'true' captures BOTH directions of all traffic - REQUIRED for HTTP/TLS content" -ForegroundColor Yellow
        Write-Host "  inspection to work (Suricata needs the inbound response side to reassemble the" -ForegroundColor Yellow
        Write-Host "  TCP stream). The old 'outbound'-only filter silently broke every HTTP-content" -ForegroundColor Yellow
        Write-Host "  signature. Only agb-black-drop.rules' small curated set can ever DROP (ET Open" -ForegroundColor Yellow
        Write-Host "  stays alert-only), so this is safe. For a narrower single-IP block test instead:" -ForegroundColor Yellow
        Write-Host "    .\suricata.exe -c suricata.yaml --windivert `"ip.DstAddr == 152.42.235.124`"" -ForegroundColor Yellow
        Write-Host "  It's still real inline blocking on real traffic either way - test on a" -ForegroundColor Red
        Write-Host "  disposable machine before ever considering this for a production agent." -ForegroundColor Red
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
