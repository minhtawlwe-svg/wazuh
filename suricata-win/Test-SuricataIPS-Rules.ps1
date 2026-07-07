# ============================================================================
#  Test-SuricataIPS-Rules.ps1
#  No admin required - only generates traffic (curl/ping/Test-NetConnection/
#  DNS lookups) and reads eve.json; doesn't touch the service or any files.
# ============================================================================
#  Exercises the ACTUAL production rules loaded by build-suricata-ips.ps1
#  (agb-black-drop.rules, agb-tor-drop.rules, agb-heuristics.rules, plus a
#  sample of stock ET Open categories) - not synthetic WAZUH-TEST markers.
#  For each test: generates the real traffic/action, checks local eve.json
#  for the matching alert (and, for drop rules, confirms the connection was
#  actually blocked), then reports PASS/FAIL/MANUAL plus the exact Wazuh
#  manager rule ID to spot-check on the dashboard for that category - this
#  script can only prove the LOCAL Suricata layer, not the manager rule
#  match itself (no API/SSH access assumed).
#
#  Usage:
#    .\Test-SuricataIPS-Rules.ps1                  # all safe/automatable tests
#    .\Test-SuricataIPS-Rules.ps1 -IncludeSlow     # also the >50MB exfil test
#    .\Test-SuricataIPS-Rules.ps1 -SkipUserAgent   # skip the botnet UA tests
#                                                     (these depend on a live
#                                                     3rd-party site, httpbin.org,
#                                                     being reachable/not rate-
#                                                     limiting - see README gotcha)
# ============================================================================
[CmdletBinding()]
param(
    [string]$DeployRoot = "C:\SuricataIPS",
    [switch]$IncludeSlow,       # large-transfer/exfil test (uploads ~55MB)
    [switch]$SkipUserAgent      # skip the ET Open botnet User-Agent tests
)

$EvePath = Join-Path $DeployRoot "log\eve.json"
$RuleDir = Join-Path $DeployRoot "rules"

function Log($m)  { Write-Host "[test] $m" -ForegroundColor Cyan }
function Warn($m) { Write-Host "[test] WARN: $m" -ForegroundColor Yellow }

if (-not (Test-Path $EvePath)) {
    Write-Host "eve.json not found at $EvePath - is the IPS build/service running? (Get-Service SuricataIPS)" -ForegroundColor Red
    return
}

$svc = Get-Service -Name SuricataIPS -ErrorAction SilentlyContinue
if (-not $svc -or $svc.Status -ne 'Running') {
    Warn "SuricataIPS service is not Running - tests will very likely show 0 hits. Start it first (Start-Service SuricataIPS) or run suricata.exe manually."
}

# ----------------------------------------------------------------------
# Test registry: each entry names what it exercises, the manager rule ID
# to confirm on the dashboard, whether a DROP (blocked connection) is
# expected in addition to the alert, and the action that generates traffic.
# ----------------------------------------------------------------------
$results = @()

function Run-Test {
    param(
        [string]$Name,
        [string]$ManagerRule,
        [string]$SignaturePattern,   # regex against alert.signature in eve.json
        [scriptblock]$Action,
        [switch]$ExpectDrop,
        [string]$TestTarget,   # the IP being tested, for the already-firewalled check
        [string]$Note
    )
    Write-Host "`n=== $Name ===" -ForegroundColor Cyan

    # GOTCHA FIXED: Get-Content -Tail N against eve.json (grows to 10s of MB,
    # actively appended by Suricata) proved unreliable in testing - a known
    # match was confirmed present via direct FileStream read/grep but
    # Get-Content -Tail missed it. Seek-from-a-known-offset with explicit
    # FileShare.ReadWrite (same pattern already proven for reading this log
    # elsewhere in this project) is reliable regardless of file size or
    # concurrent writes.
    $before = (Get-Item $EvePath).Length

    $connFailed = $null
    try {
        $connFailed = & $Action
    } catch { Warn "action threw: $($_.Exception.Message)" }

    $hit = $null
    for ($i = 0; $i -lt 6 -and -not $hit; $i++) {
        Start-Sleep -Seconds 3
        $fs = [IO.File]::Open($EvePath, 'Open', 'Read', 'ReadWrite')
        $fs.Seek($before, 'Begin') | Out-Null
        $sr = New-Object IO.StreamReader($fs)
        $new = $sr.ReadToEnd()
        $sr.Close(); $fs.Close()
        $hit = $new -split "`r?`n" | Where-Object { $_ } | ForEach-Object {
            try {
                $o = $_ | ConvertFrom-Json
                if ($o.event_type -eq 'alert' -and $o.alert.signature -match $SignaturePattern) { $o }
            } catch {}
        } | Select-Object -First 1
    }

    # GOTCHA: for drop rules, once agb-kill-block.ps1 (the netsh AR) has
    # already firewalled an IP from an earlier trigger, later test runs
    # against that SAME IP get blocked by Windows Firewall before the
    # packet ever reaches WinDivert/Suricata - so "blocked, no NEW alert"
    # is the CORRECT outcome then, not a miss. Confirmed live: an already-
    # AR-blocked IP showed exactly this (connection failed, zero new eve.json
    # entries), while the same IP tested via a clean rule (no prior AR hit)
    # produced both the block AND the alert normally.
    $status = if ($hit) { "PASS" } else { "FAIL" }
    $dropNote = ""
    if ($ExpectDrop) {
        if ($connFailed -eq $true) {
            $dropNote = " | connection BLOCKED (confirmed)"
            if (-not $hit) {
                $fwHit = Get-NetFirewallRule -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match [regex]::Escape($TestTarget) }
                if ($fwHit) {
                    $status = "PASS"
                    $dropNote += " | no NEW alert because this IP already has a netsh AR firewall rule from an earlier trigger (expected - packet never reached Suricata)"
                } else {
                    $status = "FAIL"
                    $dropNote += " | blocked but no alert AND no pre-existing firewall rule found - genuinely worth investigating"
                }
            }
        }
        elseif ($connFailed -eq $false) { $dropNote = " | connection SUCCEEDED (NOT blocked - check!)"; $status = "FAIL" }
    }

    if ($hit) {
        Write-Host "  [$status] alert: $($hit.alert.signature)$dropNote" -ForegroundColor $(if($status -eq "PASS"){"Green"}else{"Yellow"})
    } else {
        Write-Host "  [$status] no matching alert seen in eve.json$dropNote" -ForegroundColor $(if($status -eq "PASS"){"Green"}else{"Red"})
    }
    if ($Note) { Write-Host "  note: $Note" -ForegroundColor DarkGray }
    Write-Host "  -> confirm on Wazuh dashboard: rule $ManagerRule" -ForegroundColor DarkYellow

    $script:results += [pscustomobject]@{
        Test = $Name; Status = $status; ManagerRule = $ManagerRule
    }
}

# ============================================================================
# 1. IP Blacklist (agb-black-drop.rules) -> manager 100802 (+ c2_confirmed 100850)
# ============================================================================
Run-Test -Name "IP Blacklist block" -ManagerRule "100802" `
    -SignaturePattern '^AGB BLACKLIST: known test C2 IP' -ExpectDrop -TestTarget "152.42.235.124" `
    -Action {
        $r = Test-NetConnection 152.42.235.124 -Port 80 -WarningAction SilentlyContinue
        return $r.TcpTestSucceeded
    }

# ============================================================================
# 2. Tor network block (agb-tor-drop.rules) -> manager 101060
#    Pulls a REAL Tor node IP from the currently-loaded rule file so this
#    stays valid as the daily ET refresh rotates the list.
# ============================================================================
$torIp = $null
if (Test-Path "$RuleDir\agb-tor-drop.rules") {
    $torLine = Get-Content "$RuleDir\agb-tor-drop.rules" | Select-Object -First 1
    if ($torLine -match '\[([0-9.]+)') { $torIp = $Matches[1] }
}
if ($torIp) {
    Run-Test -Name "Tor network block" -ManagerRule "101060" `
        -SignaturePattern '^ET TOR Known Tor' -ExpectDrop -TestTarget $torIp `
        -Action {
            $r = Test-NetConnection $torIp -Port 443 -WarningAction SilentlyContinue
            return $r.TcpTestSucceeded
        }
} else {
    Warn "agb-tor-drop.rules not found or empty - skipping Tor test (was -SkipTorBlock used at build time?)"
}

# ============================================================================
# 3. .onion DNS query (agb-black.rules sid:1000102) -> manager 100802
#    (same "^AGB BLACKLIST:" prefix match as the IP list rule)
#    Alert-only - Tor Browser itself never generates this query (see project
#    notes), this only catches a literal DNS lookup for a .onion name.
# ============================================================================
Run-Test -Name ".onion DNS query (DNS-level only, not real Tor)" -ManagerRule "100802" `
    -SignaturePattern '^AGB BLACKLIST: Tor \.onion' `
    -Action { Resolve-DnsName "testwazuhdetection.onion" -ErrorAction SilentlyContinue | Out-Null }

# ============================================================================
# 4. DGA domain heuristic (agb-heuristics.rules sid:1000200) -> manager 101000
# ============================================================================
$dgaDomain = -join ((97..122) + (48..57) | Get-Random -Count 24 | ForEach-Object {[char]$_})
Run-Test -Name "DGA-shaped domain query ($dgaDomain.xyz)" -ManagerRule "101000" `
    -SignaturePattern '^AGB HEURISTIC: Possible DGA domain' `
    -Action { Resolve-DnsName "$dgaDomain.xyz" -ErrorAction SilentlyContinue | Out-Null }

# ============================================================================
# 5. Encoded PowerShell (built-in Sysmon rule 92057) -> manager 100840
#    Harmless payload - just Write-Host, base64-encoded like a real dropper
#    would send it. This is a SYSMON/manager-side rule, not a Suricata one -
#    no local eve.json signal to check, so this just fires the action and
#    tells you which rule to look for on the dashboard.
# ============================================================================
Write-Host "`n=== Encoded PowerShell (Sysmon-based, manager rule 100840) ===" -ForegroundColor Cyan
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'wazuh-detection-test'"))
Start-Process powershell.exe -ArgumentList "-NoProfile","-EncodedCommand",$enc -WindowStyle Hidden -Wait
Write-Host "  fired - this is Sysmon-based (rule 92057 -> 100840), no local Suricata signal to check" -ForegroundColor DarkGray
Write-Host "  -> confirm on Wazuh dashboard: rule 100840 (and base rule 92057)" -ForegroundColor DarkYellow
$results += [pscustomobject]@{ Test = "Encoded PowerShell"; Status = "MANUAL"; ManagerRule = "100840" }

# ============================================================================
# 6. Botnet User-Agent signatures (stock ET Open) -> manager 100660 (Web App Attack)
#    NOTE: these depend on httpbin.org being reachable and not itself
#    rate-limiting/blocking the request - a 503 from httpbin.org does not
#    necessarily mean Suricata failed to see/log the request.
# ============================================================================
if (-not $SkipUserAgent) {
    $uaTests = @(
        @{ UA = "Katana/";           Sig = "ET MALWARE ELF/Mirai Variant User-Agent" }
        @{ UA = "dark_NeXus";        Sig = "ET MALWARE Dark Nexus IoT Variant User-Agent" }
        @{ UA = "DVRBOT";            Sig = "ET MALWARE ELF/Mirai Variant User-Agent" }
        @{ UA = "polaris botnet";    Sig = "ET MALWARE Polaris Botnet User-Agent" }
        @{ UA = "iamdelta";          Sig = "ET MALWARE ELF/Mirai Variant User-Agent" }
        @{ UA = "Forthgoer";         Sig = "ET ADWARE_PUP Likely Hostile User-Agent" }
    )
    foreach ($t in $uaTests) {
        Run-Test -Name "Botnet User-Agent: $($t.UA)" -ManagerRule "100660" `
            -SignaturePattern [regex]::Escape($t.Sig) `
            -Note "Depends on httpbin.org being reachable; a 503 from the site itself is not a Suricata failure" `
            -Action { & curl.exe -s -m 8 -H "User-Agent: $($t.UA)" "http://httpbin.org/get" -o $null 2>$null }
    }
} else {
    Log "skipping botnet User-Agent tests (-SkipUserAgent)"
}

# ============================================================================
# 7. Large outbound transfer / exfil heuristic (sid:1000201) -> manager 101020
#    Opt-in (-IncludeSlow): uploads ~55MB to httpbin.org to cross the 50MB
#    stream_size threshold. Slow and consumes real bandwidth - skipped by default.
# ============================================================================
if ($IncludeSlow) {
    Log "generating ~55MB upload for the exfil heuristic (this will take a bit)..."
    $tmpFile = Join-Path $env:TEMP "exfil-test-blob.bin"
    $fs = [IO.File]::Create($tmpFile)
    $fs.SetLength(55MB); $fs.Close()
    Run-Test -Name "Large outbound transfer (exfil heuristic)" -ManagerRule "101020" `
        -SignaturePattern '^AGB HEURISTIC: Large outbound data transfer' `
        -Note "Threshold is 50MB client-sent bytes in one flow - can take a while over a slow link" `
        -Action { & curl.exe -s -m 120 -F "file=@$tmpFile" "https://httpbin.org/post" -o $null 2>$null }
    Remove-Item $tmpFile -Force -ErrorAction SilentlyContinue
} else {
    Log "skipping large-transfer/exfil test (pass -IncludeSlow to run it - uploads ~55MB)"
}

# ============================================================================
# 8. JA3 fingerprint heuristic (sid:1000210/1000211) -> manager 101031
#    Cannot be safely/easily generated without a tool that spoofs a specific
#    malware family's TLS ClientHello - documented as untestable here.
# ============================================================================
Write-Host "`n=== JA3 fingerprint heuristic (manager 101031) ===" -ForegroundColor Cyan
Write-Host "  SKIPPED - requires a TLS client producing one of the exact JA3 hashes in" -ForegroundColor DarkGray
Write-Host "  agb-heuristics.rules (sid:1000210/1000211); no safe way to generate that traffic" -ForegroundColor DarkGray
Write-Host "  from a script. Verify by code review of agb-heuristics.rules instead." -ForegroundColor DarkGray
$results += [pscustomobject]@{ Test = "JA3 fingerprint"; Status = "SKIPPED"; ManagerRule = "101031" }

# ============================================================================
# 9. Lateral movement pattern (Sysmon EID3) -> manager 101041 (RDP/WinRM), 101043 (SMB)
#    Manager-side correlation only (5+ distinct hosts in 2 min for RDP/WinRM,
#    20+ in 1 min for SMB) - no local Suricata/eve.json signal. Uses
#    unreachable RFC5737 documentation IPs (192.0.2.0/24) so nothing is
#    actually contacted, but Sysmon still logs the outbound connection attempt.
# ============================================================================
Write-Host "`n=== Lateral movement pattern (Sysmon-based, manager 101041/101043) ===" -ForegroundColor Cyan
Log "generating RDP/WinRM connection attempts to 6 distinct (unreachable) hosts..."
for ($i = 1; $i -le 6; $i++) {
    Test-NetConnection "192.0.2.$i" -Port 3389 -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  fired - Sysmon-based, no local Suricata signal to check" -ForegroundColor DarkGray
Write-Host "  -> confirm on Wazuh dashboard: rule 101041 (needs 5+ distinct hosts within 2 min)" -ForegroundColor DarkYellow
$results += [pscustomobject]@{ Test = "Lateral movement (RDP/WinRM)"; Status = "MANUAL"; ManagerRule = "101041" }

# ============================================================================
# 10. Reconnaissance / ICMP (manager 100600/100601)
# ============================================================================
Run-Test -Name "ICMP ping (reconnaissance)" -ManagerRule "100600 / 100601" `
    -SignaturePattern 'ICMP|PING' `
    -Note "ET Open's generic ICMP/PING signatures - may be noisy/already-suppressed depending on agb-white.rules" `
    -Action { & ping.exe -n 2 8.8.8.8 | Out-Null }

# ============================================================================
# Summary
# ============================================================================
Write-Host "`n===== SUMMARY =====" -ForegroundColor Cyan
$results | Format-Table Test, Status, @{Name="ManagerRule";Expression={$_.ManagerRule}} -AutoSize
$pass = ($results | Where-Object Status -eq "PASS").Count
$fail = ($results | Where-Object Status -eq "FAIL").Count
$manual = ($results | Where-Object { $_.Status -in "MANUAL","SKIPPED" }).Count
Write-Host "PASS: $pass   FAIL: $fail   MANUAL/SKIPPED (check dashboard or code): $manual" -ForegroundColor $(if($fail -eq 0){"Green"}else{"Yellow"})
Write-Host "`nFor every MANUAL/PASS entry, still worth spot-checking the listed manager rule ID on the" -ForegroundColor DarkGray
Write-Host "Wazuh dashboard - this script only proves the LOCAL Suricata/Sysmon layer, not the manager match." -ForegroundColor DarkGray
