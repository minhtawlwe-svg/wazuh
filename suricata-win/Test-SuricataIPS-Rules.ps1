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

    # GOTCHA: rules that pass reliably when tested alone can appear to
    # "leak through" when Run-Test calls happen back-to-back with no gap -
    # WinDivert is a userspace packet-interception layer (packets get
    # diverted out to Suricata for inspection, then reinjected or dropped),
    # and it may not hold every packet under rapid successive connection
    # attempts the same way a kernel-native firewall rule would. A few
    # seconds of spacing before each test avoids conflating that with an
    # actual rule/detection bug - also more representative of the real
    # threat model (an isolated C2/Tor connection attempt, not a rapid-fire
    # test burst).
    Start-Sleep -Seconds 5

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
    # NOTE: $connFailed actually holds the action's raw return value, which
    # for these tests IS Test-NetConnection's TcpTestSucceeded - so
    # $connFailed -eq $false means the CONNECTION FAILED, i.e. it WAS
    # blocked (good). $connFailed -eq $true means it connected, i.e. NOT
    # blocked (bad). Named for what it represents to the caller, not
    # inverted from the raw value - the two branches below were swapped in
    # an earlier version of this script, which made every successful block
    # report as a failure and vice versa; fixed after live testing showed
    # the actual Suricata/WinDivert blocking was correct all along and only
    # this reporting logic was wrong.
    $status = if ($hit) { "PASS" } else { "FAIL" }
    $dropNote = ""
    if ($ExpectDrop) {
        if ($connFailed -eq $false) {
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
            } else {
                $status = "PASS"
            }
        }
        elseif ($connFailed -eq $true) { $dropNote = " | connection SUCCEEDED (NOT blocked - check!)"; $status = "FAIL" }
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
#    GOTCHA FIXED: Resolve-DnsName never sends a real query for .onion at all
#    (Windows treats it as a reserved special-use domain and silently skips
#    it) - confirmed live via direct FileStream read of eve.json showing
#    zero new bytes. nslookup does send a real query and correctly triggers
#    both our rule and a bonus stock ET INFO signature for the same query.
# ============================================================================
Run-Test -Name ".onion DNS query (DNS-level only, not real Tor)" -ManagerRule "100802" `
    -SignaturePattern '^AGB BLACKLIST: Tor \.onion' `
    -Action { nslookup testwazuhdetection.onion 2>$null | Out-Null }

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
# 7b. Cryptomining - Stratum/getblocktemplate protocol pattern -> manager 100700
#     Sends a harmless raw TCP payload matching a REAL ET COINMINER
#     signature's content pattern (sid:2017878, getblocktemplate JSON-RPC
#     request, $HOME_NET -> $EXTERNAL_NET direction) - no actual mining
#     happens, just the matching bytes on the wire.
# ============================================================================
Run-Test -Name "Cryptomining protocol pattern" -ManagerRule "100700" `
    -SignaturePattern 'COINMINER|Crypto Currency Mining' `
    -Note "Sends a harmless payload matching a real ET COINMINER getblocktemplate signature - no actual mining occurs" `
    -Action {
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $tc.Connect("1.1.1.1", 80)
            $stream = $tc.GetStream()
            $payload = [Text.Encoding]::ASCII.GetBytes('{"id":1,"method": "getblocktemplate"}')
            $stream.Write($payload, 0, $payload.Length)
            $stream.Flush()
            Start-Sleep -Milliseconds 500
            $tc.Close()
        } catch {}
    }

# ============================================================================
# 7c. PowerShell high-port hunting rule -> manager 100862 (sid:2044771)
#     Sends the literal bytes "PS C:\" - the real signature's exact content
#     match - to an external high port. tcpbin.com is a well-known public
#     TCP echo test service. No shell/command actually runs; this is just
#     matching text on the wire, same as the signature itself expects.
# ============================================================================
Run-Test -Name "PowerShell high-port hunting rule" -ManagerRule "100862" `
    -SignaturePattern 'PowerShell Command Prompt Outbound On High Port' `
    -Note "tcpbin.com is a public TCP echo test service on a high port - if unreachable, this test can't complete" `
    -Action {
        try {
            $tc = New-Object System.Net.Sockets.TcpClient
            $tc.Connect("tcpbin.com", 4242)
            $stream = $tc.GetStream()
            $payload = [byte[]](0x50,0x53,0x20,0x43,0x3a,0x5c)  # literal "PS C:\"
            $stream.Write($payload, 0, $payload.Length)
            $stream.Flush()
            Start-Sleep -Milliseconds 500
            $tc.Close()
        } catch {}
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
#    20+ in 1 min for SMB) - no local Suricata/eve.json signal.
#    GOTCHA FULLY ROOT-CAUSED (2026-07-07): Sysmon's EID3 (Network Connect)
#    only fires for connections that actually COMPLETE a TCP handshake -
#    confirmed live: a successful Invoke-WebRequest produced 2 EID3 events
#    within 2 seconds (time-windowed FilterXPath query, ruling out both log
#    rotation and event-count-window misses), while every failed/refused/
#    unreachable attempt in this script - the original RFC5737 range
#    (192.0.2.0/24), real routable IPs (8.8.8.8/9.9.9.9/1.1.1.1) on multiple
#    ports, via both Test-NetConnection and a raw TcpClient connect -
#    produced zero. This is NOT a Sysmon config exclusion (powershell.exe is
#    explicitly on the config's NetworkConnect include list, confirmed by
#    dumping the actual config with Sysmon64.exe -c) - it's that these
#    deliberately-safe test targets never complete a handshake at all, and
#    Sysmon simply has nothing to log until one does. Genuinely testing
#    101041/101043 needs 5-20+ REAL, DIFFERENT hosts with actual RDP/WinRM/
#    SMB services listening and accepting connections - not practical or
#    safe to construct from a single machine without dedicated multi-host
#    test infrastructure (same limitation as the inbound port-scan tests).
# ============================================================================
Write-Host "`n=== Lateral movement pattern (Sysmon-based, manager 101041/101043) ===" -ForegroundColor Cyan
Log "generating RDP/WinRM connection attempts to 6 distinct (unreachable) hosts..."
for ($i = 1; $i -le 6; $i++) {
    Test-NetConnection "192.0.2.$i" -Port 3389 -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  SKIPPED (in effect) - Sysmon's EID3 only logs completed handshakes, and these" -ForegroundColor DarkGray
Write-Host "  test targets never accept a connection - confirmed root cause, not a bug in" -ForegroundColor DarkGray
Write-Host "  the manager rule. Needs 5+ REAL, responsive RDP/WinRM hosts to genuinely test." -ForegroundColor DarkGray
$results += [pscustomobject]@{ Test = "Lateral movement (RDP/WinRM)"; Status = "SKIPPED"; ManagerRule = "101041" }

# ============================================================================
# 10. Reconnaissance / ICMP (manager 100600/100601)
#     GOTCHA FIXED: a plain `ping.exe` never matched anything - checked ET
#     Open directly and found every "PING"-named signature (GPL ICMP PING
#     *NIX/BSDtype/Cisco/etc.) is $EXTERNAL_NET -> $HOME_NET (someone pinging
#     INTO this host to fingerprint its OS), not the reverse - same inbound-
#     only limitation as the port-scan signatures below. However, real
#     OUTBOUND ICMP signatures DO exist (malware/backdoor ICMP check-ins) and
#     manager rule 100600 matches "ICMP" broadly, not just "PING" - found a
#     live one requiring an exact 9-byte payload ("Echo This") that
#     System.Net.NetworkInformation.Ping can send without needing raw
#     sockets/admin. Confirmed live: fires BOTH 100600 (ICMP) and 100861
#     (its category is "Malware Command and Control Activity Detected") from
#     one ping. 100601 (bare "PING" in the signature) is NOT covered by this
#     specific payload - left as an open gap, same inbound-only issue as 100602-607.
# ============================================================================
Run-Test -Name "ICMP with malware check-in payload" -ManagerRule "100600 / 100861" `
    -SignaturePattern 'ICMP' `
    -Note "Real ET MALWARE outbound ICMP check-in signature (sid:2009130) - also triggers 100861 (C2 category)" `
    -Action {
        $payload = [Text.Encoding]::ASCII.GetBytes("Echo This")
        $ping = New-Object System.Net.NetworkInformation.Ping
        $ping.Send("8.8.8.8", 2000, $payload) | Out-Null
    }

# ============================================================================
# 10b. Network Trojan (category "A Network Trojan was detected") -> manager 100860
#      Rule 100860 became the SOLE rule for this category after the old
#      100335/100641 duplicates were removed - previously untested. Uses the
#      same craftable-ICMP-payload technique as the check-in test above, but
#      with the "ET MALWARE Gimmiv Infection Ping Outbound" signature (a
#      trojan-activity classtype -> category "A Network Trojan was detected").
#      Needs a 20-byte ICMP payload containing the literal 19-byte string
#      "abcde12345fghij6789". Confirmed live: fires 100860 (and NOT 100861 -
#      different category). No actual malware runs, just the matching bytes.
# ============================================================================
Run-Test -Name "Network Trojan ICMP payload" -ManagerRule "100860" `
    -SignaturePattern 'Gimmiv|Network Trojan' `
    -Note "Real ET MALWARE Gimmiv outbound ICMP signature (trojan-activity classtype) - no malware runs, just the matching payload bytes" `
    -Action {
        $payload = [Text.Encoding]::ASCII.GetBytes("abcde12345fghij67890")  # 20 bytes, contains the 19-byte Gimmiv content
        $ping = New-Object System.Net.NetworkInformation.Ping
        $ping.Send("8.8.8.8", 2000, $payload) | Out-Null
    }

# ============================================================================
# 11. Port scan signatures (100602-100607) - ET SCAN "Suspicious inbound to
#     <port>" signatures are $EXTERNAL_NET -> $HOME_NET (someone scanning
#     INTO this host) - a single machine can't generate genuine inbound scan
#     traffic against itself, so a miss here is expected, not a broken rule.
#     Best-effort self-connect only for completeness.
# ============================================================================
Write-Host "`n=== Port scan signatures (100602-100607) - best-effort only ===" -ForegroundColor Cyan
Write-Host "  These ET SCAN signatures match traffic INTO this host from an EXTERNAL source -" -ForegroundColor DarkGray
Write-Host "  a single machine testing itself cannot generate genuine inbound scan traffic," -ForegroundColor DarkGray
Write-Host "  so a miss here is expected and does not indicate a broken rule." -ForegroundColor DarkGray
foreach ($p in @(5900,22,1433,5432,1521,3306)) {
    Test-NetConnection 127.0.0.1 -Port $p -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  -> would need a genuine external scanner (a second machine) to properly validate" -ForegroundColor DarkYellow
$results += [pscustomobject]@{ Test = "Port scan sigs (VNC/SSH/MSSQL/PgSQL/Oracle/MySQL)"; Status = "SKIPPED"; ManagerRule = "100602-100607" }

# ============================================================================
# 12. Attack Response - "id check returned root" -> manager 100720
#     testmynids.org is a purpose-built public test endpoint that
#     intentionally serves the exact string GPL ATTACK_RESPONSE looks for -
#     designed for safely testing IDS/IPS detection, not a real exploit.
# ============================================================================
Run-Test -Name "Attack Response (testmynids.org)" -ManagerRule "100720" `
    -SignaturePattern 'ATTACK_RESPONSE|id check returned root' `
    -Note "testmynids.org is a purpose-built public test site for this exact signature" `
    -Action { & curl.exe -s -m 8 "http://testmynids.org/uid/index.html" -o $null 2>$null }

# ============================================================================
# 13. Unknown C2 - hardcoded IP match (Sysmon-based) -> manager 100820
#     Manager rule matches Sysmon EID3 (network connect) to this exact IP.
#     GOTCHA FULLY ROOT-CAUSED (2026-07-07): Sysmon's EID3 only logs
#     connections that actually complete a TCP handshake - confirmed live by
#     comparing a successful Invoke-WebRequest (produced 2 EID3 events
#     within 2s) against every failed/refused/timed-out attempt in this
#     script (produced zero, checked via a time-windowed FilterXPath query,
#     not just event count - ruled out log rotation too). 47.236.236.2:443
#     itself does not accept connections (confirmed: TcpTestSucceeded =
#     False), so no script-driven test can make Sysmon log anything for
#     this exact hardcoded IP - it's not a config or logging bug, the
#     target simply never completes a handshake. Untestable from this
#     script as long as that specific IP stays unresponsive.
# ============================================================================
Write-Host "`n=== Unknown C2 hardcoded IP (Sysmon-based, manager 100820) ===" -ForegroundColor Cyan
Write-Host "  SKIPPED - 47.236.236.2:443 does not accept connections, and Sysmon's EID3" -ForegroundColor DarkGray
Write-Host "  only logs connections that complete a handshake - confirmed via live testing" -ForegroundColor DarkGray
Write-Host "  (see the lateral-movement test comments for the full root-cause investigation)" -ForegroundColor DarkGray
$results += [pscustomobject]@{ Test = "Unknown C2 hardcoded IP"; Status = "SKIPPED"; ManagerRule = "100820" }

# ============================================================================
# 14. Reverse-shell/downloader cmdline pattern (Sysmon-based) -> manager 100821
#     Launches a harmless process whose command line merely CONTAINS one of
#     the matched substrings (never actually invoked) - Sysmon logs the full
#     command line regardless of whether anything inside it ever executes,
#     so this is safe.
# ============================================================================
Write-Host "`n=== Reverse-shell cmdline pattern (Sysmon-based, manager 100821) ===" -ForegroundColor Cyan
Start-Process cmd.exe -ArgumentList "/c","echo FromBase64String test - harmless text only, never invoked" -WindowStyle Hidden -Wait
Write-Host "  fired - Sysmon-based, no local Suricata signal to check" -ForegroundColor DarkGray
Write-Host "  -> confirm on Wazuh dashboard: rule 100821" -ForegroundColor DarkYellow
$results += [pscustomobject]@{ Test = "Reverse-shell cmdline pattern"; Status = "MANUAL"; ManagerRule = "100821" }
Write-Host "  (manager rule 100822 - script interpreter to external IP - is already covered" -ForegroundColor DarkGray
Write-Host "   indirectly: every curl/PowerShell test above IS powershell.exe/curl.exe connecting" -ForegroundColor DarkGray
Write-Host "   externally, matching 100822's own pattern)" -ForegroundColor DarkGray

# ============================================================================
# 15. Generic beaconing (any external IP) -> manager 101012
#     Reuses the Tor IP - agb-tor-drop.rules is NOT netsh-AR-gated (unlike
#     the IP blacklist), so repeat hits keep generating fresh Suricata
#     alerts each time instead of being silently firewall-blocked after the
#     first one. 11 rapid hits to cross the 10-hit/300s threshold. Manager-
#     side correlation only - no local eve.json signal for 101012 itself,
#     though each individual 101060 hit IS visible locally.
# ============================================================================
if ($torIp) {
    Write-Host "`n=== Generic beaconing pattern (manager 101012) ===" -ForegroundColor Cyan
    Log "generating 11 rapid connections to the same external IP ($torIp) to cross the 10-hit/300s threshold..."
    for ($i = 1; $i -le 11; $i++) {
        Test-NetConnection $torIp -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Host "  fired - manager-side frequency correlation, no local eve.json signal for 101012 itself" -ForegroundColor DarkGray
    Write-Host "  -> confirm on Wazuh dashboard: rule 101012 (needs 10+ alerts to the same external IP within 300s)" -ForegroundColor DarkYellow
    $results += [pscustomobject]@{ Test = "Generic beaconing"; Status = "MANUAL"; ManagerRule = "101012" }
} else {
    Log "skipping generic beaconing test (no Tor IP available to reuse)"
}

# ============================================================================
# 16. TLS anomaly - self-signed certificate -> manager 101030
#     self-signed.badssl.com is a purpose-built public test site serving a
#     deliberately self-signed cert. NOTE: unlike the other tests, this one
#     depends on ET Open actually shipping a signature whose text matches
#     "self signed"/"SUSPICIOUS TLS"/"invalid certificate" for this exact
#     scenario - unconfirmed whether current ET Open has one, so a miss here
#     is informative but not necessarily a bug.
# ============================================================================
Run-Test -Name "Self-signed TLS certificate (badssl.com)" -ManagerRule "101030" `
    -SignaturePattern '(?i)self.?signed|SUSPICIOUS TLS|invalid.*certificate' `
    -Note "Depends on ET Open shipping a matching signature for this scenario - unconfirmed, a miss is not necessarily a bug" `
    -Action { & curl.exe -sk -m 8 "https://self-signed.badssl.com/" -o $null 2>$null }

# ============================================================================
# 17. SMB lateral movement pattern (Sysmon EID3) -> manager 101043
#     Same approach as the RDP/WinRM test but needs 20+ distinct hosts within
#     1 min. Same fully-root-caused GOTCHA as 101041 above (see that comment
#     block) - Sysmon's EID3 only fires for completed handshakes, and these
#     deliberately-unreachable test targets never complete one.
# ============================================================================
Write-Host "`n=== SMB lateral movement pattern (Sysmon-based, manager 101043) ===" -ForegroundColor Cyan
Log "generating SMB connection attempts to 21 distinct (unreachable) hosts..."
for ($i = 1; $i -le 21; $i++) {
    Test-NetConnection "192.0.2.$i" -Port 445 -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
}
Write-Host "  SKIPPED (in effect) - same root cause as the RDP/WinRM test above: Sysmon" -ForegroundColor DarkGray
Write-Host "  needs a completed handshake to log EID3, and these targets never provide one." -ForegroundColor DarkGray
$results += [pscustomobject]@{ Test = "SMB lateral movement scan"; Status = "SKIPPED"; ManagerRule = "101043" }

# ============================================================================
# 17b. Spamhaus DROP-list beacon -> manager 100740 (base), 100742 (escalation,
#      6+ hits to the same dest_ip within 180s). NOT a synthetic target -
#      pulls a REAL, currently-listed network from Spamhaus's public DROP
#      list (https://www.spamhaus.org/drop/drop.txt) and connects to it.
#      User-approved trade-off: unlike testmynids.org/badssl.com, there is
#      no purpose-built safe test target for this specific list, so this
#      genuinely contacts a real, currently-blacklisted network range.
#      NOTE: rule 100740's description says "verdict from 100921/100922" -
#      if those upstream rules aren't present/active on the manager, this
#      may not escalate as expected; that's a manager-config question, not
#      something this script can verify. Connection-only (TCP SYN), no
#      data sent.
# ============================================================================
Write-Host "`n=== Spamhaus DROP-list beacon (manager 100740/100742) ===" -ForegroundColor Cyan
$spamhausIp = $null
try {
    $dropList = (Invoke-WebRequest -Uri "https://www.spamhaus.org/drop/drop.txt" -UseBasicParsing -TimeoutSec 10).Content
    $firstNet = ($dropList -split "`n" | Where-Object { $_ -match '^\d+\.\d+\.\d+\.\d+/\d+' } | Select-Object -First 1)
    if ($firstNet -match '^(\d+\.\d+\.\d+)\.\d+/') { $spamhausIp = "$($Matches[1]).1" }
} catch { Warn "could not fetch the Spamhaus DROP list: $($_.Exception.Message)" }

if ($spamhausIp) {
    Log "using $spamhausIp from the current Spamhaus DROP list - generating 6 rapid connections to cross the escalation threshold..."
    for ($i = 1; $i -le 6; $i++) {
        Test-NetConnection $spamhausIp -Port 443 -WarningAction SilentlyContinue -InformationLevel Quiet -ErrorAction SilentlyContinue | Out-Null
    }
    Write-Host "  fired - manager-side rule, check eve.json/dashboard for whether Suricata's own" -ForegroundColor DarkGray
    Write-Host "  Spamhaus-intel matching (rules 100921/100922, not visible to this script) engaged" -ForegroundColor DarkGray
    Write-Host "  -> confirm on Wazuh dashboard: rule 100740 (base) / 100742 (6+ hits within 180s)" -ForegroundColor DarkYellow
    $results += [pscustomobject]@{ Test = "Spamhaus DROP-list beacon"; Status = "MANUAL"; ManagerRule = "100740/100742" }
} else {
    Log "skipping Spamhaus test - could not retrieve a current DROP-list entry"
    $results += [pscustomobject]@{ Test = "Spamhaus DROP-list beacon"; Status = "SKIPPED"; ManagerRule = "100740-100742" }
}

# ============================================================================
# 18. Categories with no safe/reliable test payload
#     These all require either a real malware/exploit sample, a genuine
#     external attacker, or connecting to a real live-malicious IP we don't
#     control - none of which is safe to script. Verify these by code review
#     of the manager rule + underlying ET signature instead.
# ============================================================================
Write-Host "`n=== Categories with no safe test payload ===" -ForegroundColor Cyan
$noSafeTest = @(
    @{ Name = "Trojan Activity (100640)";        Rule = "100640" }
    @{ Name = "Exploit Kit activity";            Rule = "100721" }
    @{ Name = "Noise suppression (by design)";   Rule = "100760-100764" }
    @{ Name = "Information Leak";                Rule = "100680" }
    @{ Name = "Privilege Gain";                  Rule = "100780-100782" }
)
foreach ($t in $noSafeTest) {
    Write-Host ("  SKIPPED  {0,-32} rule {1}" -f $t.Name, $t.Rule) -ForegroundColor DarkGray
    $results += [pscustomobject]@{ Test = $t.Name; Status = "SKIPPED"; ManagerRule = $t.Rule }
}
Write-Host "  (100760-100764 are SUPPRESSION rules by design - the goal there is confirming" -ForegroundColor DarkGray
Write-Host "   they DON'T escalate, not triggering an alert; not meaningfully testable in this format)" -ForegroundColor DarkGray
Write-Host "  (100640 matches category 'Trojan Activity' - NOTE this is not a standard Suricata" -ForegroundColor DarkGray
Write-Host "   classification string, so it may never fire; the real trojan detector is 100860," -ForegroundColor DarkGray
Write-Host "   category 'A Network Trojan was detected', which IS tested above via the Gimmiv payload)" -ForegroundColor DarkGray

# ============================================================================
# c2_confirmed (manager 100850) - not a separate test. Fires when 2+
# c2_correlate-tagged rules hit the SAME agent within 5 minutes. This run
# already fired several (100802 IP blacklist, 101000 DGA, 101060 Tor, plus
# Sysmon-based 100820/100821/100840 if those completed) well within that
# window, so 100850 SHOULD already be showing on the dashboard as a side
# effect of the tests above - nothing more to do here except check for it.
# ============================================================================
Write-Host "`n=== c2_confirmed correlation (manager 100850) ===" -ForegroundColor Cyan
Write-Host "  not a separate test - fires when 2+ c2_correlate-tagged rules (100802, 101000," -ForegroundColor DarkGray
Write-Host "  101060, 100820, 100821, 100840) hit this agent within 5 min. This run already" -ForegroundColor DarkGray
Write-Host "  fired several of those, so 100850 should already be on the dashboard too." -ForegroundColor DarkGray
Write-Host "  -> confirm on Wazuh dashboard: rule 100850" -ForegroundColor DarkYellow
$results += [pscustomobject]@{ Test = "c2_confirmed correlation"; Status = "MANUAL"; ManagerRule = "100850" }

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
