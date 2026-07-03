# ============================================================================
# AGB Active Response: kill process + block IP on CONFIRMED blacklist hit
# ============================================================================
# Triggered ONLY by explicit blacklist rules (IOC list match or agb-black.rules
# signature) - NOT by heuristic/behavioral rules, which stay alert-only for
# human review. See project_c2_detection_engineering memory for the full
# rule design.
#
# Wazuh AR gotchas respected (see feedback_wazuh_windows_ar_stdin.md,
# feedback_wazuh_custom_ar_no_log.md):
#   - execd keeps stdin open -> MUST ReadLine(), never ReadToEnd() (would hang)
#   - custom AR scripts get NO automatic logging - this script logs itself
#   - use taskkill/Stop-Process, not pskill (can hang as SYSTEM)
#
# Install: copy to <ossec-agent>\active-response\bin\agb-kill-block.ps1 on
# EVERY agent that should enforce this (see DEPLOY section in
# project_c2_detection_engineering memory / suricata-win README).
# ============================================================================

$LogFile = "C:\Program Files (x86)\ossec-agent\active-response\agb-kill-block.log"
function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

Log "===== AR invoked ====="

# --- Read exactly ONE line from stdin (never ReadToEnd - execd keeps stdin open) ---
$raw = [Console]::In.ReadLine()
if (-not $raw) { Log "no input received - exiting"; exit 0 }
Log "raw input: $raw"

try {
    $payload = $raw | ConvertFrom-Json
} catch {
    Log "failed to parse JSON: $($_.Exception.Message)"
    exit 1
}

$command = $payload.command
Log "command: $command"

if ($command -ne "add") {
    # "delete" = Wazuh's automatic revert after a configured timeout. We do
    # NOT auto-unblock a confirmed blacklist IP - leave the firewall rule in
    # place; remove it manually once you've investigated. Just acknowledge.
    Log "command is '$command' (not 'add') - no automatic revert for a confirmed blacklist hit, exiting"
    exit 0
}

$alert = $payload.parameters.alert
if (-not $alert) { Log "no alert object in payload - exiting"; exit 1 }

# --- SAFETY: never block on a DNS-type event. For event_type:"dns", dest_ip
# is the DNS RESOLVER's IP (e.g. 8.8.8.8 or the org's DNS server), NOT the
# malicious domain's actual IP - Suricata's DNS record has no resolved-IP
# field usable for this. Blocking it would firewall your own DNS server
# instead of the bad domain. Domain-based agb-black.rules alerts (or rule
# 100314) should stay alert-only; the ACTUAL connection to the resolved IP
# (a separate flow/alert event) is what the IP-based rules correctly catch. -->
if ($alert.data.event_type -eq "dns") {
    Log "[!] event_type=dns - dest_ip would be the DNS resolver, not the malicious domain's IP. Skipping block (domain-based detection stays alert-only by design). Add the RESOLVED IP to agb-black.rules once known instead."
    Log "===== AR complete (skipped - dns event) ====="
    exit 0
}

# --- Extract IP from whichever field is present (Suricata OR Sysmon side) ---
$ip = $null
foreach ($path in @(
    { $alert.data.dest_ip },
    { $alert.data.src_ip },
    { $alert.data.win.eventdata.destinationIp },
    { $alert.dest_ip }
)) {
    try { $v = & $path; if ($v) { $ip = $v; break } } catch {}
}

# --- Extract process info if present (Sysmon-side rules only, e.g. 100974) ---
$procImage = $alert.data.win.eventdata.image
$procId    = $alert.data.win.eventdata.processId

Log "extracted: ip=$ip processImage=$procImage processId=$procId"

# --- 1. Block the IP (both directions) ---
if ($ip) {
    $ruleName = "AGB-BLOCK-$ip"
    $existing = netsh advfirewall firewall show rule name="$ruleName" 2>&1
    if ($existing -match "No rules match") {
        netsh advfirewall firewall add rule name="$ruleName" dir=out action=block remoteip="$ip" | Out-Null
        netsh advfirewall firewall add rule name="$ruleName-in" dir=in action=block remoteip="$ip" | Out-Null
        Log "[+] Blocked IP $ip (inbound + outbound firewall rules added)"
    } else {
        Log "[=] IP $ip already blocked - skipping"
    }
} else {
    Log "[!] No IP found in alert - cannot block"
}

# --- 2. Kill the process (only if Sysmon gave us a PID - safer than image-name match) ---
if ($procId) {
    try {
        $proc = Get-Process -Id $procId -ErrorAction Stop
        Stop-Process -Id $procId -Force -ErrorAction Stop
        Log "[+] Killed process PID $procId ($($proc.ProcessName), image: $procImage)"
    } catch {
        Log "[=] Could not kill PID $procId (may have already exited): $($_.Exception.Message)"
    }
} else {
    Log "[i] No process ID in this alert (network-layer detection, e.g. Suricata) - IP block only, no process to kill"
}

Log "===== AR complete ====="
exit 0
