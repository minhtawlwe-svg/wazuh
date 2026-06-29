# reenable-defender.ps1
# Wazuh custom Active Response + standalone launcher.
# Re-enable Windows Defender real-time protection.
#
# Triggered by:
#  - Wazuh rule 100620 / 100630 (Defender RTP disabled) -- via `reenable-defender.cmd`
#  - Scheduled Task Defender-Guard-Event-Watch / Defender-Guard-Service-Watch -- directly
#
# Strategy for first-action aggression:
#   - Issue ALL preference re-enables in parallel (no sleeps before).
#   - Verify RTP status with Get-MpComputerStatus; if it flipped, return fast.
#   - Only restart the service if the preference write did NOT take effect.
#   - Bounded retry (max 5 s total) so we never block the AR / watcher past a window.
#
# NOTE: Wazuh execd keeps stdin OPEN -> must ReadLine(), never ReadToEnd().
# NOTE: custom AR is NOT auto-logged -> we Add-Content our own log lines.

$ErrorActionPreference = "SilentlyContinue"
$log = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$deadline = (Get-Date).AddSeconds(5)

function Write-Log($msg) {
    $line = "{0} reenable-defender: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $msg
    try {
        $fs = [System.IO.FileStream]::new($log, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $sw = [System.IO.StreamWriter]::new($fs)
        $sw.WriteLine($line); $sw.Flush(); $sw.Close(); $fs.Close()
    } catch { }
}

# Detect mode: Wazuh AR (stdin JSON) vs standalone (Scheduled Task / manual call).
$isAR = $false
$stdin = $null
try {
    if ([Console]::In -ne $null -and [Console]::In.Peek() -ge 0) {
        $isAR  = $true
        $stdin = [Console]::In.ReadLine()
    }
} catch {}

$action = "add"
if ($isAR) {
    Write-Log "Starting (AR). stdin=$stdin"
    try { $action = ($stdin | ConvertFrom-Json).command } catch {}
} else {
    Write-Log "Starting (standalone)."
}

if ($action -ne "add") {
    Write-Log "Timeout/delete action received, no-op."
    Write-Log "Ended."
    return
}

# ----------------------------------------------------------------------
# 1. SERVICE LIVENESS -- do this first so a stopped WinDefend does not
#    block the preference API.
# ----------------------------------------------------------------------
try {
    $svc = Get-Service -Name WinDefend -ErrorAction Stop
    if ($svc.Status -ne 'Running') {
        Write-Log "WinDefend not Running ($($svc.Status)), starting."
        try { Set-Service -Name WinDefend -StartupType Automatic } catch {}
        Start-Service -Name WinDefend -ErrorAction SilentlyContinue
    }
} catch { }

# ----------------------------------------------------------------------
# 2. PREFERENCE RE-ENABLE -- all four preference flags at once, no
#    intermediate sleeps. Allow the service a brief moment to register
#    the writes (preference API is sync but WinDefend may need ~200 ms
#    to flip IsTamperProtected-gated writes).
# ----------------------------------------------------------------------
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring  $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection     $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning     $false -ErrorAction SilentlyContinue

# ----------------------------------------------------------------------
# 3. VERIFY FAST -- poll once now; if RTP is back, we're done. If not,
#    poll a few more times within the 5s budget, restarting the service
#    only when needed.
# ----------------------------------------------------------------------
function Test-Rtp {
    try {
        $s = Get-MpComputerStatus -ErrorAction Stop
        return [bool]$s.RealTimeProtectionEnabled
    } catch { return $false }
}

if (Test-Rtp) {
    Write-Log "Verification Ended. RealTimeProtectionEnabled=True (first check)"
    Write-Log "Ended."
    return
}

# Not yet on. Bounded retry loop until we hit the 5s deadline.
$attempt = 0
while ((Get-Date) -lt $deadline) {
    $attempt++
    Start-Sleep -Milliseconds 500
    if (Test-Rtp) { break }
    # On the second or later failure, restart the service once -- that's
    # the last lever that re-applies preferences on a stuck state.
    if ($attempt -eq 2) {
        Write-Log "Attempt ${attempt}: still off, restarting WinDefend."
        try { Restart-Service -Name WinDefend -Force -ErrorAction Stop } catch { }
        Start-Sleep -Milliseconds 500
        # Re-issue preferences (the restart clears state).
        Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableBehaviorMonitoring  $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableIOAVProtection     $false -ErrorAction SilentlyContinue
        Set-MpPreference -DisableScriptScanning     $false -ErrorAction SilentlyContinue
    }
}

$rtp = Test-Rtp
Write-Log "Verification Ended. RealTimeProtectionEnabled=$rtp (attempts=${attempt})"
Write-Log "Ended."
