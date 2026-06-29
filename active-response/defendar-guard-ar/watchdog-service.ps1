# watchdog-service.ps1 - Layer-2 defender: keep WinDefend alive & force-re-enable
# defense preferences the moment they flip OFF.
#
# Why this layer exists:
#   Option A (event-log) misses the very first disable because Windows Defender
#   takes 100ms-1s to write Event 5001 after a preference flip. Tamper Protection
#   ON makes Set-MpPreference a no-op, so re-enable can re-trigger reliably.
#   This script polls via SCM (user-mode, no kernel impact) and reacts in ~1s.
#
# Resource use: ~20 MB RAM, ~0.01% CPU, zero disk IO at idle. See README.
# Run as SYSTEM via Scheduled Task (AtStartup, RunAs=SYSTEM, highest privileges).
#
# Tamper Protection can still block Set-MpPreference from a SYSTEM context
# (by design). When it does, the script logs and keeps the service alive; the
# state flip will be permanently blocked at source. That is the WIN.

$ErrorActionPreference = "SilentlyContinue"
$log = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
$pollSeconds = 1   # safe on Windows; 3 is fine for laptops if you want less CPU

function Write-Log($msg) {
    $line = "{0} watchdog-service: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $msg
    $fs = [System.IO.FileStream]::new($log, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    $sw = [System.IO.StreamWriter]::new($fs)
    $sw.WriteLine($line); $sw.Flush(); $sw.Close(); $fs.Close()
}

Write-Log "Starting (poll=${pollSeconds}s, PID=$PID)."

# Enforce Automatic startup once (idempotent, no-op if already set)
try { Set-Service -Name WinDefend -StartupType Automatic } catch {}

# Restore default preferences once at startup. If Tamper Protection rejects,
# the Set-MpPreference calls fail silently - that is fine, the periodic poll
# below will retry each cycle.
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring  $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection     $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning     $false -ErrorAction SilentlyContinue

$lastServiceLog = New-TimeSpan -Seconds 60
$lastPrefLog    = New-TimeSpan -Seconds 60

while ($true) {
    $now = [DateTime]::Now

    # 1. Service liveness: if WinDefend stopped, restart it.
    $svc = Get-Service -Name WinDefend -ErrorAction SilentlyContinue
    if ($null -eq $svc) {
        # service may not exist on Server Core; skip quietly
    } elseif ($svc.Status -ne 'Running') {
        Write-Log "WinDefend status=$($svc.Status), restarting."
        try { Set-Service -Name WinDefend -StartupType Automatic } catch {}
        try { Start-Service -Name WinDefend -ErrorAction Stop } catch {}
    }

    # 2. Preference flip detection: cheap query, fully cached by SCM/Get-MpPreference.
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop
        if (-not $status.RealTimeProtectionEnabled) {
            Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
            if (($now - $lastPrefLog).TotalSeconds -ge 30) {
                Write-Log "RTP disabled -> re-issued Set-MpPreference DisableRealtimeMonitoring=`$false"
                $lastPrefLog = $now
            }
        }
    } catch {
        # Get-MpComputerStatus can fail briefly during service startup; ignore
    }

    Start-Sleep -Seconds $pollSeconds
}
