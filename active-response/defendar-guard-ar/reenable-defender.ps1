# reenable-defender.ps1
# Wazuh custom Active Response: re-enable Windows Defender real-time protection.
# Also runs standalone (no stdin / Scheduled Task trigger) for instant re-enable.
# Triggered by rule 100620 (Defender real-time protection DISABLED).
# NOTE: Wazuh execd keeps stdin OPEN -> must ReadLine(), never ReadToEnd().
# NOTE: custom AR is NOT auto-logged -> we Add-Content our own log lines.

$ErrorActionPreference = "SilentlyContinue"
$log = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Write-Log($msg) {
    $line = "{0} reenable-defender: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $msg
    # FileShare so logcollector tailing the same file does not lock us out
    $fs = [System.IO.FileStream]::new($log, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
    $sw = [System.IO.StreamWriter]::new($fs)
    $sw.WriteLine($line); $sw.Flush(); $sw.Close(); $fs.Close()
}

# Detect mode: Wazuh AR (stdin JSON) vs standalone (Scheduled Task / manual call).
# Wazuh execd keeps stdin open with a JSON line; Scheduled Task has empty/null stdin.
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

# 1. Start Service
Start-Service -Name WinDefend -ErrorAction SilentlyContinue
Start-Sleep -Seconds 2

# 2. Re-enable settings
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring  $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection     $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning    $false -ErrorAction SilentlyContinue

# 3. Verification Loop
for ($i=0; $i -lt 3; $i++) {
    Start-Sleep -Seconds 3
    $rtp = (Get-MpComputerStatus).RealTimeProtectionEnabled
    if ($rtp) { break }

    Write-Log "Attempt $($i+1): Protection still disabled, restarting WinDefend..."
    Restart-Service -Name WinDefend -Force -ErrorAction SilentlyContinue
}

$rtp = (Get-MpComputerStatus).RealTimeProtectionEnabled
Write-Log "Verification Ended. RealTimeProtectionEnabled=$rtp"
Write-Log "Ended."
