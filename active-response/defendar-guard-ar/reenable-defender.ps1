# reenable-defender.ps1
# Wazuh custom Active Response: re-enable Windows Defender real-time protection.
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

# Read the JSON command line Wazuh sends on stdin (ReadLine, not ReadToEnd)
$stdin = [Console]::In.ReadLine()
Write-Log "Starting. stdin=$stdin"

try {
    $cmd = $stdin | ConvertFrom-Json
    $action = $cmd.command          # "add" on trigger, "delete" on timeout
} catch {
    $action = "add"
}

if ($action -eq "add") {
    # Flip real-time protection back ON
    Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableBehaviorMonitoring $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableIOAVProtection   $false -ErrorAction SilentlyContinue
    Set-MpPreference -DisableScriptScanning    $false -ErrorAction SilentlyContinue

    # Make sure the service is running
    Start-Service -Name WinDefend -ErrorAction SilentlyContinue

    Start-Sleep -Seconds 2
    $rtp = (Get-MpComputerStatus).RealTimeProtectionEnabled
    Write-Log "Re-enable attempted. RealTimeProtectionEnabled=$rtp"
} else {
    Write-Log "Timeout/delete action received, no-op."
}

Write-Log "Ended."
