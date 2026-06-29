# enforce-tamper-protection.ps1 - Defender-Guard Layer-0 enforcement
#
# Goal: enable Tamper Protection so non-admin/non-MDE attempts to disable
# real-time protection are REJECTED at source. This eliminates the ~1s
# detection window that the local watchers have to repair.
#
# What this script DOES:
#   1. Re-enforces DisableRealtimeMonitoring = 0 (preference)
#   2. Re-enforces DisableBehaviorMonitoring / IOAV / ScriptScanning = 0
#   3. Recommends enabling Tamper Protection (cannot be set by local script
#      by Microsoft design - this script surfaces the Intune/GPO path
#      and emits clear instructions)
#   4. Audits recent tamper attempts (Event 5010 / 5012 / 5019)
#
# What this script CANNOT DO:
#   - Tamper Protection can ONLY be turned on via:
#       * GUI (Windows Security)
#       * Intune (Antivirus policy)
#       * GPO  (Microsoft Defender ADMX)
#     This is by Microsoft design - a SYSTEM-level script cannot
#     bypass that, which is the entire point.
#
# Run elevated.

$ErrorActionPreference = "Continue"
$log = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function Write-Log($msg) {
    $line = "{0} enforce-tamper: {1}" -f (Get-Date -Format "yyyy/MM/dd HH:mm:ss"), $msg
    try {
        $fs = [System.IO.FileStream]::new($log, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $sw = [System.IO.StreamWriter]::new($fs)
        $sw.WriteLine($line); $sw.Flush(); $sw.Close(); $fs.Close()
    } catch {}
    Write-Host $line
}

# 1. Must be elevated
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
          ).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "ERROR: run in an ELEVATED PowerShell (Run as Administrator)." -ForegroundColor Red
    return
}

Write-Host "=== Defender-Guard: enforce Tamper Protection + audit ===" -ForegroundColor Cyan
Write-Log "Starting."

# 2. Re-enforce all preference flags (idempotent, no-op if Tamper is OFF but harmless)
Write-Host "Re-enforcing preferences..." -ForegroundColor Yellow
Set-MpPreference -DisableRealtimeMonitoring $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableBehaviorMonitoring  $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableIOAVProtection     $false -ErrorAction SilentlyContinue
Set-MpPreference -DisableScriptScanning     $false -ErrorAction SilentlyContinue

# 3. Read effective state
$status = Get-MpComputerStatus -ErrorAction SilentlyContinue

Write-Host ""
Write-Host "Effective state:" -ForegroundColor Cyan
Write-Host ("  RealTimeProtectionEnabled : {0}" -f $status.RealTimeProtectionEnabled)
Write-Host ("  BehaviorMonitoringEnabled : {0}" -f $status.BehaviorMonitorEnabled)
Write-Host ("  Tamper Protection         : {0}" -f $status.IsTamperProtected)
Write-Host ("  Cloud Protection          : {0}" -f $status.CloudProtectionEnabled)
Write-Host ("  AntivirusSignature       : {0}" -f $status.AntivirusSignatureLastUpdated)
Write-Host ""

if ($status.IsTamperProtected) {
    Write-Host "[OK] Tamper Protection is ON. Disable attempts will be REJECTED." -ForegroundColor Green
    Write-Log "Tamper Protection ON, RTP=True."
} else {
    Write-Host "[WARN] Tamper Protection is OFF. Disable attempts succeed, ~1s re-enable gap." -ForegroundColor Red
    Write-Log "Tamper Protection OFF. Provide Intune/GPO path to user."
    Write-Host ""
    Write-Host "Tamper Protection cannot be enabled by a local script (Microsoft design)." -ForegroundColor Magenta
    Write-Host "Choose ONE of these paths to enable it:" -ForegroundColor Magenta
    Write-Host ""
    Write-Host "  GUI (single machine):" -ForegroundColor Yellow
    Write-Host "    Windows Security -> Virus & threat protection -> Manage settings"
    Write-Host "    -> Tamper Protection -> ON"
    Write-Host ""
    Write-Host "  Intune (fleet):" -ForegroundColor Yellow
    Write-Host "    Endpoint security -> Antivirus -> Tamper Protection = Enabled"
    Write-Host "    See tamper-protection-policy.xml (OMA-URI snippets)."
    Write-Host ""
    Write-Host "  GPO (domain-joined fleet):" -ForegroundColor Yellow
    Write-Host "    Computer\Administrative Templates\Windows Components\"
    Write-Host "    Microsoft Defender Antivirus\Real-time Protection"
    Write-Host "      Tamper Protection = Enabled"
    Write-Host "      Configure real-time protection = Enabled"
}

# 4. Audit recent tamper attempts (last 50 events matching the relevant IDs)
Write-Host ""
Write-Host "Recent tamper-related events (last 50):" -ForegroundColor Cyan
try {
    $events = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' `
                           -FilterXPath "*[System[EventID=5010 or EventID=5012 or EventID=5019]]" `
                           -MaxEvents 50 -ErrorAction Stop
    if ($events) {
        $events | Select-Object TimeCreated, Id, Message | Format-Table -AutoSize -Wrap
    } else {
        Write-Host "  (no recent events - good)" -ForegroundColor Green
    }
} catch {
    Write-Host "  (could not read event log: $($_.Exception.Message))" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Done. Pair this with the two watchers (install-watcher.ps1) for layered defense." -ForegroundColor Cyan
Write-Log "Ended."
