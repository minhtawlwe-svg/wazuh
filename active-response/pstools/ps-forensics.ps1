# ps-forensics.ps1
# Gathers real-time system and process information using PsTools.

$ErrorActionPreference = "SilentlyContinue"
$bin = "C:\Program Files\Sysinternals"
$arlog = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"

function ArLog($line) {
    $entry = "$((Get-Date).ToString('yyyy/MM/dd HH:mm:ss')) active-response/bin/get-forensics.cmd: $line"
    try {
        $fs = New-Object System.IO.FileStream($arlog, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $sw = New-Object System.IO.StreamWriter($fs, (New-Object System.Text.UTF8Encoding($false)))
        $sw.WriteLine($entry); $sw.Flush(); $sw.Close(); $fs.Close()
    } catch {}
}

# Reading Wazuh Payload
$raw = [Console]::In.ReadLine()
try { $j = $raw | ConvertFrom-Json } catch { exit 1 }
if ($j.command -ne "add") { exit 0 }

$ed = $j.parameters.alert.data.win.eventdata
$procId = $ed.processId
$agent = $env:COMPUTERNAME

ArLog "Starting Forensics for Agent: $agent (Source Alert PID: $procId)"

# Tools paths
$pslist = Join-Path $bin "pslist64.exe"
$psinfo = Join-Path $bin "psinfo64.exe"

$outDir = "C:\Program Files\Sysinternals\Forensics"
if (!(Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$outFile = Join-Path $outDir "forensic-$(Get-Date -Format 'yyyyMMdd_HHmm')-pid-$procId.txt"

# 1. System Info
ArLog "Collecting System Info..."
"--- SYSTEM INFO ---" | Out-File $outFile -Append
& $psinfo /accepteula -h -s 2>&1 | Out-File $outFile -Append

# 2. Process Tree
ArLog "Collecting Process Tree Snapshot..."
"`n--- PROCESS TREE ---" | Out-File $outFile -Append
& $pslist /accepteula -t 2>&1 | Out-File $outFile -Append

ArLog "Forensics completed. Results saved in $outFile"
exit 0
