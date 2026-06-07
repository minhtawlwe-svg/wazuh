# pssuspend_v2.ps1
$ErrorActionPreference = "SilentlyContinue"

# Define binary directory and log files relative to script execution context
$bin = "C:\Program Files\Sysinternals"
$log = Join-Path $bin "pssuspend-actions.log"
$jsonlog = Join-Path $bin "software-policy-events.log"

function Log($m) {
    "$((Get-Date).ToString('o')) $m" | Add-Content $log
}

# active-responses.log (agent root) -- USER-FRIENDLY plain-English lines, no raw JSON.
# FileShare.ReadWrite so the logcollector localfile lock can't swallow the write.
$arlog = "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log"
function ArLog($line) {
    try {
        $entry = "$((Get-Date).ToString('yyyy/MM/dd HH:mm:ss')) active-response/bin/pssuspend.cmd: $line"
        $fs = New-Object System.IO.FileStream($arlog, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $sw = New-Object System.IO.StreamWriter($fs, (New-Object System.Text.UTF8Encoding($false)))
        $sw.WriteLine($entry); $sw.Flush(); $sw.Close(); $fs.Close()
    } catch {}
}

# Forensic JSON per decision -> shipped to the Wazuh manager (keeps the 100420 success alert).
function Forensic($action, $method) {
    try {
        $sha256 = ""
        if ($ed.hashes) {
            $mm = [regex]::Match($ed.hashes, 'SHA256=([0-9A-Fa-f]+)');
            if ($mm.Success) { $sha256 = $mm.Groups[1].Value }
        }
        $evt = [ordered]@{
            sp_event    = "software_policy";
            sp_action   = $action;
            sp_method   = "$method";
            sp_base     = "$base"
            sp_image    = "$image";
            sp_pid      = "$procId";
            sp_user     = "$user";
            sp_integrity = "$($ed.integrityLevel)"
            sp_sha256   = $sha256;
            sp_cmdline  = "$($ed.commandLine)";
            sp_parent   = "$($ed.parentImage)"
            sp_company  = "$company";
            sp_agent    = "$env:COMPUTERNAME";
            sp_time     = (Get-Date).ToString('o')
        }
        $line = ($evt | ConvertTo-Json -Compress)
        $fs = New-Object System.IO.FileStream($jsonlog, [System.IO.FileMode]::Append, [System.IO.FileAccess]::Write, [System.IO.FileShare]::ReadWrite)
        $sw = New-Object System.IO.StreamWriter($fs, (New-Object System.Text.UTF8Encoding($false)))
        $sw.WriteLine($line); $sw.Flush(); $sw.Close(); $fs.Close()
    } catch { Log "forensic ERROR $_" }
}

# Drop the flag the user-session watcher turns into a popup (Windows-Home friendly; no msg.exe).
function Notify($base) {
    try {
        $dir = Join-Path $env:ProgramData 'SoftwarePolicy'
        New-Item -ItemType Directory -Force -Path $dir | Out-Null
        "This application is not allowed.`r`n`r`n'$base' is not on the approved software list and has been stopped.`r`n`r`nContact IT if you need it approved." | Set-Content (Join-Path $dir 'notify.txt') -Encoding ascii
    } catch { Log "notify ERROR $_" }
}

# Repo-style balloon in the user session via PsExec -i.
function Balloon() {
    try {
        # Dynamically find the active user session ID (Console or RDP)
        $session = "1"
        $sessionInfo = query user 2>&1
        if ($sessionInfo -match '>(?<user>\S+)\s+(?<name>\S+)?\s+(?<id>\d+)\s+(?<state>\S+)') {
            $session = $Matches['id']
        }

        $psexec = Join-Path $bin "psexec64.exe"
        if (-not (Test-Path $psexec)) { $psexec = Join-Path $bin "psexec.exe" }
        
        $script = Join-Path "C:\Program Files (x86)\ossec-agent\active-response\bin" "notify-balloon.ps1"
        if ((Test-Path $psexec) -and (Test-Path $script)) {
            $argLine = "/accepteula /nobanner -i $session -d powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$script`""
            Start-Process -FilePath $psexec -ArgumentList $argLine -WindowStyle Hidden
            ArLog "Balloon popup triggered for user session $session"
        } else {
            ArLog "Balloon skipped: PsExec or notify-balloon.ps1 not found."
        }
    } catch { ArLog "Balloon failed: $_" }
}

# Run a PsTool with a hard timeout so a hang can never jam execd.
function RunTimed($exe, $argline, $timeoutMs) {
    try {
        $p = Start-Process -FilePath $exe -ArgumentList $argline -WindowStyle Hidden -PassThru
        if ($p.WaitForExit($timeoutMs)) { return $true }
        try { $p.Kill() } catch {}
        return $false
    } catch { return $false }
}

# execd keeps stdin open -> ReadLine ONE line, not ReadToEnd (which hangs).
$raw = [Console]::In.ReadLine()
try { $j = $raw | ConvertFrom-Json } catch { ArLog "Starting"; ArLog "ERROR: could not read the alert"; ArLog "Ended"; exit 1 }

if ($j.command -ne "add") { exit 0 }

$ed = $j.parameters.alert.data.win.eventdata
$procId = $ed.processId
$image = $ed.image
$user = $ed.user

$company = $ed.company;
if ([string]::IsNullOrWhiteSpace($company)) { $company = "(unsigned / no publisher)" }
$base = "";
if ($image) { $base = [System.IO.Path]::GetFileName($image).ToLower() }

ArLog "Starting"
ArLog ("BLOCKED app='{0}' publisher='{1}' user='{2}' pid={3}" -f $base, $company, $user, $procId)

# Anti-loop: never act on our own policy tools or core processes (belt-and-suspenders).
$ignore = @("pskill64.exe","pssuspend64.exe","psexec64.exe","powershell.exe","wazuh-agent.exe","taskkill.exe","conhost.exe")
if ($ignore -contains $base) {
    ArLog ("SKIPPED '{0}' is a policy/system tool - left running" -f $base); ArLog "Ended"; exit 0
}

if (-not $procId) { ArLog "SKIPPED no process id in the alert"; ArLog "Ended"; exit 0 }

$pidInt = [int]$procId

# Freeze with PsSuspend, then kill the tree with PsKill (each timeout-guarded); taskkill fallback.
$pssuspend = Join-Path $bin "pssuspend64.exe"
if (-not (Test-Path $pssuspend)) { $pssuspend = Join-Path $bin "pssuspend.exe" }

$pskill = Join-Path $bin "pskill64.exe"
if (-not (Test-Path $pskill)) { $pskill = Join-Path $bin "pskill.exe" }

$method = "none"

# 1. Try Suspend first
$null = RunTimed $pssuspend "/accepteula /nobanner $pidInt" 5000

# 2. Try Kill with Retry Logic
$attempts = 0
while ($attempts -lt 3) {
    ArLog "Kill attempt $($attempts + 1) for PID $pidInt"
    $null = RunTimed $pskill "/accepteula /nobanner -t $pidInt" 5000
    Start-Sleep -Milliseconds 500
    if (-not (Get-Process -Id $pidInt -ErrorAction SilentlyContinue)) { 
        $method = "pskill"
        break 
    }
    $attempts++
}

if ($method -eq "none") {
    ArLog "pskill failed, trying taskkill /F /T"
    & "$env:SystemRoot\System32\taskkill.exe" /F /T /PID $pidInt 2>&1 | Out-Null
    Start-Sleep -Milliseconds 500
    if (-not (Get-Process -Id $pidInt -ErrorAction SilentlyContinue)) { $method = "taskkill" }
}

$status = if ($method -eq "none") { "STILL RUNNING - kill FAILED, needs attention" } else { "terminated" }
$action = if ($method -eq "none") { "kill_failed" } else { "killed" }

ArLog ("RESULT app='{0}' pid={1} -> {2} (how: {3})" -f $base, $pidInt, $status, $method)
Log "result pid=$pidInt base=$base method=$method company=$company"
Forensic $action $method
Notify $base
Balloon

ArLog "Ended"
exit 0
