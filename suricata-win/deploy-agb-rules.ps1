# ============================================================================
# AGB Suricata rules - PULL-based deploy (GitHub is source of truth)
# ============================================================================
# Downloads the current agb-white.rules / agb-black.rules directly from
# GitHub (raw, no auth needed - public repo) into C:\ProgramData\Suricata\
# rules\, validates with suricata -T, and restarts the service.
#
# Edit the rules ON GITHUB (minhtawlwe-svg/wazuh @ git-home/suricata-win),
# not locally - this script always pulls the latest published version.
#
# Runs on EVERY agent independently via a local Scheduled Task at 1:30 PM
# (see install-agb-rules-task.ps1) - no central push/credentials needed to
# scale this to any number of machines; just run the one-liner install on
# each agent.
# ============================================================================

$ErrorActionPreference = "Stop"
$BaseUrl     = "https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win"
$DestDir     = "C:\ProgramData\Suricata\rules"
$SuricataExe = "C:\Program Files\Suricata\suricata.exe"
$SuricataYaml= "C:\Program Files\Suricata\suricata.yaml"
$LogFile     = "$DestDir\agb-deploy.log"

function Log($msg) {
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $msg"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line
}

Log "===== Pull-deploy run starting ====="

try {
    # 1. Pull latest rule files straight from GitHub (no git, no auth)
    Invoke-WebRequest -Uri "$BaseUrl/agb-white.rules" -OutFile "$DestDir\agb-white.rules.new" -UseBasicParsing
    Invoke-WebRequest -Uri "$BaseUrl/agb-black.rules" -OutFile "$DestDir\agb-black.rules.new" -UseBasicParsing
    Log "[+] Downloaded latest agb-white.rules / agb-black.rules from GitHub"

    # 2. Only replace if content actually changed (avoids needless restarts)
    $changed = $false
    foreach ($name in @("agb-white.rules","agb-black.rules")) {
        $old = "$DestDir\$name"
        $new = "$DestDir\$name.new"
        if (-not (Test-Path $old) -or (Get-FileHash $old).Hash -ne (Get-FileHash $new).Hash) {
            Move-Item $new $old -Force
            $changed = $true
            Log "[+] $name changed - updated"
        } else {
            Remove-Item $new -Force
            Log "[=] $name unchanged"
        }
    }

    if (-not $changed) {
        Log "[=] No changes - skipping validate/restart"
        Log "===== Pull-deploy run SUCCEEDED (no-op) ====="
        exit 0
    }

    # 3. Ensure suricata.yaml references both files (idempotent)
    $yamlContent = Get-Content $SuricataYaml -Raw
    if ($yamlContent -notmatch 'agb-white\.rules') {
        $yamlContent = $yamlContent -replace '(\n\s*-\s*suricata\.rules\s*\n)', "`$1  - agb-white.rules`r`n  - agb-black.rules`r`n"
        Set-Content -Path $SuricataYaml -Value $yamlContent -Encoding ascii
        Log "[+] Added agb-white.rules / agb-black.rules to suricata.yaml rule-files"
    }

    # 4. Validate BEFORE restarting.
    # NOTE: `suricata -T` is strict and always fails on the ~9 ET signatures
    # using the `file.magic` keyword (no libmagic on Windows builds) - this
    # is expected/harmless, the service loads fine at runtime skipping only
    # those rules (see README Troubleshooting). Only a REAL parse error
    # (anything other than file.magic) should block the restart.
    $testOutput = & $SuricataExe -T -c $SuricataYaml 2>&1
    $errorLines = $testOutput | Where-Object { $_ -match '^E:' }
    $realErrors = $errorLines | Where-Object { $_ -notmatch "unknown rule keyword 'file\.magic'" }

    if ($LASTEXITCODE -ne 0 -and $realErrors) {
        Log "[!] Suricata config test FAILED (real errors, not just file.magic) - NOT restarting."
        Log ($realErrors -join "`n")
        exit 1
    }
    if ($errorLines) { Log "[+] Suricata config test passed (ignoring $($errorLines.Count) expected file.magic errors)" }
    else { Log "[+] Suricata config test passed" }

    # 5. Restart to load new rules
    Restart-Service Suricata -ErrorAction Stop
    Start-Sleep -Seconds 3
    $svc = Get-Service Suricata
    if ($svc.Status -ne 'Running') {
        Log "[!] Suricata service not Running after restart (status: $($svc.Status))"
        exit 1
    }
    Log "[+] Suricata restarted, status: $($svc.Status)"
    Log "===== Pull-deploy run SUCCEEDED ====="
}
catch {
    Log "[!] Pull-deploy run FAILED: $($_.Exception.Message)"
    exit 1
}
