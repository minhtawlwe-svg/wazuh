# ============================================================================
# AGB rules auto-deploy - uninstall (removes ONLY the agb-white/agb-black
# rules + scheduled task; leaves base Suricata install untouched)
# ============================================================================
param([switch]$WhatIfOnly)

$ErrorActionPreference = 'Continue'
$TaskName    = "AGB-Suricata-Rules-Deploy"
$ScriptsDir  = "C:\ProgramData\Suricata\agb-scripts"
$RulesDir    = "C:\ProgramData\Suricata\rules"
$SuricataExe = "C:\Program Files\Suricata\suricata.exe"
$SuricataYaml= "C:\Program Files\Suricata\suricata.yaml"

function Log($m){ Write-Host "[agb-uninstall] $m" -ForegroundColor Cyan }
function Act($m){ if($WhatIfOnly){ Write-Host "  WOULD: $m" -ForegroundColor Yellow } else { Write-Host "  $m" } }

# 1. Scheduled task ----------------------------------------------------
$task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
if ($task) {
    Act "remove scheduled task '$TaskName'"
    if (-not $WhatIfOnly) { Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false }
} else { Log "no scheduled task '$TaskName' found" }

# 2. Local deploy script + logs ----------------------------------------
if (Test-Path $ScriptsDir) {
    Act "remove $ScriptsDir"
    if (-not $WhatIfOnly) { Remove-Item $ScriptsDir -Recurse -Force -ErrorAction SilentlyContinue }
} else { Log "$ScriptsDir does not exist" }

# 3. Rule files ----------------------------------------------------------
foreach ($f in @("agb-white.rules","agb-black.rules")) {
    $p = "$RulesDir\$f"
    if (Test-Path $p) {
        Act "remove $p"
        if (-not $WhatIfOnly) { Remove-Item $p -Force -ErrorAction SilentlyContinue }
    } else { Log "$p does not exist" }
}
$deployLog = "$RulesDir\agb-deploy.log"
if (Test-Path $deployLog) {
    Act "remove $deployLog"
    if (-not $WhatIfOnly) { Remove-Item $deployLog -Force -ErrorAction SilentlyContinue }
}

# 4. suricata.yaml - drop the two rule-files lines ------------------------
if (Test-Path $SuricataYaml) {
    $content = Get-Content $SuricataYaml -Raw
    if ($content -match 'agb-white\.rules|agb-black\.rules') {
        Act "remove agb-white.rules/agb-black.rules entries from suricata.yaml rule-files"
        if (-not $WhatIfOnly) {
            $content = $content -replace '\s*-\s*agb-white\.rules\s*\r?\n', "`r`n"
            $content = $content -replace '\s*-\s*agb-black\.rules\s*\r?\n', "`r`n"
            Set-Content -Path $SuricataYaml -Value $content -Encoding ascii
        }
    } else { Log "suricata.yaml does not reference agb rules - nothing to remove" }
} else { Log "suricata.yaml not found (Suricata may already be uninstalled)" }

# 5. Validate + restart Suricata (if still installed) ---------------------
# NOTE: `suricata -T` is strict and always fails on the ~9 ET signatures
# using the `file.magic` keyword (no libmagic on Windows builds) - this is
# expected and harmless; the service loads fine at runtime, skipping only
# those rules (see suricata-win/README.md Troubleshooting). Only treat this
# as a real failure if there are OTHER, non-file.magic errors too.
if ((Test-Path $SuricataExe) -and -not $WhatIfOnly) {
    $testOutput = & $SuricataExe -T -c $SuricataYaml 2>&1
    $errorLines = $testOutput | Where-Object { $_ -match '^E:' }
    $realErrors = $errorLines | Where-Object { $_ -notmatch "unknown rule keyword 'file\.magic'" }

    if ($LASTEXITCODE -eq 0 -or -not $realErrors) {
        if ($errorLines) { Log "config test passed (ignoring $($errorLines.Count) expected file.magic errors)" }
        else { Log "config test passed" }
        Restart-Service Suricata -ErrorAction SilentlyContinue
    } else {
        Write-Host "[!] Config test failed after removal - check suricata.yaml manually" -ForegroundColor Red
        Write-Host ($realErrors -join "`n")
    }
}

Log "AGB rules auto-deploy uninstall complete$(if($WhatIfOnly){' (preview only, nothing changed)'})"
