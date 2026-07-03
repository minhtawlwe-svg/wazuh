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
if ((Test-Path $SuricataExe) -and -not $WhatIfOnly) {
    $testOutput = & $SuricataExe -T -c $SuricataYaml 2>&1
    if ($LASTEXITCODE -eq 0) {
        Log "config test passed - restarting Suricata"
        Restart-Service Suricata -ErrorAction SilentlyContinue
    } else {
        Write-Host "[!] Config test failed after removal - check suricata.yaml manually" -ForegroundColor Red
        Write-Host ($testOutput -join "`n")
    }
}

Log "AGB rules auto-deploy uninstall complete$(if($WhatIfOnly){' (preview only, nothing changed)'})"
