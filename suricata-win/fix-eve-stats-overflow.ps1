# ============================================================================
# Standalone fix: disable Suricata eve-log 'stats' output on an ALREADY
# INSTALLED agent, without needing a full reinstall.
#
# Root cause: Suricata's periodic stats record has hundreds of nested
# numeric fields; once flattened by Wazuh's generic JSON decoder this
# exceeds analysisd's hard field-count limit ("ERROR: Too many fields for
# JSON decoder"). The event is silently dropped on the MANAGER with zero
# indication on the agent side - eve.json grows fine locally, the agent
# log shows no errors, the agent stays Active, but ZERO Suricata data
# EVER reaches the manager as a decoded json event. Confirmed 2026-07-03
# after a full day of debugging what looked like a shipping/network
# problem (see project_c2_detection_engineering memory).
#
# One-liner (elevated PowerShell):
#   iwr https://cdn.jsdelivr.net/gh/minhtawlwe-svg/wazuh@git-home/suricata-win/fix-eve-stats-overflow.ps1 -UseBasicParsing | iex
# ============================================================================

$ErrorActionPreference = "Stop"
$Yaml = "C:\Program Files\Suricata\suricata.yaml"
$Exe  = "C:\Program Files\Suricata\suricata.exe"

if (-not (Test-Path $Yaml)) { throw "suricata.yaml not found at $Yaml - is Suricata installed?" }

Copy-Item $Yaml "$Yaml.bak-statsfix-$(Get-Date -Format yyyyMMddHHmmss)" -Force
$y = Get-Content -LiteralPath $Yaml -Raw
$ylines = $y -split "`r?`n"

$si = -1
for ($i = 0; $i -lt $ylines.Count; $i++) { if ($ylines[$i] -match '^(\s*)-\s*stats:\s*$') { $si = $i; break } }

if ($si -ge 0) {
    # already disabled?
    $indent = ($ylines[$si] -replace '-.*$','').Length
    $j = $si + 1
    $alreadyDisabled = $false
    while ($j -lt $ylines.Count -and $ylines[$j] -match '^\s+\S' -and (($ylines[$j] -replace '^(\s*).*$','$1').Length) -gt $indent) {
        if ($ylines[$j] -match 'enabled:\s*no') { $alreadyDisabled = $true }
        $j++
    }
    if ($alreadyDisabled) {
        Write-Host "[=] eve-log stats already disabled - nothing to do" -ForegroundColor Cyan
    } else {
        $pad = ' ' * ($indent + 4)
        $ylines = @($ylines[0..$si]) + @("$pad" + 'enabled: no') + @($(if ($j -le $ylines.Count - 1) { $ylines[$j..($ylines.Count - 1)] } else { @() }))
        $y = $ylines -join "`r`n"
        [IO.File]::WriteAllText($Yaml, $y, (New-Object Text.UTF8Encoding($false)))
        Write-Host "[+] eve-log stats output disabled" -ForegroundColor Green

        Write-Host "[*] Validating config..."
        $tout = (& $Exe -T -c $Yaml 2>&1 | Out-String)
        $tline = ($tout -split "`n" | Where-Object { $_ -match 'successfully loaded|no rules were loaded' } | Select-Object -First 1)
        if ($tline) { Write-Host "  -T: $($tline.Trim())" }

        Write-Host "[*] Restarting Suricata..."
        Restart-Service Suricata
        Start-Sleep 3
        Get-Service Suricata
    }
} else {
    Write-Host "[!] No eve-log 'stats' block found in suricata.yaml - may already be absent/disabled, or this version's default config differs. Nothing changed." -ForegroundColor Yellow
}
