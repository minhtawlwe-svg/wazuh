# deploy-ar.ps1
# Master deployment script for Wazuh Active Response with PsTools
$ErrorActionPreference = "SilentlyContinue"

$repoBase = "https://raw.githubusercontent.com/yekyawhan/wazuh/master/wz-agent-windows/active-response/pstools"
$sysDir = "C:\Program Files\Sysinternals"
$arDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"

Write-Host "--- Starting Wazuh AR Deployment ---" -ForegroundColor Cyan

# 1. Install PowerShell 7
Write-Host "[1/5] Checking for PowerShell 7..."
if (!(Get-Command pwsh -ErrorAction SilentlyContinue)) {
    Write-Host "Installing PowerShell 7..."
    $msiUrl = "https://github.com/PowerShell/PowerShell/releases/download/v7.4.2/PowerShell-7.4.2-win-x64.msi"
    $msiPath = Join-Path $env:TEMP "ps7.msi"
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath
    Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /quiet /qn /norestart" -Wait
} else {
    Write-Host "PowerShell 7 already installed."
}

# 2. Setup Sysinternals
Write-Host "[2/5] Setting up Sysinternals Tools..."
if (!(Test-Path $sysDir)) { New-Item -ItemType Directory -Path $sysDir -Force | Out-Null }
$zipUrl = "https://download.sysinternals.com/files/PSTools.zip"
$zipPath = Join-Path $env:TEMP "PSTools.zip"
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath
Expand-Archive -Path $zipPath -DestinationPath $sysDir -Force
Remove-Item $zipPath -Force

# 3. Download AR Scripts from GitHub
Write-Host "[3/5] Downloading AR Scripts from GitHub..."
$files = @(
    "pssuspend_v2.ps1",
    "ps-forensics.ps1",
    "pssuspend.cmd",
    "get-forensics.cmd"
)

foreach ($f in $files) {
    $target = if ($f.EndsWith(".ps1") -and $f -eq "pssuspend_v2.ps1") { Join-Path $sysDir $f } else { Join-Path $arDir $f }
    if ($f -eq "ps-forensics.ps1") { $target = Join-Path $arDir $f }
    
    # Custom mapping logic as per Ko Ye's request
    if ($f -eq "pssuspend_v2.ps1") { $dest = Join-Path $sysDir $f }
    elseif ($f -eq "ps-forensics.ps1") { $dest = Join-Path $arDir $f }
    else { $dest = Join-Path $arDir $f }

    Write-Host "Downloading $f to $dest ..."
    Invoke-WebRequest -Uri "$repoBase/$f" -OutFile $dest
}

Write-Host "[4/5] Verifying files..."
$required = @(
    "$sysDir\PsSuspend64.exe",
    "$sysDir\pssuspend_v2.ps1",
    "$arDir\pssuspend.cmd",
    "$arDir\get-forensics.cmd",
    "$arDir\ps-forensics.ps1"
)

foreach ($path in $required) {
    if (Test-Path $path) { Write-Host "CHECK OK: $path" -ForegroundColor Green }
    else { Write-Host "MISSING: $path" -ForegroundColor Red }
}

Write-Host "[5/5] Restarting Wazuh Agent..."
& "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe" stop
& "C:\Program Files (x86)\ossec-agent\wazuh-agent.exe" start

Write-Host "--- Deployment Finished ---" -ForegroundColor Cyan
