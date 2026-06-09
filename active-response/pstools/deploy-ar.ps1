# deploy-ar.ps1
# Master deployment script for Wazuh Active Response with PsTools
$ErrorActionPreference = "Stop" # Error တက်ရင် ချက်ချင်းပြပြီး ရပ်သွားအောင် Stop ပြောင်းထားတယ်

# 0. Check Administrator Privilege
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "This script must be run as Administrator! Please reopen PowerShell as Administrator."
    Exit
}

$branch = "git-home"
$repoBase = "https://raw.githubusercontent.com/yekyawhan/wazuh/$branch/active-response/pstools"
$sysDir = "C:\Program Files\Sysinternals"
$arDir = "C:\Program Files (x86)\ossec-agent\active-response\bin"

Write-Host "--- Starting Wazuh AR Deployment ---" -ForegroundColor Cyan

# 1. Install PowerShell 7
Write-Host "[1/5] Checking for PowerShell 7..."
if (!(Get-Command pwsh -ErrorAction SilentlyContinue)) {
    Write-Host "Installing PowerShell 7..."
    $msiUrl = "https://github.com/PowerShell/PowerShell/releases/download/v7.6.2/PowerShell-7.6.2-win-x64.msi"
    $msiPath = Join-Path $env:TEMP "ps7.msi"
    Invoke-WebRequest -Uri $msiUrl -OutFile $msiPath
    Start-Process msiexec.exe -ArgumentList "/i `"$msiPath`" /quiet /qn /norestart" -Wait
} else {
    Write-Host "PowerShell 7 already installed."
}

# 2. Setup Sysinternals
Write-Host "[2/5] Setting up Sysinternals Tools..."
if (!(Test-Path $sysDir)) { 
    Write-Host "Creating Sysinternals directory: $sysDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $sysDir -Force | Out-Null 
}
$zipUrl = "https://download.sysinternals.com/files/PSTools.zip"
$zipPath = Join-Path $env:TEMP "PSTools.zip"
Invoke-WebRequest -Uri $zipUrl -OutFile $zipPath
Expand-Archive -Path $zipPath -DestinationPath $sysDir -Force
Remove-Item $zipPath -Force

# 3. Download AR Scripts from GitHub
Write-Host "[3/5] Downloading AR Scripts from GitHub..."
# Wazuh Active Response bin directory မရှိသေးရင် ဆောက်ပေးရန်
if (!(Test-Path $arDir)) {
    Write-Host "Creating Wazuh Active Response bin directory: $arDir" -ForegroundColor Yellow
    New-Item -ItemType Directory -Path $arDir -Force | Out-Null
}

$files = @(
    "pssuspend_v2.ps1",
    "ps-forensics.ps1",
    "pssuspend.cmd",
    "get-forensics.cmd",
    "notify-balloon.ps1"
)

foreach ($f in $files) {
    # Place core logic .ps1 scripts in Sysinternals, and wrapper .cmd / notification .ps1 scripts in Wazuh AR bin
    if ($f.EndsWith(".ps1") -and $f -ne "notify-balloon.ps1") { 
        $dest = Join-Path $sysDir $f 
    } else { 
        $dest = Join-Path $arDir $f 
    }

    Write-Host "Downloading $f to $dest ..."
    Invoke-WebRequest -Uri "$repoBase/$f" -OutFile $dest
}

Write-Host "[4/5] Verifying files..."
$required = @(
    "$sysDir\PsSuspend64.exe",
    "$sysDir\pssuspend_v2.ps1",
    "$sysDir\ps-forensics.ps1",
    "$arDir\pssuspend.cmd",
    "$arDir\get-forensics.cmd",
    "$arDir\notify-balloon.ps1"
)

$allPassed = $true
foreach ($path in $required) {
    if (Test-Path $path) { 
        Write-Host "CHECK OK: $path" -ForegroundColor Green 
    }
    else { 
        Write-Host "MISSING: $path" -ForegroundColor Red 
        $allPassed = $false
    }
}

if (-not $allPassed) {
    Write-Error "Deployment verification failed. Some files are missing!"
    Exit
}

# 5. Force Restart Windows
Write-Host "[5/5] Restarting Windows..." -ForegroundColor Yellow
Write-Host "System will restart in 10 seconds..." -ForegroundColor Red

Start-Sleep -Seconds 10

# Force reboot immediately
shutdown.exe /r /f /t 0
