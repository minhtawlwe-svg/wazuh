param(
    [switch]$Uninstall,
    [switch]$ForceReinstall,
    [string]$configUrl = "https://raw.githubusercontent.com/yekyawhan/wazuh/main/sysmon/config/custom-sysmon-tuned.xml"
)

# =========================
# Admin Check
# =========================
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Write-Host "[!] Not running as Administrator. Relaunching..." -ForegroundColor Yellow
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# =========================
# Variables
# =========================
$SysmonDir = "${env:ProgramFiles(x86)}\Sysmon"
$TempDir = "$env:TEMP\SysmonInstall"
$ZipUrl = "https://download.sysinternals.com/files/Sysmon.zip"
$ZipFile = "$TempDir\Sysmon.zip"
$LogFile = "$SysmonDir\install.log"

# =========================
# Logging
# =========================
function Log($msg) {
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $line = "[$time] $msg"
    Write-Host $line
    Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
}

# =========================
# Cleanup Temp
# =========================
function Cleanup {
    if (Test-Path $TempDir) {
        Remove-Item $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

# =========================
# Download File
# =========================
function Download($url, $out) {
    Log "Downloading $url"
    Invoke-WebRequest -Uri $url -OutFile $out -UseBasicParsing
}

# =========================
# Install Sysmon
# =========================
function Install-Sysmon {

    New-Item -ItemType Directory -Path $TempDir -Force | Out-Null
    New-Item -ItemType Directory -Path $SysmonDir -Force | Out-Null

    Download $ZipUrl $ZipFile
    Log "Extracting Sysmon..."

    Expand-Archive -Path $ZipFile -DestinationPath $TempDir -Force

    $sysmonExe = Get-ChildItem -Path $TempDir -Recurse -Filter "Sysmon64.exe" | Select-Object -First 1
    if (-not $sysmonExe) {
        Log "Sysmon64.exe not found!"
        exit 1
    }

    Copy-Item $sysmonExe.FullName $SysmonDir -Force

    # Download config
    $configPath = "$SysmonDir\sysmonconfig-export.xml"
    Download $ConfigUrl $configPath

    # Validate config
    if ((Get-Item $configPath).Length -eq 0) {
        Log "Config file is EMPTY. Abort!"
        exit 1
    }

    # Install or Update
    Set-Location $SysmonDir

    $service = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

    if ($service) {
        Log "Sysmon already installed. Updating config..."
        .\Sysmon64.exe -c $configPath
    }
    else {
        Log "Installing Sysmon..."
        .\Sysmon64.exe -i $configPath -accepteula
    }

    Start-Sleep 2

    Verify
}

# =========================
# Uninstall Sysmon
# =========================
function Uninstall-Sysmon {
    Log "Uninstalling Sysmon..."
    $exe = Get-ChildItem $SysmonDir -Filter "Sysmon64.exe" -ErrorAction SilentlyContinue | Select-Object -First 1

    if ($exe) {
        & $exe.FullName -u force
        Log "Sysmon removed."
    } else {
        Log "Sysmon64.exe not found."
    }
}

# =========================
# Verify Installation
# =========================
function Verify {

    Log "Verifying service..."
    $svc = Get-Service -Name "Sysmon64" -ErrorAction SilentlyContinue

    if ($svc -and $svc.Status -eq "Running") {
        Log "Sysmon64 service is RUNNING"
    } else {
        Log "Sysmon service NOT running"
    }

    Log "Checking event log..."
    $events = Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" -MaxEvents 1 -ErrorAction SilentlyContinue

    if ($events) {
        Log "Sysmon event log active"
    } else {
        Log "No Sysmon events found yet"
    }

    Log "DONE"
}

# =========================
# MAIN
# =========================
try {
    Log "===== Sysmon Installer Started ====="

    if ($Uninstall) {
        Uninstall-Sysmon
        Cleanup
        exit
    }

    Install-Sysmon
    Cleanup

    Log "===== Completed Successfully ====="
}
catch {
    Log "ERROR: $_"
    exit 1
}
