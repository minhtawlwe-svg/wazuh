<# 
Wazuh Agent Production Installer
Author: SOC Automation
#>

param(
    # SECURITY: no default - this repo is public, so the internal manager IP
    # must be passed at run time: -WazuhManager <ip-or-hostname>
    [Parameter(Mandatory = $true)]
    [string]$WazuhManager,
    [string]$WazuhVersionUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi",
    [switch]$ForceReinstall,
    [string]$LogFile = "$env:TEMP\wazuh-install.log"
)

function Write-Log {
    param([string]$msg)
    $time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$time - $msg" | Tee-Object -FilePath $LogFile -Append
}

Write-Log "===== Wazuh Agent Installation Started ====="

try {
    # -------------------------------
    # Check existing installation
    # -------------------------------
    $installed = Get-WmiObject -Class Win32_Product | Where-Object {
        $_.Name -like "*Wazuh*"
    }

    if ($installed -and -not $ForceReinstall) {
        Write-Log "Wazuh Agent already installed. Exiting..."
        exit 0
    }

    if ($installed -and $ForceReinstall) {
        Write-Log "ForceReinstall enabled. Removing existing agent..."
        $installed.Uninstall() | Out-Null
        Start-Sleep -Seconds 5
    }

    # -------------------------------
    # Download MSI
    # -------------------------------
    $msiPath = "$env:TEMP\wazuh-agent.msi"

    Write-Log "Downloading Wazuh Agent..."
    Invoke-WebRequest -Uri $WazuhVersionUrl -OutFile $msiPath -UseBasicParsing

    if (!(Test-Path $msiPath)) {
        throw "MSI download failed"
    }

    Write-Log "Download completed: $msiPath"

    # -------------------------------
    # Install silently
    # -------------------------------
    Write-Log "Installing Wazuh Agent..."

    $args = "/i `"$msiPath`" /qn WAZUH_MANAGER=`"$WazuhManager`""

    $process = Start-Process msiexec.exe -ArgumentList $args -Wait -PassThru

    if ($process.ExitCode -ne 0) {
        throw "MSI installation failed with exit code $($process.ExitCode)"
    }

    Write-Log "Installation completed successfully"

    # -------------------------------
    # Start service
    # -------------------------------
    Write-Log "Starting Wazuh service..."
    Start-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue

    # -------------------------------
    # Verify service
    # -------------------------------
    $svc = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue

    if ($svc.Status -eq "Running") {
        Write-Log "Wazuh service is running"
    } else {
        Write-Log "WARNING: Wazuh service is NOT running"
    }

    Write-Log "===== Installation Finished Successfully ====="
    exit 0
}
catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    exit 1
}
