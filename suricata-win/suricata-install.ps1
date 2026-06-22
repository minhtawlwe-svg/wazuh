#Requires -RunAsAdministrator
# =====================================================================
#  Install-Suricata-Full-Auto.ps1   (patched 2026-06-19)
#  Fixes applied vs. original:
#   1. Interface GUID: $adapter.InterfaceGuid is already a braced string -
#      ".Guid" threw under StrictMode and produced \Device\NPF_{} otherwise.
#   2. Rules: replaced suricata-update (BROKEN on Windows, Errno 13) with a
#      direct, version-matched ET Open tarball download (main + maintenance).
#   3. Service: Suricata's --service-install writes an UNQUOTED binPath, so
#      SCM tries to start "C:\Program" and the service dies. Now the quoted
#      ImagePath is forced via registry (or New-Service fallback).
#   4. YAML: Windows paths must be SINGLE-quoted (\D etc. are invalid escapes
#      inside double quotes) - was writing double quotes.
#   5. Encoding: write suricata.yaml / ossec.conf BOM-less (PS5.1 UTF8 adds a
#      BOM, which breaks Suricata rule 1 and YAML line 1).
#   6. Wazuh: strip any pre-existing Suricata eve.json <localfile> first so we
#      never double-monitor / leave a stale path.
#   7. StrictMode-safe property access; MSI bumped to 7.0.16 (known-good here).
#   8. Added: Defender exclusion for the rules dir + non-fatal "suricata -T".
#   Optional: -CaptureInterfaceName 'VMware Network Adapter VMnet8' to sniff
#   the lab network instead of auto-selecting a physical adapter.
# =====================================================================
[CmdletBinding()]
param(
    [string]$SuricataMsiUrl = "https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.5-1-64bit.msi",
    [string]$SuricataMsiPath = "",
    [string]$NpcapUrl = "https://npcap.com/dist/npcap-1.82.exe",
    [string]$InstallRoot = "C:\Program Files\Suricata",
    [string]$DataRoot = "C:\ProgramData\Suricata",
    [string]$WazuhConf = "",
    [string]$WazuhManager = "",   # empty = do NOT install/enroll an agent. Set e.g. 192.168.144.128 to install+enroll.
    [string]$WazuhAgentMsiUrl = "https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi",
    [string]$WazuhAgentName = $env:COMPUTERNAME,
    [string]$CaptureInterfaceName = "",
    [int64]$MaxEveBytes = 2GB,
    [int]$KeepRotatedLogs = 3,
    [string]$DailyTaskTime = "13:00",
    [switch]$SkipNpcap,
    [switch]$SkipSuricata,
    [switch]$SkipWazuhAgentInstall,
    [switch]$SkipWazuhConfig,
    [switch]$SkipScheduledTask
)

Set-StrictMode -Version 1.0   # 1.0 catches uninitialized vars but does NOT throw on missing properties (registry/CIM objects)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 } catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

$LogRoot = Join-Path $DataRoot "log"
$RuleRoot = Join-Path $DataRoot "rules"
$StateRoot = Join-Path $DataRoot "state"
$DownloadRoot = Join-Path $DataRoot "downloads"
$MaintenanceScript = Join-Path $DataRoot "Suricata-Maintenance.ps1"
$InstallLog = Join-Path $DataRoot "install.log"
$TaskName = "Suricata Daily Update And Log Rotation"
$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

function Write-Log {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    Write-Host $line
    [System.IO.File]::AppendAllText($InstallLog, "$line`r`n", $Utf8NoBom)
}

function New-Directory {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -ItemType Directory -Path $Path -Force | Out-Null
    }
}

function Write-TextFileNoBom {
    param([string]$Path, [string]$Text)
    [System.IO.File]::WriteAllText($Path, $Text, $Utf8NoBom)
}

function Invoke-Download {
    param([string]$Uri, [string]$OutFile)

    # Reuse a pre-staged file (lets you copy the installer manually if this host
    # can't reach the internet / the site's TLS is unhappy).
    if ((Test-Path -LiteralPath $OutFile) -and ((Get-Item $OutFile).Length -gt 1MB)) {
        Write-Log "Using existing file (skip download): $OutFile"
        return
    }

    Write-Log "Download: $Uri"
    $ok = $false
    try {
        Invoke-WebRequest -Uri $Uri -OutFile $OutFile -UseBasicParsing -MaximumRedirection 5
        $ok = (Test-Path -LiteralPath $OutFile) -and ((Get-Item $OutFile).Length -gt 0)
    } catch {
        Write-Log "Invoke-WebRequest failed ($($_.Exception.Message)); trying curl.exe..."
    }

    if (-not $ok) {
        # curl.exe uses the OS (Schannel) TLS stack - often works when .NET's does not.
        $curl = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
        if ($curl) {
            & $curl -L --fail --ssl-no-revoke --retry 2 -o $OutFile $Uri
            $ok = (Test-Path -LiteralPath $OutFile) -and ((Get-Item $OutFile).Length -gt 0)
        }
    }

    if (-not $ok) {
        throw "Download failed for $Uri`n         This host may be unable to reach the site. Download it on another machine and copy it to:`n         $OutFile`n         then re-run (the script will reuse it)."
    }
}

function Invoke-Process {
    param([string]$FilePath, [string[]]$ArgumentList, [switch]$IgnoreExitCode)
    Write-Log ("Run: {0} {1}" -f $FilePath, ($ArgumentList -join " "))
    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -Wait -PassThru -NoNewWindow
    if (-not $IgnoreExitCode -and $process.ExitCode -ne 0) {
        throw "$FilePath exited with code $($process.ExitCode)"
    }
    return $process.ExitCode
}

function Get-CaptureInterfaces {
    # Explicit override (e.g. VMnet8 for the host<->VM lab network)
    if ($CaptureInterfaceName) {
        $adapter = Get-NetAdapter -Name $CaptureInterfaceName -ErrorAction Stop
        return ,([pscustomobject]@{
            Name = $adapter.Name
            Description = $adapter.InterfaceDescription
            # InterfaceGuid is ALREADY a braced string: {GUID}
            Device = "\Device\NPF_$($adapter.InterfaceGuid)"
        })
    }

    $exclude = "(?i)(virtual|vmware|virtualbox|hyper-v|veth|vethernet|loopback|npcap loopback|wi-fi direct|bluetooth|tap|tun|wireguard|zerotier|tailscale|hamachi|isatap|teredo)"

    $adapters = Get-NetAdapter -Physical -ErrorAction Stop |
        Where-Object {
            $_.Status -eq "Up" -and $_.InterfaceGuid -and
            $_.Name -notmatch $exclude -and $_.InterfaceDescription -notmatch $exclude
        } | Sort-Object -Property @{Expression = "LinkSpeed"; Descending = $true}, Name

    if (-not $adapters) {
        $adapters = Get-NetAdapter -Physical -ErrorAction Stop |
            Where-Object {
                $_.InterfaceGuid -and
                $_.Name -notmatch $exclude -and $_.InterfaceDescription -notmatch $exclude
            } | Sort-Object -Property @{Expression = "LinkSpeed"; Descending = $true}, Name
    }

    if (-not $adapters) {
        throw "No capture adapter found. Pass -CaptureInterfaceName '<adapter name>'."
    }

    foreach ($adapter in $adapters) {
        [pscustomobject]@{
            Name = $adapter.Name
            Description = $adapter.InterfaceDescription
            Device = "\Device\NPF_$($adapter.InterfaceGuid)"   # InterfaceGuid already braced
        }
    }
}

function Get-SuricataExePath {
    $candidates = @(
        (Join-Path $InstallRoot "suricata.exe"),
        "C:\Program Files\Suricata\suricata.exe",
        "C:\Program Files (x86)\Suricata\suricata.exe"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $found = Get-ChildItem -Path "C:\Program Files", "C:\Program Files (x86)" -Filter "suricata.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.FullName }
    throw "suricata.exe not found."
}

function Get-SuricataYamlPath {
    $candidates = @(
        (Join-Path $InstallRoot "suricata.yaml"),
        (Join-Path $DataRoot "suricata.yaml"),
        "C:\Program Files\Suricata\suricata.yaml",
        "C:\Program Files (x86)\Suricata\suricata.yaml"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    $found = Get-ChildItem -Path "C:\Program Files", "C:\Program Files (x86)", $DataRoot -Filter "suricata.yaml" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($found) { return $found.FullName }
    throw "suricata.yaml not found."
}

function Get-WazuhConfPath {
    if ($WazuhConf -and (Test-Path -LiteralPath $WazuhConf)) { return $WazuhConf }
    $candidates = @(
        "C:\Program Files (x86)\ossec-agent\ossec.conf",
        "C:\Program Files\ossec-agent\ossec.conf"
    )
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate) { return $candidate }
    }
    return $null
}

function Install-Npcap {
    if ($SkipNpcap) { Write-Log "Skip Npcap install."; return }

    $npcapInstalled = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue |
        Where-Object { $_.DisplayName -and $_.DisplayName -match "Npcap" } | Select-Object -First 1
    if ($npcapInstalled) {
        Write-Log "Npcap already installed: $($npcapInstalled.DisplayName) $($npcapInstalled.DisplayVersion)"
        return
    }

    $installer = Join-Path $DownloadRoot "npcap.exe"
    Invoke-Download -Uri $NpcapUrl -OutFile $installer
    # The FREE Npcap build cannot install silently ("/S" is OEM-only and pops a
    # warning). Launch the wizard interactively and wait for the user to finish.
    Write-Log "Launching Npcap installer INTERACTIVELY (free build has no silent mode)."
    Write-Host ""
    Write-Host "  >>> In the Npcap wizard: TICK 'Install Npcap in WinPcap API-compatible Mode', then Install/Finish." -ForegroundColor Yellow
    Write-Host ""
    Start-Process -FilePath $installer -Wait
    Start-Sleep -Seconds 2
    if ((Get-Service npcap -ErrorAction SilentlyContinue) -or (Test-Path "C:\Windows\System32\Npcap")) {
        Write-Log "Npcap installed."
    } else {
        throw "Npcap not detected after the wizard. Re-run and complete the Npcap installer (don't cancel it)."
    }
}

function Install-SuricataUpdate {
    $existing = Get-Command "suricata-update" -ErrorAction SilentlyContinue
    if ($existing) {
        Write-Log "suricata-update already present: $($existing.Source)"
        return
    }

    $python = Get-Command "python.exe" -ErrorAction SilentlyContinue
    if (-not $python) {
        $winget = Get-Command "winget.exe" -ErrorAction SilentlyContinue
        if (-not $winget) {
            Write-Log "Python and winget not found. Skip suricata-update install (direct ET Open tarball path will be used)."
            return
        }
        Write-Log "Installing Python via winget (required for suricata-update)..."
        $rc = Invoke-Process -FilePath $winget.Source -ArgumentList @("install", "--id", "Python.Python.3.12", "--source", "winget", "--silent", "--accept-package-agreements", "--accept-source-agreements") -IgnoreExitCode
        Write-Log "winget python install exit: $rc"
        $python = Get-Command "python.exe" -ErrorAction SilentlyContinue
    }

    if (-not $python) {
        Write-Log "Python not available. Skip suricata-update."
        return
    }

    Write-Log "Upgrading pip and installing suricata-update via pip..."
    Invoke-Process -FilePath $python.Source -ArgumentList @("-m", "pip", "install", "--upgrade", "pip") -IgnoreExitCode | Out-Null
    $rc = Invoke-Process -FilePath $python.Source -ArgumentList @("-m", "pip", "install", "--upgrade", "suricata-update") -IgnoreExitCode
    if ($rc -eq 0) {
        Write-Log "suricata-update installed."
    } else {
        Write-Log "suricata-update install returned exit $rc - may be broken on Windows (see comment in Invoke-RuleUpdate)."
    }
}

function Install-Suricata {
    if ($SkipSuricata) { Write-Log "Skip Suricata install."; return }

    $existingPath = $null
    $cmd = Get-Command "suricata.exe" -ErrorAction SilentlyContinue
    if ($cmd -and $cmd.Source) { $existingPath = $cmd.Source }
    if (-not $existingPath) {
        $found = Get-ChildItem -Path "C:\Program Files", "C:\Program Files (x86)" -Filter "suricata.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($found) { $existingPath = $found.FullName }
    }
    if ($existingPath) { Write-Log "Suricata already present: $existingPath"; return }

    $localCandidates = @()
    if ($SuricataMsiPath -and (Test-Path -LiteralPath $SuricataMsiPath)) {
        $localCandidates += $SuricataMsiPath
    }
    if ($PSScriptRoot) {
        $localCandidates += (Join-Path $PSScriptRoot "Suricata-7.0.16-1-64bit.msi")
    }
    $installer = $null
    foreach ($candidate in $localCandidates) {
        if (Test-Path -LiteralPath $candidate) {
            $installer = $candidate
            Write-Log "Use local Suricata MSI: $installer"
            break
        }
    }
    if (-not $installer) {
        $installer = Join-Path $DownloadRoot "suricata.msi"
        $msiLog = Join-Path $DataRoot "suricata-msi.log"
        Invoke-Download -Uri $SuricataMsiUrl -OutFile $installer
    }
    $msiLog = Join-Path $DataRoot "suricata-msi.log"
    Write-Log "Installing Suricata MSI silently (/qn)..."
    # 0 = success, 3010 = success but reboot requested (common with /norestart)
    $rc = Invoke-Process -FilePath "msiexec.exe" -ArgumentList @("/i", $installer, "/qn", "/norestart", "/L*v", $msiLog) -IgnoreExitCode
    if ($rc -ne 0 -and $rc -ne 3010) { throw "Suricata MSI failed (msiexec exit $rc). See $msiLog" }
    Start-Sleep -Seconds 2
    $exe = (Join-Path $InstallRoot "suricata.exe")
    if (-not (Test-Path -LiteralPath $exe)) {
        $exe = (Get-ChildItem "C:\Program Files", "C:\Program Files (x86)" -Filter "suricata.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
    }
    if (-not $exe) { throw "Suricata MSI ran (exit $rc) but suricata.exe was not found." }
    Write-Log "Suricata installed (msiexec exit $rc): $exe"
}

function Install-WazuhAgent {
    if ($SkipWazuhAgentInstall) { Write-Log "Skip Wazuh agent install."; return }

    if (Get-Service WazuhSvc -ErrorAction SilentlyContinue) {
        Write-Log "Wazuh agent already installed (WazuhSvc present)."
        return
    }
    if (-not $WazuhManager) { Write-Log "No -WazuhManager set; skipping Wazuh agent install."; return }

    $installer = Join-Path $DownloadRoot "wazuh-agent.msi"
    Invoke-Download -Uri $WazuhAgentMsiUrl -OutFile $installer
    Write-Log "Installing Wazuh agent (manager=$WazuhManager, name=$WazuhAgentName)..."
    $rc = Invoke-Process -FilePath "msiexec.exe" -ArgumentList @(
        "/i", $installer, "/qn", "/norestart",
        "WAZUH_MANAGER=$WazuhManager",
        "WAZUH_REGISTRATION_SERVER=$WazuhManager",
        "WAZUH_AGENT_NAME=$WazuhAgentName"
    ) -IgnoreExitCode
    if ($rc -ne 0 -and $rc -ne 3010) { throw "Wazuh agent MSI failed (msiexec exit $rc)." }
    Start-Sleep -Seconds 3

    $confPath = Get-WazuhConfPath
    if (-not $confPath) { throw "Wazuh agent installed but ossec.conf not found." }
    $agentDir = Split-Path $confPath

    # MSI property quotes can be mangled (agent then defaults to 127.0.0.1) -
    # force the manager address directly in ossec.conf to be safe.
    $c = [System.IO.File]::ReadAllText($confPath)
    if ($c -match "<address>.*?</address>") {
        $c = [regex]::Replace($c, "<address>.*?</address>", "<address>$WazuhManager</address>", 1)
        [System.IO.File]::WriteAllText($confPath, $c, $Utf8NoBom)
        Write-Log "Forced agent manager address -> $WazuhManager"
    }

    # Register with the manager (authd on 1515) if not already keyed.
    $keys = Join-Path $agentDir "client.keys"
    $keyed = (Test-Path $keys) -and ((Get-Item $keys).Length -gt 0)
    $auth = Join-Path $agentDir "agent-auth.exe"
    if (-not $keyed -and (Test-Path $auth)) {
        Write-Log "Registering with manager via agent-auth (-m $WazuhManager)..."
        Invoke-Process -FilePath $auth -ArgumentList @("-m", $WazuhManager, "-A", $WazuhAgentName) -IgnoreExitCode | Out-Null
    }

    Set-Service -Name WazuhSvc -StartupType Automatic -ErrorAction SilentlyContinue
    Restart-Service WazuhSvc -Force -ErrorAction SilentlyContinue
    Start-Sleep -Seconds 2
    $st = (Get-Service WazuhSvc -ErrorAction SilentlyContinue).Status
    Write-Log "WazuhSvc status: $st"
    if ((Test-Path $keys) -and ((Get-Item $keys).Length -gt 0)) { Write-Log "Agent registered (client.keys populated)." }
    else { Write-Log "WARNING: client.keys empty - manager may require an enrollment password; register manually." }
}

function Backup-File {
    param([string]$Path)
    if (Test-Path -LiteralPath $Path) {
        $backup = "{0}.{1}.bak" -f $Path, (Get-Date -Format "yyyyMMddHHmmss")
        Copy-Item -LiteralPath $Path -Destination $backup -Force
        Write-Log "Backup: $backup"
    }
}

function Set-KeyValueLine {
    param([string]$Text, [string]$Key, [string]$Value)
    $pattern = "(?m)^\s*$([regex]::Escape($Key))\s*:.*$"
    $replacement = "${Key}: $Value"
    if ($Text -match $pattern) {
        return [regex]::Replace($Text, $pattern, $replacement, 1)
    }
    return "$replacement`r`n$Text"
}

function Test-YamlIntact {
    # A complete suricata.yaml has these core sections. If they're missing the
    # file was truncated/corrupted and must NOT be tuned as-is.
    param([string]$Text)
    return (($Text -match "(?m)^\s*rule-files:") -and ($Text -match "(?m)^\s*app-layer:"))
}

function Set-SuricataYaml {
    param([string]$YamlPath, [object[]]$Interfaces)

    $content = Get-Content -LiteralPath $YamlPath -Raw

    # Self-heal: if the yaml is truncated/incomplete, restore the newest INTACT
    # backup instead of tuning a broken file.
    if (-not (Test-YamlIntact $content)) {
        Write-Log "WARNING: suricata.yaml looks truncated - searching for an intact backup..."
        $good = Get-ChildItem (Split-Path $YamlPath) -Filter "suricata.yaml*.bak" -ErrorAction SilentlyContinue |
                Sort-Object LastWriteTime -Descending |
                Where-Object { Test-YamlIntact (Get-Content -LiteralPath $_.FullName -Raw) } |
                Select-Object -First 1
        if ($good) {
            Copy-Item -LiteralPath $good.FullName -Destination $YamlPath -Force
            $content = Get-Content -LiteralPath $YamlPath -Raw
            Write-Log "Restored intact suricata.yaml from backup: $($good.Name)"
        } else {
            throw "suricata.yaml is incomplete and no intact backup found. Reinstall the Suricata MSI (it ships the default config), then re-run."
        }
    }

    Backup-File -Path $YamlPath

    # Only change the two path keys (single-line, safe). SINGLE quotes because
    # backslashes are invalid escapes inside double-quoted YAML (\D, \S, ...).
    $content = Set-KeyValueLine -Text $content -Key "default-log-dir"   -Value ("'{0}'" -f $LogRoot)
    $content = Set-KeyValueLine -Text $content -Key "default-rule-path" -Value ("'{0}'" -f $RuleRoot)

    # IMPORTANT: do NOT regex-rewrite the eve-log or pcap blocks.
    #  - Stock suricata.yaml already has eve-log enabled -> eve.json with the full
    #    'types' list. A greedy (?s) regex here previously truncated the whole file
    #    (no types -> empty eve.json; no rule-files -> -T fails).
    #  - The capture interface is supplied on the service command line (-i <device>),
    #    so no 'pcap:' block edit is required.

    Write-TextFileNoBom -Path $YamlPath -Text $content
    Write-Log "Updated Suricata YAML (log-dir + rule-path only): $YamlPath"
}

function Invoke-RuleUpdate {
    # Direct ET Open download. suricata-update is broken on Windows (it locks its
    # NamedTemporaryFile -> "Failed to copy file: [Errno 13]"), so we never use it.
    New-Directory -Path $RuleRoot
    New-Directory -Path $StateRoot
    New-Directory -Path $DownloadRoot

    try {
        Add-MpPreference -ExclusionPath $RuleRoot, $DownloadRoot -ErrorAction Stop
        Write-Log "Defender exclusion added for rules/download dirs."
    } catch {
        Write-Log "Could not add Defender exclusion: $($_.Exception.Message)"
    }

    $exe = Get-SuricataExePath
    $version = "7.0.16"
    try {
        $vout = (& $exe -V 2>&1 | Out-String)
        if ($vout -match "version\s+([0-9]+\.[0-9]+\.[0-9]+)") { $version = $Matches[1] }
    } catch { }
    Write-Log "Suricata version detected: $version"

    $url = "https://rules.emergingthreats.net/open/suricata-$version/emerging.rules.tar.gz"
    $tar = Join-Path $DownloadRoot "emerging.rules.tar.gz"
    Invoke-Download -Uri $url -OutFile $tar

    $extract = Join-Path $StateRoot "rules-extract"
    if (Test-Path -LiteralPath $extract) { Remove-Item -LiteralPath $extract -Recurse -Force }
    New-Directory -Path $extract
    Invoke-Process -FilePath "tar.exe" -ArgumentList @("-xzf", $tar, "-C", $extract) | Out-Null

    $glob = Join-Path $extract "rules\*.rules"
    $ruleFiles = @(Get-ChildItem -Path $glob -ErrorAction SilentlyContinue)
    if (-not $ruleFiles) { throw "No .rules files found in the extracted ET Open archive." }

    $merged = Join-Path $RuleRoot "suricata.rules"
    Get-Content -Path $glob | Set-Content -LiteralPath $merged -Encoding ascii   # ASCII = no BOM (BOM breaks rule 1)
    $count = (Select-String -Path $merged -Pattern "^\s*alert " -ErrorAction SilentlyContinue).Count
    Write-Log "Wrote $merged ($($ruleFiles.Count) files, ~$count alert signatures)."

    $yaml = Get-SuricataYamlPath
    $rc = Invoke-Process -FilePath $exe -ArgumentList @("-T", "-c", $yaml) -IgnoreExitCode
    if ($rc -eq 0) { Write-Log "Config test (suricata -T) passed." }
    else { Write-Log "Config test returned exit $rc - review warnings, continuing." }
}

function Restart-Suricata {
    $exe = Get-SuricataExePath
    $yaml = Get-SuricataYamlPath
    $iface = (Get-CaptureInterfaces | Select-Object -First 1).Device
    $imagePath = '"{0}" -c "{1}" -i "{2}"' -f $exe, $yaml, $iface

    $service = Get-Service -Name "Suricata" -ErrorAction SilentlyContinue
    if (-not $service) {
        Invoke-Process -FilePath $exe -ArgumentList @("--service-install", "-c", $yaml, "-i", $iface) -IgnoreExitCode | Out-Null
        $service = Get-Service -Name "Suricata" -ErrorAction SilentlyContinue
    }
    if (-not $service) {
        New-Service -Name "Suricata" -BinaryPathName $imagePath -DisplayName "Suricata IDS" -StartupType Automatic | Out-Null
        Write-Log "Created Suricata service via New-Service."
        $service = Get-Service -Name "Suricata" -ErrorAction SilentlyContinue
    }
    if (-not $service) { throw "Failed to create the Suricata service." }

    # Force the QUOTED ImagePath - fixes --service-install's unquoted binPath bug
    # (SCM otherwise tries to launch "C:\Program" and the service won't start).
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\Suricata"
    Set-ItemProperty -Path $regPath -Name "ImagePath" -Value $imagePath -Type ExpandString
    Set-Service -Name "Suricata" -StartupType Automatic
    Write-Log "Service ImagePath (quoted): $imagePath"

    Restart-Service -Name "Suricata" -Force
    Start-Sleep -Seconds 2
    $status = (Get-Service -Name "Suricata").Status
    Write-Log "Suricata service status: $status"
    if ($status -ne "Running") { throw "Suricata service did not reach Running (status: $status)." }
}

function Set-WazuhLocalfile {
    if ($SkipWazuhConfig) { Write-Log "Skip Wazuh ossec.conf update."; return }

    $confPath = Get-WazuhConfPath
    if (-not $confPath) { Write-Log "Wazuh agent ossec.conf not found. Skip Wazuh binding."; return }

    $evePath = Join-Path $LogRoot "eve.json"
    $content = Get-Content -LiteralPath $confPath -Raw
    Backup-File -Path $confPath

    # Remove any pre-existing Suricata eve.json <localfile> so we never double-monitor
    # or leave a stale path behind.
    $before = $content
    $content = [regex]::Replace($content, "(?is)[ \t]*<localfile>(?:(?!</localfile>).)*?eve\.json(?:(?!</localfile>).)*?</localfile>\s*", "`r`n")
    if ($content -ne $before) { Write-Log "Removed pre-existing Suricata eve.json localfile block(s)." }

    $block = @"
  <localfile>
    <log_format>json</log_format>
    <location>$evePath</location>
  </localfile>
"@
    if ($content -match "</ossec_config>") {
        $content = [regex]::Replace($content, "(?is)\s*</ossec_config>\s*$", "`r`n$block`r`n</ossec_config>`r`n", 1)
    } else {
        $content += "`r`n$block`r`n"
    }

    Write-TextFileNoBom -Path $confPath -Text $content
    Write-Log "Updated Wazuh config: $confPath -> $evePath"

    $wazuhService = Get-Service -Name "WazuhSvc" -ErrorAction SilentlyContinue
    if ($wazuhService) {
        Restart-Service -Name "WazuhSvc" -Force
        Write-Log "Restarted WazuhSvc."
    }
}

function Write-MaintenanceScript {
    $script = @'
[CmdletBinding()]
param(
    [string]$DataRoot = "__DATA_ROOT__",
    [int64]$MaxEveBytes = __MAX_EVE_BYTES__,
    [int]$KeepRotatedLogs = __KEEP_ROTATED_LOGS__
)

Set-StrictMode -Version 1.0   # 1.0 catches uninitialized vars but does NOT throw on missing properties (registry/CIM objects)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
try { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 -bor [Net.SecurityProtocolType]::Tls13 } catch { [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12 }

$LogRoot = Join-Path $DataRoot "log"
$RuleRoot = Join-Path $DataRoot "rules"
$DownloadRoot = Join-Path $DataRoot "downloads"
$StateRoot = Join-Path $DataRoot "state"
$MaintLog = Join-Path $DataRoot "maintenance.log"

function Write-MaintLog {
    param([string]$Message)
    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss"), $Message
    [System.IO.File]::AppendAllText($MaintLog, "$line`r`n", $Utf8NoBom)
}

function Get-SuricataExe {
    foreach ($p in @("C:\Program Files\Suricata\suricata.exe","C:\Program Files (x86)\Suricata\suricata.exe")) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    $f = Get-ChildItem "C:\Program Files","C:\Program Files (x86)" -Filter "suricata.exe" -Recurse -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($f) { return $f.FullName }
    return $null
}

function Get-SuricataYaml {
    foreach ($p in @("C:\Program Files\Suricata\suricata.yaml","C:\Program Files (x86)\Suricata\suricata.yaml",(Join-Path $DataRoot "suricata.yaml"))) {
        if (Test-Path -LiteralPath $p) { return $p }
    }
    return $null
}

function Restart-SuricataService {
    $service = Get-Service -Name "Suricata" -ErrorAction SilentlyContinue
    if ($service) {
        Restart-Service -Name "Suricata" -Force
        Write-MaintLog "Restarted Suricata service."
        return
    }
    Get-Process -Name "suricata" -ErrorAction SilentlyContinue | Stop-Process -Force
    Write-MaintLog "Suricata service missing; stopped Suricata processes only."
}

function Update-SuricataRules {
    # Direct ET Open download (suricata-update is broken on Windows - Errno 13).
    $exe = Get-SuricataExe
    if (-not $exe) { Write-MaintLog "suricata.exe not found. Skip rule update."; return }

    $ver = "7.0.16"
    try { $vout = (& $exe -V 2>&1 | Out-String); if ($vout -match "version\s+([0-9]+\.[0-9]+\.[0-9]+)") { $ver = $Matches[1] } } catch { }

    New-Item -ItemType Directory -Force $DownloadRoot | Out-Null
    New-Item -ItemType Directory -Force $RuleRoot | Out-Null
    $tar = Join-Path $DownloadRoot "emerging.rules.tar.gz"
    $rurl = "https://rules.emergingthreats.net/open/suricata-$ver/emerging.rules.tar.gz"
    try { Invoke-WebRequest -Uri $rurl -OutFile $tar -UseBasicParsing }
    catch {
        $curl = (Get-Command curl.exe -ErrorAction SilentlyContinue).Source
        if ($curl) { & $curl -L --fail --ssl-no-revoke --retry 2 -o $tar $rurl }
    }
    if (-not (Test-Path -LiteralPath $tar) -or (Get-Item $tar).Length -le 0) { Write-MaintLog "Rule download failed. Skip."; return }

    $extract = Join-Path $StateRoot "rules-extract"
    if (Test-Path -LiteralPath $extract) { Remove-Item -LiteralPath $extract -Recurse -Force }
    New-Item -ItemType Directory -Force $extract | Out-Null
    & tar.exe -xzf $tar -C $extract
    $glob = Join-Path $extract "rules\*.rules"
    if (-not (Get-ChildItem -Path $glob -ErrorAction SilentlyContinue)) { Write-MaintLog "No rules extracted. Skip."; return }

    Get-Content -Path $glob | Set-Content -LiteralPath (Join-Path $RuleRoot "suricata.rules") -Encoding ascii
    $yaml = Get-SuricataYaml
    if ($yaml) { & $exe -T -c $yaml 2>&1 | Out-Null }
    Write-MaintLog "Rules updated via direct ET Open download (Suricata $ver)."
    Restart-SuricataService
}

function Rotate-EveLog {
    $eve = Join-Path $LogRoot "eve.json"
    if (-not (Test-Path -LiteralPath $eve)) { Write-MaintLog "eve.json not found. Skip rotation."; return }

    $item = Get-Item -LiteralPath $eve
    if ($item.Length -lt $MaxEveBytes) {
        Write-MaintLog "eve.json size $($item.Length) below limit $MaxEveBytes."
        return
    }

    Restart-SuricataService
    Start-Sleep -Seconds 2
    Get-Process -Name "suricata" -ErrorAction SilentlyContinue | Stop-Process -Force

    for ($i = $KeepRotatedLogs; $i -ge 1; $i--) {
        $current = Join-Path $LogRoot "eve.json.$i"
        $next = Join-Path $LogRoot "eve.json.$($i + 1)"
        if (Test-Path -LiteralPath $current) {
            if ($i -eq $KeepRotatedLogs) { Remove-Item -LiteralPath $current -Force }
            else { Move-Item -LiteralPath $current -Destination $next -Force }
        }
    }

    Move-Item -LiteralPath $eve -Destination (Join-Path $LogRoot "eve.json.1") -Force
    Restart-SuricataService
    Write-MaintLog "Rotated eve.json."
}

try {
    Update-SuricataRules
    Rotate-EveLog
    Write-MaintLog "Maintenance complete."
} catch {
    Write-MaintLog "ERROR: $($_.Exception.Message)"
    throw
}
'@

    $script = $script.Replace("__DATA_ROOT__", $DataRoot.Replace("\", "\\"))
    $script = $script.Replace("__MAX_EVE_BYTES__", $MaxEveBytes.ToString())
    $script = $script.Replace("__KEEP_ROTATED_LOGS__", $KeepRotatedLogs.ToString())
    Write-TextFileNoBom -Path $MaintenanceScript -Text $script
    Write-Log "Wrote maintenance script: $MaintenanceScript"
}

function Register-MaintenanceTask {
    if ($SkipScheduledTask) { Write-Log "Skip scheduled task."; return }

    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$MaintenanceScript`""
    $trigger = New-ScheduledTaskTrigger -Daily -At $DailyTaskTime
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Hours 2)
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Log "Registered scheduled task: $TaskName at $DailyTaskTime"
}

try {
    New-Directory -Path $DataRoot
    New-Directory -Path $LogRoot
    New-Directory -Path $RuleRoot
    New-Directory -Path $StateRoot
    New-Directory -Path $DownloadRoot

    Write-Log "Start Suricata Windows full auto install."
    Install-Npcap
    Install-Suricata
    Install-SuricataUpdate
    Install-WazuhAgent

    $interfaces = @(Get-CaptureInterfaces)
    foreach ($interface in $interfaces) {
        Write-Log "Capture interface: $($interface.Name) -> $($interface.Device)"
    }

    $yaml = Get-SuricataYamlPath
    Set-SuricataYaml -YamlPath $yaml -Interfaces $interfaces
    Invoke-RuleUpdate
    Restart-Suricata
    Set-WazuhLocalfile
    Write-MaintenanceScript
    Register-MaintenanceTask

    Write-Log "Complete. Suricata eve.json: $(Join-Path $LogRoot "eve.json")"
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    throw
}
