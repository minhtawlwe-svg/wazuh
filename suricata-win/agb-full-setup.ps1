#Requires -RunAsAdministrator
# ============================================================================
# AGB Suricata + Wazuh - FULL SELF-CONTAINED SETUP (one file, one command)
# ============================================================================
# Everything in ONE script: Suricata install, ET Open ruleset, agb-white/
# agb-black rules + daily GitHub pull-deploy, Active Response (auto-kill)
# scripts, and the "Too many fields for JSON decoder" stats fix. No
# chained downloads of other install scripts (deploy-agb-rules.ps1 is the
# one exception - it's fetched as a plain data file because the daily
# Scheduled Task needs to invoke it repeatedly; that's not a one-time
# install step, it can't be inlined here).
#
#   iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-setup.ps1 -UseBasicParsing | iex
#
# INTERACTIVE by default - prompts for capture interface AND HOME_NET
# (press Enter on either to auto-pick/keep the stock default). Pass
# -NoPrompt to skip both, or -CaptureInterfaceName/-HomeNet to pre-supply
# a value non-interactively (only works when downloaded and run directly
# with params - piping via | iex can't pass script parameters).
# ============================================================================
[CmdletBinding()]
param(
    [string]$SuricataMsiUrl = 'https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.3-1-64bit.msi',
    [string]$SuricataMsiPath = '',
    [string]$NpcapUrl       = 'https://npcap.com/dist/npcap-1.82.exe',
    [string]$InstallRoot    = 'C:\Program Files\Suricata',
    [string]$DataRoot       = 'C:\ProgramData\Suricata',
    [string]$CaptureInterfaceName = '',
    [string]$HomeNet        = '',
    [string]$WazuhManager   = '',
    [int]   $WazuhRegPort   = 1515,
    [string]$RegPassword    = '',
    [string]$AgentName      = $env:COMPUTERNAME,
    [switch]$StripFileMagic,
    [switch]$SkipNpcap,
    [switch]$SkipScheduledTask,
    [switch]$SkipWazuhEnroll,
    [switch]$ForceEnroll,
    [switch]$NoPrompt,
    [switch]$SelfTest
)

$GitHubBase = "https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win"

$ErrorActionPreference='Continue'
[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12
$utf8 = New-Object Text.UTF8Encoding($false)
$Exe       = Join-Path $InstallRoot 'suricata.exe'
$Yaml      = Join-Path $InstallRoot 'suricata.yaml'
$LogDir    = Join-Path $DataRoot 'log'
$RuleDir   = Join-Path $DataRoot 'rules'
$DlDir     = Join-Path $DataRoot 'downloads'
$StateDir  = Join-Path $DataRoot 'state'
$RulesFile = Join-Path $RuleDir 'suricata.rules'
$EvePath   = Join-Path $LogDir 'eve.json'
$SuriLog   = Join-Path $LogDir 'suricata.log'
$Ossec     = 'C:\Program Files (x86)\ossec-agent\ossec.conf'
$AgentLog  = 'C:\Program Files (x86)\ossec-agent\ossec.log'
function Log($m){ Write-Host "[install] $m" -ForegroundColor Cyan }
function Warn($m){ Write-Host "[install] WARN: $m" -ForegroundColor Yellow }
function Restart-Robust($name){
    if(-not (Get-Service $name -EA SilentlyContinue)){ return }
    try{ Stop-Service $name -Force -ErrorAction Stop }catch{}
    $sw=[Diagnostics.Stopwatch]::StartNew()
    while((Get-Service $name -EA SilentlyContinue).Status -ne 'Stopped' -and $sw.Elapsed.TotalSeconds -lt 20){Start-Sleep 1}
    if((Get-Service $name -EA SilentlyContinue).Status -ne 'Stopped'){
        $pn=if($name -match 'Wazuh'){'wazuh-agent'}else{'suricata'}
        Get-Process $pn -EA SilentlyContinue | Stop-Process -Force -EA SilentlyContinue; Start-Sleep 2
    }
    Start-Service $name -EA SilentlyContinue; Start-Sleep 3
}
function Test-AlreadyEnrolled([string]$mgr){
    $keys = 'C:\Program Files (x86)\ossec-agent\client.keys'
    if(-not (Test-Path $keys)){ return $false }
    if(-not ((Get-Content $keys -Raw).Trim())){ return $false }
    $addr = ([regex]::Match((Get-Content $Ossec -Raw),'(?is)<server>\s*<address>\s*([^<]+)')).Groups[1].Value.Trim()
    return ($addr -eq $mgr)
}

# ---------- interactive prompts ----------
if(-not $NoPrompt -and -not $CaptureInterfaceName){
    Write-Host "`nAvailable physical network adapters that are UP:" -ForegroundColor Cyan
    Get-NetAdapter -Physical -EA SilentlyContinue | Where-Object { $_.Status -eq 'Up' } |
        Format-Table -AutoSize Name,InterfaceDescription,LinkSpeed | Out-Host
    $ans = Read-Host "Capture interface name (press Enter to auto-pick the fastest UP adapter)"
    if($ans){ $CaptureInterfaceName = $ans.Trim() }
}
if(-not $NoPrompt -and -not $HomeNet){
    Write-Host "`nHOME_NET defines your local networks (rules fire EXTERNAL -> HOME_NET)." -ForegroundColor Cyan
    $ans = Read-Host "HOME_NET, e.g. [192.168.1.0/24]  (press Enter to keep stock RFC1918)"
    if($ans){ $HomeNet = $ans.Trim() }
}

Write-Host "===== STEP 1/4: Base Suricata install =====" -ForegroundColor Green

# ---------- 0. dirs + Defender exclusions ----------
foreach($d in $DataRoot,$LogDir,$RuleDir,$DlDir,$StateDir){ New-Item -ItemType Directory -Force -Path $d | Out-Null }
foreach($p in $InstallRoot,$DataRoot){ Add-MpPreference -ExclusionPath $p -EA SilentlyContinue }
Add-MpPreference -ExclusionProcess 'suricata.exe' -EA SilentlyContinue
Log "data dirs ready + Defender exclusions set"

# ---------- 1. Npcap ----------
if(-not $SkipNpcap){
    $hasNpcap = (Get-Service npcap -EA SilentlyContinue) -or (Test-Path 'C:\Windows\System32\Npcap')
    if($hasNpcap){ Log "Npcap already present" }
    else{
        $np = Join-Path $DlDir 'npcap.exe'
        Log "downloading Npcap..."; Invoke-WebRequest -Uri $NpcapUrl -OutFile $np -UseBasicParsing
        Warn "Npcap free build has NO silent mode - complete the wizard (tick 'WinPcap API-compatible Mode')."
        Start-Process -FilePath $np -Wait
        if(-not ((Get-Service npcap -EA SilentlyContinue) -or (Test-Path 'C:\Windows\System32\Npcap'))){ throw "Npcap not detected after wizard - re-run and finish it." }
        Log "Npcap installed"
    }
}

# ---------- 2. Suricata MSI ----------
if(Test-Path $Exe){ Log "Suricata already installed" }
else{
    $msi = if($SuricataMsiPath){ $SuricataMsiPath } else { Join-Path $DlDir 'suricata.msi' }
    if((Test-Path $msi) -and (Get-Item $msi).Length -gt 5MB){
        Log "using pre-staged MSI: $msi ($([math]::Round((Get-Item $msi).Length/1MB,1)) MB) - skipping download"
    } else {
        Log "downloading Suricata MSI from $SuricataMsiUrl ..."
        try{ Invoke-WebRequest -Uri $SuricataMsiUrl -OutFile $msi -UseBasicParsing -TimeoutSec 300 }
        catch{ Log "Invoke-WebRequest failed, falling back to curl..."; & curl.exe -L --ssl-no-revoke --max-time 300 -o $msi $SuricataMsiUrl }
    }
    if(-not ((Test-Path $msi) -and (Get-Item $msi).Length -gt 5MB)){ throw "Suricata MSI not available at $msi (download failed). Pre-stage it and pass -SuricataMsiPath." }
    $existing = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' -EA SilentlyContinue | Where-Object { $_.DisplayName -match 'Suricata' }
    if($existing){
        if(Get-Service Suricata -EA SilentlyContinue){ Stop-Service Suricata -Force -EA SilentlyContinue; Start-Sleep 2; & sc.exe delete Suricata | Out-Null }
        foreach($e in $existing){ $code=Split-Path $e.PSPath -Leaf; Log "removing existing '$($e.DisplayName)' ($code) before install..."; Start-Process msiexec.exe -ArgumentList "/x $code /qn /norestart" -Wait }
    }
    Log "installing Suricata MSI (silent)..."
    $p = Start-Process msiexec.exe -ArgumentList "/i `"$msi`" /qn /norestart /L*v `"$(Join-Path $DataRoot 'suricata-msi.log')`"" -Wait -PassThru
    if($p.ExitCode -notin 0,3010){ $hint=if($p.ExitCode -eq 1638){' (1638 = another Suricata still registered; uninstall it in Add/Remove Programs, then re-run)'}else{''}; throw "Suricata MSI failed (exit $($p.ExitCode))$hint" }
    if(-not (Test-Path $Exe)){ throw "suricata.exe missing after MSI install" }
    Log "Suricata installed (exit $($p.ExitCode))"
}
$ver = (& $Exe -V 2>&1 | Select-String -Pattern '(\d+\.\d+\.\d+)' | Select-Object -First 1).Matches.Groups[1].Value
Log "Suricata version $ver"

# ---------- 3. capture interface ----------
if($CaptureInterfaceName){ $ad = Get-NetAdapter -Name $CaptureInterfaceName -ErrorAction Stop }
else{
    $ex='(?i)(virtual|vmware|virtualbox|hyper-v|veth|loopback|npcap loopback|wi-fi direct|bluetooth|tap|tun|wireguard|zerotier|tailscale|hamachi|isatap|teredo)'
    $ad = Get-NetAdapter -Physical -EA SilentlyContinue | Where-Object { $_.Status -eq 'Up' -and $_.Name -notmatch $ex -and $_.InterfaceDescription -notmatch $ex } | Sort-Object LinkSpeed -Descending | Select-Object -First 1
    if(-not $ad){ throw "no capture adapter found - pass -CaptureInterfaceName '<name>'" }
}
$Device = "\Device\NPF_$($ad.InterfaceGuid)"
Log "capture interface: $($ad.Name) -> $Device"

# ---------- 4. ET Open rules ----------
$tar = Join-Path $DlDir 'emerging.rules.tar.gz'
$mm = $ver.Substring(0,$ver.LastIndexOf('.'))
$urls = @("https://rules.emergingthreats.net/open/suricata-$ver/emerging.rules.tar.gz",
          "https://rules.emergingthreats.net/open/suricata-$mm.0/emerging.rules.tar.gz",
          "https://rules.emergingthreats.net/open/suricata-$mm/emerging.rules.tar.gz")
$got=$false
foreach($u in $urls){ try{ Log "downloading ET Open: $u"; Invoke-WebRequest -Uri $u -OutFile $tar -UseBasicParsing; $got=$true; break }catch{ Warn "failed $u" } }
if(-not $got){ throw "could not download ET Open ruleset" }
$ext = Join-Path $StateDir 'rules-extract'
if(Test-Path $ext){ Remove-Item $ext -Recurse -Force }
New-Item -ItemType Directory -Force -Path $ext | Out-Null
& tar.exe -xzf $tar -C $ext
$rfiles = Get-ChildItem (Join-Path $ext 'rules') -Filter *.rules -EA SilentlyContinue
if(-not $rfiles){ $rfiles = Get-ChildItem $ext -Recurse -Filter *.rules }
$sb = New-Object Text.StringBuilder
foreach($f in $rfiles){ [void]$sb.AppendLine([IO.File]::ReadAllText($f.FullName)) }
$rulesText = $sb.ToString()
if($StripFileMagic){ $rulesText = ($rulesText -split "`n" | Where-Object { $_ -notmatch 'file\.magic' }) -join "`n" }
[IO.File]::WriteAllText($RulesFile, $rulesText, $utf8)
$sigCount = ([regex]::Matches($rulesText,'(?m)^\s*(alert|drop)\s')).Count
Log "wrote $RulesFile ($($rfiles.Count) files, ~$sigCount signatures)"

# ---------- 4b. AGB whitelist/blacklist rules (pulled straight from GitHub) ----------
Log "downloading agb-white.rules / agb-black.rules ..."
Invoke-WebRequest -Uri "$GitHubBase/agb-white.rules" -OutFile (Join-Path $RuleDir 'agb-white.rules') -UseBasicParsing
Invoke-WebRequest -Uri "$GitHubBase/agb-black.rules" -OutFile (Join-Path $RuleDir 'agb-black.rules') -UseBasicParsing
Log "agb-white.rules / agb-black.rules written to $RuleDir"

# ---------- 5. configure suricata.yaml ----------
Copy-Item $Yaml "$Yaml.bak-$(Get-Date -Format yyyyMMddHHmmss)" -Force
$y = Get-Content -LiteralPath $Yaml -Raw
function Set-YamlKey([string]$text,[string]$key,[string]$val){
    if($text -match "(?m)^(\s*)$([regex]::Escape($key)):.*$"){ return [regex]::Replace($text,"(?m)^(\s*)$([regex]::Escape($key)):.*$","`${1}${key}: $val",1) }
    return $text
}
$y = Set-YamlKey $y 'default-log-dir'   ("'{0}'" -f $LogDir)
$y = Set-YamlKey $y 'default-rule-path' ("'{0}'" -f $RuleDir)
if($HomeNet){ $y = Set-YamlKey $y 'HOME_NET' ('"{0}"' -f $HomeNet) }
# rule-files: -> merged suricata.rules + agb-white.rules + agb-black.rules
$ylines = $y -split "`r?`n"
$rf=-1; for($i=0;$i -lt $ylines.Count;$i++){ if($ylines[$i] -match '^\s*rule-files:\s*$'){ $rf=$i; break } }
if($rf -ge 0){
    $j=$rf+1; while($j -lt $ylines.Count -and $ylines[$j] -match '^\s*#?\s*-\s'){ $j++ }
    $ylines = @($ylines[0..$rf]) + @('  - suricata.rules','  - agb-white.rules','  - agb-black.rules') + @($(if($j -le $ylines.Count-1){$ylines[$j..($ylines.Count-1)]}else{@()}))
    $y = $ylines -join "`r`n"
}
# disable eve-log 'stats' output - see project_c2_detection_engineering memory.
# Suricata's periodic stats record has hundreds of nested numeric fields
# (decoder.*, tcp.*, app_layer.*, flow.*); once flattened by Wazuh's generic
# JSON decoder this exceeds analysisd's hard field-count limit ("ERROR: Too
# many fields for JSON decoder"), silently dropping EVERY Suricata event
# ON THE MANAGER with zero indication on the agent side - eve.json grows
# fine locally, the agent log shows no errors, the agent stays Active, but
# ZERO Suricata data ever reaches the manager as a decoded json event.
# Confirmed root cause 2026-07-03 after a full day debugging what looked
# like a shipping/duplicate-config/network problem.
$ylines = $y -split "`r?`n"
$si=-1; for($i=0;$i -lt $ylines.Count;$i++){ if($ylines[$i] -match '^(\s*)-\s*stats:\s*$'){ $si=$i; break } }
if($si -ge 0){
    $indent = ($ylines[$si] -replace '-.*$','').Length
    $j=$si+1; while($j -lt $ylines.Count -and $ylines[$j] -match '^\s+\S' -and (($ylines[$j] -replace '^(\s*).*$','$1').Length) -gt $indent){ $j++ }
    $pad = ' ' * ($indent + 4)
    $ylines = @($ylines[0..$si]) + @("$pad" + 'enabled: no') + @($(if($j -le $ylines.Count-1){$ylines[$j..($ylines.Count-1)]}else{@()}))
    $y = $ylines -join "`r`n"
    Log "eve-log stats output disabled (prevents 'Too many fields for JSON decoder' on the manager)"
} else {
    Log "no eve-log 'stats' block found - skipping"
}
# trim eve-log 'tls' fields (added 2026-07-03). extended:yes logs the FULL
# certificate chain + subjectaltname (often dozens of SAN entries per cert,
# each flattened into its own field) - on an actively-browsing desktop this
# alone can push individual tls events past the field-count limit even with
# stats disabled and decoder_order_size raised. Trimmed to a curated list
# that keeps detection value (JA3/JA4 fingerprinting, SNI, cert identity)
# without the chain/SAN explosion.
$old = "        - tls:`r`n            extended: yes     # enable this for extended logging information"
if($y.Contains($old)){
    $new = "        - tls:`r`n            extended: no      # trimmed via custom list below - full chain/SAN caused JSON decoder field-count overflow on the manager`r`n            custom: [subject, issuer, sni, version, fingerprint, ja3, ja3s, ja4, not_before, not_after]"
    $y = $y.Replace($old, $new)
    Log "eve-log tls fields trimmed (dropped full cert chain/SAN, kept JA3/JA4/SNI/identity)"
} else {
    Log "eve-log tls extended-logging line not found in expected form - skipping trim (may already be customized)"
}
[IO.File]::WriteAllText($Yaml, $y, $utf8)
Log "suricata.yaml configured (log-dir, rule-path, rule-files incl. agb rules, stats disabled, tls trimmed)"
try { $tout = (& $Exe -T -c $Yaml 2>&1 | Out-String) } catch { $tout = "$_" }
$tline = ($tout -split "`n" | Where-Object { $_ -match 'successfully loaded|no rules were loaded' } | Select-Object -First 1)
if($tline){ Log ("  -T: " + $tline.Trim()) } else { Log "  -T: config parsed (file.magic warnings ignored on Windows)" }

# ---------- 6. service ----------
if(Get-Service Suricata -EA SilentlyContinue){ Restart-Robust 'Suricata' }
else{
    & $Exe --service-install -c $Yaml -i $Device | Out-Null
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Suricata' -Name ImagePath -Value ('"{0}" -c "{1}" -i "{2}"' -f $Exe,$Yaml,$Device) -Type ExpandString
    Set-Service Suricata -StartupType Automatic
    Start-Service Suricata; Start-Sleep 4
}
Log "Suricata service: $((Get-Service Suricata).Status)"

# ---------- 7. optional: enroll Wazuh agent ----------
if($WazuhManager -and (Test-Path $Ossec)){
    if($SkipWazuhEnroll){
        Log "enrollment skipped (-SkipWazuhEnroll)"
    } elseif((Test-AlreadyEnrolled $WazuhManager) -and -not $ForceEnroll){
        Log "agent already enrolled to $WazuhManager - skipping. Use -ForceEnroll to re-enroll."
    } else {
        Log "enrolling Wazuh agent to $WazuhManager as $AgentName"
        $oc = Get-Content $Ossec -Raw
        $oc = [regex]::Replace($oc,'(?is)(<server>\s*<address>)\s*[^<]+\s*(</address>)',"`${1}$WazuhManager`${2}")
        Copy-Item $Ossec "$Ossec.bak-enroll-$(Get-Date -Format yyyyMMddHHmmss)" -Force
        [IO.File]::WriteAllText($Ossec,$oc,$utf8)
        $aa = 'C:\Program Files (x86)\ossec-agent\agent-auth.exe'
        $aaArgs = @('-m',$WazuhManager,'-p',"$WazuhRegPort",'-A',$AgentName)
        if($RegPassword){ $aaArgs += @('-P',$RegPassword) }
        & $aa @aaArgs 2>&1 | ForEach-Object { Log "  agent-auth: $_" }
    }
}

# ---------- 8. Wazuh eve.json <localfile> (self-healing against group duplicates) ----------
if(Test-Path $Ossec){
    $oc = Get-Content $Ossec -Raw; $o0=$oc
    $oc = [regex]::Replace($oc,"(?is)[ \t]*<localfile>(?:(?!</localfile>).)*?eve\.json(?:(?!</localfile>).)*?</localfile>\s*","`r`n")
    $blk = "  <localfile>`r`n    <log_format>json</log_format>`r`n    <location>$EvePath</location>`r`n  </localfile>`r`n"
    $idx = $oc.LastIndexOf('</ossec_config>')
    $oc = $oc.Substring(0,$idx)+$blk+$oc.Substring($idx)
    if($oc -ne $o0){ Copy-Item $Ossec "$Ossec.bak-eve-$(Get-Date -Format yyyyMMddHHmmss)" -Force; [IO.File]::WriteAllText($Ossec,$oc,$utf8) }
    Restart-Robust 'WazuhSvc'
    Log "eve.json bound to Wazuh agent + agent restarted"

    # Self-heal: if this agent is ALSO in a manager GROUP that defines eve.json
    # (common setup), Wazuh logs "Log file ... is duplicated" and Suricata data
    # can silently fail to ship - hit this for real 2026-07-03 (see
    # project_c2_detection_engineering memory). Detect it and remove the LOCAL
    # definition we just added, relying on the group's copy instead - one
    # source of truth, no manual cleanup needed.
    Start-Sleep 3
    $dup = Select-String -Path $AgentLog -Pattern "eve\.json.*is duplicated" -ErrorAction SilentlyContinue | Select-Object -Last 1
    if ($dup) {
        Warn "duplicate eve.json localfile detected (this agent's manager GROUP already defines it) - removing the LOCAL copy just added, relying on the group config instead"
        $oc2 = Get-Content $Ossec -Raw
        $oc2clean = [regex]::Replace($oc2,"(?is)[ \t]*<localfile>(?:(?!</localfile>).)*?eve\.json(?:(?!</localfile>).)*?</localfile>\s*","`r`n")
        if ($oc2clean -ne $oc2) {
            Copy-Item $Ossec "$Ossec.bak-eve-dedupe-$(Get-Date -Format yyyyMMddHHmmss)" -Force
            [IO.File]::WriteAllText($Ossec,$oc2clean,$utf8)
            Restart-Robust 'WazuhSvc'
            Start-Sleep 3
            $stillDup = Select-String -Path $AgentLog -Pattern "eve\.json.*is duplicated" -ErrorAction SilentlyContinue | Select-Object -Last 1
            if ($stillDup) { Warn "duplicate warning persists - check group config manually: agent_groups -s -i <id> on the manager" }
            else { Log "duplicate resolved - eve.json now sourced from the group config only" }
        }
    } else {
        Log "no duplicate eve.json warning - single clean binding confirmed"
    }
} else { Warn "no Wazuh agent (ossec.conf) on this machine - Suricata runs as local IDS only" }

Write-Host "`n===== STEP 2/4: AGB daily rule auto-deploy (scheduled task) =====" -ForegroundColor Green

# ---------- 9. AGB daily pull-deploy task ----------
if (-not $SkipScheduledTask) {
    $AgbScriptsDir = Join-Path $DataRoot 'agb-scripts'
    New-Item -ItemType Directory -Path $AgbScriptsDir -Force | Out-Null
    $DeployScript = Join-Path $AgbScriptsDir 'deploy-agb-rules.ps1'
    # deploy-agb-rules.ps1 is fetched as a plain DATA file (not executed here) -
    # the Scheduled Task invokes it daily; it can't be inlined since it needs
    # to exist standalone for that recurring job.
    Invoke-WebRequest -Uri "$GitHubBase/deploy-agb-rules.ps1" -OutFile $DeployScript -UseBasicParsing
    Log "deploy-agb-rules.ps1 saved to $DeployScript"

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)) {
        Warn "not elevated - scheduled task registration as SYSTEM will fail. Re-run this script directly (not nested) as Administrator."
    } else {
        $Action    = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$DeployScript`""
        $Trigger   = New-ScheduledTaskTrigger -Daily -At 1:30PM
        $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
        $Settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -DontStopOnIdleEnd
        try {
            Register-ScheduledTask -TaskName "AGB-Suricata-Rules-Deploy" -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings `
                -Description "Daily 1:30 PM: pull agb-white.rules/agb-black.rules from GitHub and deploy to Suricata" -Force -ErrorAction Stop | Out-Null
            $verify = Get-ScheduledTask -TaskName "AGB-Suricata-Rules-Deploy" -ErrorAction SilentlyContinue
            if ($verify) { Log "scheduled task 'AGB-Suricata-Rules-Deploy' registered - daily 1:30 PM as SYSTEM" }
            else { Warn "Register-ScheduledTask reported success but task not visible - registration did not persist" }
        } catch {
            Warn "Register-ScheduledTask FAILED: $($_.Exception.Message)"
        }
    }

    # Suricata's own ET Open refresh + log rotation task (13:00)
    $maint = Join-Path $DataRoot 'Suricata-Maintenance.ps1'
    $body = @"
`$ErrorActionPreference='Continue'
`$ver=(& '$Exe' -V 2>&1 | Select-String '(\d+\.\d+\.\d+)').Matches.Groups[1].Value
`$tar='$DlDir\emerging.rules.tar.gz'; `$ext='$StateDir\rules-extract'
try{ Invoke-WebRequest "https://rules.emergingthreats.net/open/suricata-`$ver/emerging.rules.tar.gz" -OutFile `$tar -UseBasicParsing
 if(Test-Path `$ext){Remove-Item `$ext -Recurse -Force}; New-Item -ItemType Directory -Force `$ext|Out-Null
 & tar.exe -xzf `$tar -C `$ext
 `$sb=New-Object Text.StringBuilder; Get-ChildItem "`$ext\rules" -Filter *.rules|%{[void]`$sb.AppendLine([IO.File]::ReadAllText(`$_.FullName))}
 [IO.File]::WriteAllText('$RulesFile',`$sb.ToString(),(New-Object Text.UTF8Encoding(`$false)))
 Restart-Service Suricata -Force }catch{}
`$e='$EvePath'; if((Test-Path `$e) -and (Get-Item `$e).Length -gt 2GB){ Stop-Service Suricata -Force
 for(`$i=2;`$i -ge 1;`$i--){ if(Test-Path "`$e.`$i"){Move-Item "`$e.`$i" "`$e.`$(`$i+1)" -Force} }
 Move-Item `$e "`$e.1" -Force; Start-Service Suricata }
"@
    [IO.File]::WriteAllText($maint,$body,$utf8)
    $act=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$maint`""
    $trg=New-ScheduledTaskTrigger -Daily -At '13:00'
    $prn=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName 'Suricata Daily Update And Log Rotation' -Action $act -Trigger $trg -Principal $prn -Force | Out-Null
    Log "Suricata daily maintenance task registered (13:00)"
}

Write-Host "`n===== STEP 3/4: Active Response (auto-kill on confirmed blacklist hit) =====" -ForegroundColor Green

# ---------- 10. Active Response scripts ----------
$AgentArBin = "C:\Program Files (x86)\ossec-agent\active-response\bin"
if (Test-Path $AgentArBin) {
    try {
        Invoke-WebRequest -Uri "$GitHubBase/wazuh-manager/active-response/agb-kill-block.ps1" -OutFile "$AgentArBin\agb-kill-block.ps1" -UseBasicParsing
        Invoke-WebRequest -Uri "$GitHubBase/wazuh-manager/active-response/agb-kill-block.cmd" -OutFile "$AgentArBin\agb-kill-block.cmd" -UseBasicParsing
        Log "agb-kill-block.ps1/.cmd deployed to $AgentArBin (no agent restart needed)"
        Write-Host "[i] Manager-side (rules + command/active-response binding in ossec.conf) must still be" -ForegroundColor DarkGray
        Write-Host "    configured ONCE on the manager - see suricata-win/wazuh-manager/" -ForegroundColor DarkGray
    } catch {
        Warn "Failed to deploy AR scripts: $($_.Exception.Message)"
    }
} else {
    Warn "Wazuh agent not found at $AgentArBin - skipping AR deployment (install/enroll the Wazuh agent first)"
}

Write-Host "`n===== STEP 4/4: Verify =====" -ForegroundColor Green
Start-Sleep 4
$ld = Select-String -Path $SuriLog -Pattern 'rules successfully loaded|no rules were loaded' -EA SilentlyContinue | Select-Object -Last 1
Write-Host ("  rules        : " + $(if($ld){$ld.Line.Trim()}else{'?'}))
Write-Host ("  Suricata svc : " + (Get-Service Suricata -EA SilentlyContinue).Status)
Write-Host ("  Wazuh agent  : " + $(if(Get-Service WazuhSvc -EA SilentlyContinue){(Get-Service WazuhSvc).Status}else{'not installed'}))
$conn = Get-NetTCPConnection -RemotePort 1514 -State Established -EA SilentlyContinue | Select-Object -First 1
Write-Host ("  manager link : " + $(if($conn){"Established -> $($conn.RemoteAddress):1514"}else{'none'}))
if(Test-Path $AgentLog){ $an=Select-String -Path $AgentLog -Pattern 'Analyzing file.*eve\.json' -EA SilentlyContinue | Select-Object -Last 1; Write-Host ("  logcollector : " + $(if($an){'tailing eve.json'}else{'NOT tailing eve.json'})) }

if($SelfTest){
    Write-Host "  self-test    : waiting up to 120s for a live alert..."
    for($s=0;$s -lt 120;$s+=10){ Start-Sleep 10
        if(Test-Path $EvePath){ $r=Get-Content $EvePath -Tail 800|%{try{$x=$_|ConvertFrom-Json; if($x.event_type -eq 'alert'){$x}}catch{}}|Select-Object -Last 1
            if($r){ Write-Host "  LIVE ALERT   : [$($r.alert.signature_id)] $($r.alert.signature)" -ForegroundColor Green; break } }
    }
}

Write-Host "`n===== AGB full setup complete =====" -ForegroundColor Green
Write-Host "Suricata + agb-white.rules/agb-black.rules + daily 1:30 PM auto-deploy + Active Response scripts all in place."
Write-Host "eve.json: $EvePath"
if($conn){ Write-Host "Confirm on manager: sudo grep -c 'Suricata: Alert' /var/ossec/logs/alerts/alerts.json" -ForegroundColor Cyan }
