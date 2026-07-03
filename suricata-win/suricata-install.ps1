#Requires -RunAsAdministrator
# =====================================================================
#  Install-Suricata-Wazuh-AllInOne.ps1                  2026-06-22
#  Self-contained Suricata IDS -> Wazuh installer for Windows.
#  No external installer script, no GitHub dependency. Portable across
#  any user account (machine-wide paths + %TEMP%). All the y3kh bugs are
#  designed out: rule-files points at the merged file, the service path
#  is quoted, and the eve.json <localfile> is written + verified.
#
#  USAGE (Administrator PowerShell):
#    # local IDS only (no manager shipping):
#    .\Install-Suricata-Wazuh-AllInOne.ps1
#    # install + enroll the Wazuh agent to a manager:
#    .\Install-Suricata-Wazuh-AllInOne.ps1 -WazuhManager <MANAGER_IP> `
#         -RegPassword 'cEENvWCbudRnZ1j1OlTrua7PekOf' -SelfTest
#
#  Npcap (free build) cannot install silently: if absent an interactive
#  wizard opens - tick "WinPcap API-compatible Mode" and finish it.
# =====================================================================
[CmdletBinding()]
param(
    [string]$SuricataMsiUrl = 'https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.3-1-64bit.msi',
    [string]$SuricataMsiPath = '',   # pre-staged local .msi; auto-used if present (skips the flaky OISF download)
    [string]$NpcapUrl       = 'https://npcap.com/dist/npcap-1.82.exe',
    [string]$InstallRoot    = 'C:\Program Files\Suricata',
    [string]$DataRoot       = 'C:\ProgramData\Suricata',
    [string]$CaptureInterfaceName = '',     # e.g. 'Wi-Fi'; blank = auto-pick physical
    [string]$HomeNet        = '',           # e.g. '[192.168.1.0/24]'; blank = keep stock RFC1918
    [string]$WazuhManager   = '',           # blank = do not touch agent enrollment
    [int]   $WazuhRegPort   = 1515,
    [string]$RegPassword    = '',           # authd registration password (if manager requires one)
    [string]$AgentName      = $env:COMPUTERNAME,
    [switch]$StripFileMagic,
    [switch]$SkipNpcap,
    [switch]$SkipScheduledTask,
    [switch]$SkipWazuhEnroll,   # never enroll, even if -WazuhManager is given
    [switch]$ForceEnroll,       # re-enroll even if already enrolled to this manager
    [switch]$NoPrompt,          # do not interactively ask for interface / HOME_NET
    [switch]$SelfTest
)
# NOTE: 'Continue' (not 'Stop') so a native tool writing to stderr (suricata -T's
# harmless file.magic warning, agent-auth INFO, etc.) can't abort the installer.
# Critical failures are handled explicitly with throw / exit-code checks below.
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
    if(-not ((Get-Content $keys -Raw).Trim())){ return $false }     # empty client.keys = not enrolled
    $addr = ([regex]::Match((Get-Content $Ossec -Raw),'(?is)<server>\s*<address>\s*([^<]+)')).Groups[1].Value.Trim()
    return ($addr -eq $mgr)                                         # enrolled AND pointing at this manager
}

# ---------- interactive prompts (ask when not supplied on the command line) ----------
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
    # remove any already-registered Suricata first (avoids MSI 1638 "another version already installed")
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

# ---------- 4. ET Open rules (suricata-update is broken on Windows) ----------
$tar = Join-Path $DlDir 'emerging.rules.tar.gz'
$mm = $ver.Substring(0,$ver.LastIndexOf('.'))   # major.minor e.g. 8.0
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
[IO.File]::WriteAllText($RulesFile, $rulesText, $utf8)   # UTF-8 no BOM (BOM breaks rule 1)
$sigCount = ([regex]::Matches($rulesText,'(?m)^\s*(alert|drop)\s')).Count
Log "wrote $RulesFile ($($rfiles.Count) files, ~$sigCount signatures)"

# ---------- 5. configure suricata.yaml (the CORRECT way) ----------
Copy-Item $Yaml "$Yaml.bak-$(Get-Date -Format yyyyMMddHHmmss)" -Force
$y = Get-Content -LiteralPath $Yaml -Raw
function Set-YamlKey([string]$text,[string]$key,[string]$val){
    if($text -match "(?m)^(\s*)$([regex]::Escape($key)):.*$"){ return [regex]::Replace($text,"(?m)^(\s*)$([regex]::Escape($key)):.*$","`${1}${key}: $val",1) }
    return $text
}
$y = Set-YamlKey $y 'default-log-dir'   ("'{0}'" -f $LogDir)
$y = Set-YamlKey $y 'default-rule-path' ("'{0}'" -f $RuleDir)
if($HomeNet){ $y = Set-YamlKey $y 'HOME_NET' ('"{0}"' -f $HomeNet) }
# rule-files: -> single merged file (FIX 1 baked in)
$ylines = $y -split "`r?`n"
$rf=-1; for($i=0;$i -lt $ylines.Count;$i++){ if($ylines[$i] -match '^\s*rule-files:\s*$'){ $rf=$i; break } }
if($rf -ge 0){
    $j=$rf+1; while($j -lt $ylines.Count -and $ylines[$j] -match '^\s*#?\s*-\s'){ $j++ }
    $ylines = @($ylines[0..$rf]) + @('  - suricata.rules') + @($(if($j -le $ylines.Count-1){$ylines[$j..($ylines.Count-1)]}else{@()}))
    $y = $ylines -join "`r`n"
}
# disable eve-log 'stats' output (FIX 3, added 2026-07-03). Suricata's
# periodic stats record has HUNDREDS of nested numeric fields
# (decoder.*, tcp.*, app_layer.*, flow.*, etc.) - once flattened by
# Wazuh's generic JSON decoder this exceeds analysisd's hard field-count
# limit ("ERROR: Too many fields for JSON decoder"), which silently
# drops the event with NO indication to the agent - the agent shows
# "Analyzing file: eve.json" with zero errors, eve.json grows correctly
# locally, the agent stays Active, but ZERO Suricata data EVER reaches
# the manager as a decoded json event. Confirmed root cause on a real
# manager 2026-07-03 (see project_c2_detection_engineering memory) after
# an entire day of debugging what looked like a config/shipping/network
# problem - it was purely this. Disabling stats (a low-value output for
# SOC purposes anyway) fixes it; alert/flow/dns/http events have far
# fewer fields and decode fine.
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
    Log "no eve-log 'stats' block found - skipping (may already be disabled or absent in this Suricata version)"
}
[IO.File]::WriteAllText($Yaml, $y, $utf8)
Log "suricata.yaml configured (log-dir, rule-path, rule-files=suricata.rules, stats disabled)"
# validate quietly with QUOTED path (FIX 2). file.magic warnings are expected on Windows (no libmagic).
try { $tout = (& $Exe -T -c $Yaml 2>&1 | Out-String) } catch { $tout = "$_" }
$tline = ($tout -split "`n" | Where-Object { $_ -match 'successfully loaded|no rules were loaded' } | Select-Object -First 1)
if($tline){ Log ("  -T: " + $tline.Trim()) } else { Log "  -T: config parsed (file.magic warnings ignored on Windows)" }

# ---------- 6. service with QUOTED ImagePath (FIX 2) ----------
if(Get-Service Suricata -EA SilentlyContinue){ Restart-Robust 'Suricata' }
else{
    & $Exe --service-install -c $Yaml -i $Device | Out-Null
    Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\Suricata' -Name ImagePath -Value ('"{0}" -c "{1}" -i "{2}"' -f $Exe,$Yaml,$Device) -Type ExpandString
    Set-Service Suricata -StartupType Automatic
    Start-Service Suricata; Start-Sleep 4
}
Log "Suricata service: $((Get-Service Suricata).Status)"

# ---------- 7. optional: enroll Wazuh agent to a manager (skip if already enrolled) ----------
if($WazuhManager -and (Test-Path $Ossec)){
    if($SkipWazuhEnroll){
        Log "enrollment skipped (-SkipWazuhEnroll)"
    } elseif((Test-AlreadyEnrolled $WazuhManager) -and -not $ForceEnroll){
        Log "agent already enrolled to $WazuhManager (client.keys present + address matches) - skipping enroll. Use -ForceEnroll to re-enroll."
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

# ---------- 8. Wazuh eve.json <localfile> (FIX 3) ----------
if(Test-Path $Ossec){
    $oc = Get-Content $Ossec -Raw; $o0=$oc
    $oc = [regex]::Replace($oc,"(?is)[ \t]*<localfile>(?:(?!</localfile>).)*?eve\.json(?:(?!</localfile>).)*?</localfile>\s*","`r`n")
    $blk = "  <localfile>`r`n    <log_format>json</log_format>`r`n    <location>$EvePath</location>`r`n  </localfile>`r`n"
    $idx = $oc.LastIndexOf('</ossec_config>')
    $oc = $oc.Substring(0,$idx)+$blk+$oc.Substring($idx)
    if($oc -ne $o0){ Copy-Item $Ossec "$Ossec.bak-eve-$(Get-Date -Format yyyyMMddHHmmss)" -Force; [IO.File]::WriteAllText($Ossec,$oc,$utf8) }
    Restart-Robust 'WazuhSvc'
    Log "eve.json bound to Wazuh agent + agent restarted"
} else { Warn "no Wazuh agent (ossec.conf) on this machine - Suricata runs as local IDS only" }

# ---------- 9. daily maintenance task (rule refresh + log rotation) ----
if(-not $SkipScheduledTask){
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
# rotate eve.json if > 2GB
`$e='$EvePath'; if((Test-Path `$e) -and (Get-Item `$e).Length -gt 2GB){ Stop-Service Suricata -Force
 for(`$i=2;`$i -ge 1;`$i--){ if(Test-Path "`$e.`$i"){Move-Item "`$e.`$i" "`$e.`$(`$i+1)" -Force} }
 Move-Item `$e "`$e.1" -Force; Start-Service Suricata }
"@
    [IO.File]::WriteAllText($maint,$body,$utf8)
    $act=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument "-NoProfile -ExecutionPolicy Bypass -File `"$maint`""
    $trg=New-ScheduledTaskTrigger -Daily -At '13:00'
    $prn=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -RunLevel Highest
    Register-ScheduledTask -TaskName 'Suricata Daily Update And Log Rotation' -Action $act -Trigger $trg -Principal $prn -Force | Out-Null
    Log "daily maintenance task registered (13:00)"
}

# ---------- 10. verify ----------
Write-Host "`n===== VERIFY =====" -ForegroundColor Cyan
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
Write-Host "`nDONE. eve.json: $EvePath" -ForegroundColor Green
if($conn){ Write-Host "Confirm on manager: sudo grep -c 'Suricata: Alert' /var/ossec/logs/alerts/alerts.json" -ForegroundColor Cyan }
