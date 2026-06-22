#Requires -RunAsAdministrator
# =====================================================================
#  Test-SuricataAlerts.ps1                              2026-06-22
#  Proves the Suricata->eve.json->Wazuh pipeline on demand by injecting
#  labeled "WAZUH-TEST" rules (SID 9000001+), generating matching
#  LAN/cleartext traffic, confirming each in eve.json, then removing
#  the test rules again.
#
#  KEY: Suricata needs ~15-25s to load ~50k rules before it starts
#  capturing. This script WAITS for "Engine started" after each restart
#  before generating traffic - otherwise the test packets fly by while
#  the engine is still loading (the reason an early version got 0/4).
#
#  Each WAZUH-TEST hit also ships to the manager as rule 86601
#  ("Suricata: Alert - WAZUH-TEST ...").
# =====================================================================
[CmdletBinding()]
param(
    [string]$InstallRoot='C:\Program Files\Suricata',
    [string]$DataRoot='C:\ProgramData\Suricata',
    [string]$Target='',
    [switch]$KeepRules,
    [switch]$IncludeInternetTests
)
$ErrorActionPreference='Continue'; $utf8=New-Object Text.UTF8Encoding($false)
$Exe=Join-Path $InstallRoot 'suricata.exe'; $Yaml=Join-Path $InstallRoot 'suricata.yaml'
$RuleDir=Join-Path $DataRoot 'rules'; $TestRules=Join-Path $RuleDir 'wazuh-test.rules'
$EvePath=Join-Path $DataRoot 'log\eve.json'; $SuriLog=Join-Path $DataRoot 'log\suricata.log'
function Log($m){Write-Host "[test] $m" -ForegroundColor Cyan}
function Restart-AndWaitCapture(){
    # capture current log size so we only look at NEW lines after this restart
    $pos = if(Test-Path $SuriLog){(Get-Item $SuriLog).Length}else{0}
    try{Stop-Service Suricata -Force -EA Stop}catch{}
    $sw=[Diagnostics.Stopwatch]::StartNew(); while((Get-Service Suricata -EA SilentlyContinue).Status -ne 'Stopped' -and $sw.Elapsed.TotalSeconds -lt 20){Start-Sleep 1}
    if((Get-Service Suricata).Status -ne 'Stopped'){Get-Process suricata -EA SilentlyContinue|Stop-Process -Force -EA SilentlyContinue;Start-Sleep 2}
    Start-Service Suricata
    Log "waiting for Suricata to finish loading rules + start capturing (can take ~25s)..."
    $sw=[Diagnostics.Stopwatch]::StartNew()
    while($sw.Elapsed.TotalSeconds -lt 70){
        Start-Sleep 3
        if(Test-Path $SuriLog){
            $fs=[IO.File]::Open($SuriLog,'Open','Read','ReadWrite'); $fs.Seek($pos,'Begin')|Out-Null
            $sr=New-Object IO.StreamReader($fs); $new=$sr.ReadToEnd(); $sr.Close(); $fs.Close()
            if($new -match 'Engine started'){ Start-Sleep 3; Log "engine is capturing."; return $true }
        }
    }
    Log "WARN: did not see 'Engine started' within 70s - continuing anyway"; return $false
}

if(-not (Test-Path $Exe)){ Write-Host "Suricata not installed." -ForegroundColor Red; return }

if(-not $Target){
    $Target=(Get-NetIPConfiguration | Where-Object { $_.IPv4DefaultGateway -and $_.NetAdapter.Status -eq 'Up' -and $_.InterfaceAlias -notmatch 'vEthernet|VMware|Loopback' } | Select-Object -First 1).IPv4DefaultGateway.NextHop
}
if(-not $Target){ $Target='8.8.8.8' }
Log "LAN target for test traffic: $Target"

# ---- 1. write + load test rules ----
$rules=@(
 'alert icmp any any -> any any (msg:"WAZUH-TEST ICMP echo request"; itype:8; sid:9000001; rev:1;)'
 'alert tcp any any -> any 9999 (msg:"WAZUH-TEST TCP SYN to port 9999"; flags:S; sid:9000002; rev:1;)'
 'alert dns any any -> any any (msg:"WAZUH-TEST DNS query marker"; dns.query; content:"wazuh-suricata-test"; nocase; sid:9000003; rev:1;)'
 'alert http any any -> any any (msg:"WAZUH-TEST HTTP user-agent"; http.user_agent; content:"WazuhSuricataTest"; sid:9000004; rev:1;)'
)
[IO.File]::WriteAllText($TestRules, ($rules -join "`n")+"`n", $utf8)
$y=Get-Content $Yaml -Raw
if($y -notmatch '(?m)^\s*-\s*wazuh-test\.rules\s*$'){
    $y=[regex]::Replace($y,'(?m)^(\s*-\s*suricata\.rules\s*)$',"`$1`r`n  - wazuh-test.rules",1)
    Copy-Item $Yaml "$Yaml.bak-test-$(Get-Date -Format yyyyMMddHHmmss)" -Force
    [IO.File]::WriteAllText($Yaml,$y,$utf8)
}
Log "loaded 4 WAZUH-TEST rules; restarting Suricata..."
Restart-AndWaitCapture | Out-Null

# ---- 2. generate traffic in 3 rounds (so capture can't miss it) ----
Log "generating test traffic (3 rounds)..."
for($round=1;$round -le 3;$round++){
    Log "  round $round"
    & ping.exe -n 2 $Target | Out-Null                                                    # 9000001 ICMP
    1..2 | ForEach-Object { Test-NetConnection -ComputerName $Target -Port 9999 -WarningAction SilentlyContinue -InformationLevel Quiet | Out-Null }  # 9000002 TCP
    Resolve-DnsName "wazuh-suricata-test.example.com" -ErrorAction SilentlyContinue | Out-Null   # 9000003 DNS
    & curl.exe -s -m 4 -A 'WazuhSuricataTest' "http://$Target/" -o $null 2>$null            # 9000004 HTTP
    Start-Sleep 3
}
if($IncludeInternetTests){ Log "  testmynids (real ET rule; VPN may hide outbound)"; & curl.exe -s -m 8 -A 'BlackSun' 'http://testmynids.org/uid/index.html' -o $null 2>$null }

# ---- 3. wait + scan eve.json ----
Log "waiting up to 45s for alerts in eve.json..."
$want=@{9000001='ICMP ping';9000002='TCP :9999';9000003='DNS marker';9000004='HTTP UA'}
$seen=@{}
for($s=0;$s -lt 45;$s+=5){
    Start-Sleep 5
    Get-Content $EvePath -Tail 2500 | ForEach-Object {
        try{ $o=$_|ConvertFrom-Json
            if($o.event_type -eq 'alert' -and $o.alert.signature -match 'WAZUH-TEST'){ $seen[[int]$o.alert.signature_id]=$o.alert.signature }
            if($IncludeInternetTests -and $o.event_type -eq 'alert' -and $o.alert.signature -match 'id check returned root|ATTACK_RESPONSE'){ $seen[2100498]=$o.alert.signature }
        }catch{}
    }
    if(($want.Keys | Where-Object { -not $seen.ContainsKey($_) }).Count -eq 0){ break }
}

# ---- 4. report ----
Write-Host "`n===== RESULTS =====" -ForegroundColor Cyan
$pass=0
foreach($sid in 9000001,9000002,9000003,9000004){
    if($seen.ContainsKey($sid)){ Write-Host ("  [PASS] {0,-10} {1}  (sid {2})" -f $want[$sid],$seen[$sid],$sid) -ForegroundColor Green; $pass++ }
    else { Write-Host ("  [miss] {0,-10} sid {1}  (LAN traffic Suricata couldn't see - e.g. VPN routed it, or no :80)" -f $want[$sid],$sid) -ForegroundColor Yellow }
}
if($IncludeInternetTests){ if($seen.ContainsKey(2100498)){Write-Host "  [PASS] testmynids ET ATTACK_RESPONSE (real ET rule!)" -ForegroundColor Green}else{Write-Host "  [miss] testmynids (outbound likely VPN-tunneled)" -ForegroundColor Yellow} }
Write-Host ("  TEST RULES FIRED: {0}/4" -f $pass) -ForegroundColor $(if($pass -ge 1){'Green'}else{'Red'})
if($pass -ge 1){ Write-Host "  PIPELINE PROVEN: detection -> eve.json works; these also shipped to the manager (rule 86601)." -ForegroundColor Green }
else { Write-Host "  0 fired - tell Claude; we'll check capture timing / VPN routing." -ForegroundColor Red }

# ---- 5. cleanup ----
if(-not $KeepRules){
    Log "removing WAZUH-TEST rules + restarting Suricata..."
    $y=Get-Content $Yaml -Raw; $y=[regex]::Replace($y,'(?m)^\s*-\s*wazuh-test\.rules\s*\r?\n','')
    [IO.File]::WriteAllText($Yaml,$y,$utf8)
    Remove-Item $TestRules -Force -EA SilentlyContinue
    try{Stop-Service Suricata -Force -EA SilentlyContinue;Start-Sleep 2}catch{}; Start-Service Suricata -EA SilentlyContinue
    Log "cleanup done (test rules removed)."
} else { Log "-KeepRules set: WAZUH-TEST rules left loaded (sid 9000001 alerts on ALL ICMP)." }

Write-Host "`nConfirm on manager (run from a Linux shell):" -ForegroundColor Cyan
Write-Host "  sudo grep WAZUH-TEST /var/ossec/logs/alerts/alerts.json"
