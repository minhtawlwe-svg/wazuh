# suricata-win

Self-contained **Suricata IDS → Wazuh** deployment for Windows. One PowerShell script installs Npcap, Suricata (8.x), the ET Open ruleset, the Windows service, the Wazuh agent binding, and a daily maintenance task — then verifies the whole pipeline.

```
traffic → Suricata → eve.json → Wazuh agent → manager (rule 86601 "Suricata: Alert") → dashboard
```

No external installer dependency. Portable across any user account (machine-wide paths only).

---

## Repo contents

| File | What it does |
| --- | --- |
| [`suricata-install.ps1`](https://github.com/yekyawhan/wazuh/blob/git-home/suricata-win/suricata-install.ps1) | installer + configurator + verifier |
| [`Test-SuricataAlerts.ps1`](https://github.com/yekyawhan/wazuh/blob/git-home/suricata-win/Test-SuricataAlerts.ps1) | on-demand alert test (injects WAZUH-TEST rules, fires traffic, confirms) |
| [`uninstall.ps1`](https://github.com/yekyawhan/wazuh/blob/git-home/suricata-win/uninstall.ps1) | deep clean (service, MSI, configs, rules, eve.json, task, Defender/firewall rules) |

> **Run everything from an Administrator PowerShell** (Win+X → *Terminal (Admin)*). All scripts declare `#Requires -RunAsAdministrator`.

---

## Quick start (single-line commands)

**Install (local IDS; ships to a manager the agent is already enrolled to):**
```powershell
$u='https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-win/suricata-install.ps1';$f="$env:TEMP\suricata-install.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -SelfTest
```

**Install AND enroll the Wazuh agent to a manager:**
```powershell
$u='https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-win/suricata-install.ps1';$f="$env:TEMP\suricata-install.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -WazuhManager <MANAGER_IP> -RegPassword 'YOUR_AUTHD_PASSWORD' -SelfTest
```

**Install fully unattended (no prompts):**
```powershell
$u='https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-win/suricata-install.ps1';$f="$env:TEMP\suricata-install.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -NoPrompt -CaptureInterfaceName 'Wi-Fi' -HomeNet '[192.168.0.0/16]'
```

**Test alerts on demand:**
```powershell
$u='https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-win/Test-SuricataAlerts.ps1';$f="$env:TEMP\Test-SuricataAlerts.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f
```

**Uninstall (deep clean; keeps Npcap + Wazuh agent):**
```powershell
$u='https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-win/uninstall.ps1';$f="$env:TEMP\uninstall.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f
```

**Preview an uninstall (changes nothing):**
```powershell
$u='https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-win/uninstall.ps1';$f="$env:TEMP\uninstall.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -WhatIfOnly
```

---

## Requirements

1. **Administrator PowerShell.**
2. **Wazuh agent installed** (`Get-Service WazuhSvc`). If not yet enrolled, the installer can enroll it with `-WazuhManager` / `-RegPassword`.
3. **Npcap** — installed automatically if missing, but the free build **cannot install silently**: a wizard appears → tick **"Install Npcap in WinPcap API-compatible Mode"** → Install → Finish.
4. **(Behind a VPN / slow OISF link)** pre-stage the MSI so the installer skips the download:
   download `Suricata-8.0.3-1-64bit.msi` from `https://www.openinfosecfoundation.org/download/windows/`, save it to `C:\ProgramData\Suricata\downloads\suricata.msi`, or pass `-SuricataMsiPath <path>`.

---

## What the installer does (step by step)

1. **Data dirs + Defender exclusions** under `C:\ProgramData\Suricata\` (`log` `rules` `state` `downloads`).
2. **Npcap** — skipped if present; otherwise interactive wizard.
3. **Suricata MSI** — uses a pre-staged `suricata.msi` if present (>5 MB); **auto-uninstalls any older Suricata first** (fixes MSI error 1638); silent `/qn` install; detects the installed version.
4. **Capture interface** — auto-picks the fastest UP physical adapter (excludes virtual/VPN), or `-CaptureInterfaceName`.
5. **ET Open ruleset** — downloads the version-matched `emerging.rules.tar.gz` (with `suricata-<major.minor>` fallbacks), merges all categories into a single `suricata.rules` (~50k signatures). `suricata-update` is broken on Windows, so this is direct.
6. **`suricata.yaml`** — sets single-quoted `default-log-dir` / `default-rule-path`, optional `HOME_NET`, and **`rule-files: [suricata.rules]`** (the correct single merged file). Validated with a properly **quoted** `-T` test.
7. **Service** — installed with a **quoted** ImagePath (`"suricata.exe" -c "suricata.yaml" -i "\Device\NPF_{...}"`), Automatic start.
8. **Wazuh enrollment** *(optional)* — sets `<address>` and runs `agent-auth`; **skipped automatically if already enrolled** to that manager (`-ForceEnroll` to override).
9. **eve.json binding** — writes one clean `<localfile log_format="json">` block into `ossec.conf` and restarts the agent (robust restart handles the "WazuhSvc cannot be stopped" race).
10. **Daily maintenance** — scheduled task `Suricata Daily Update And Log Rotation` (SYSTEM, **13:00**): refresh ET Open + restart Suricata, and rotate `eve.json` past **2 GB** (keeps 3 copies).
11. **Verify** — prints rule count, service states, manager link, logcollector status; `-SelfTest` waits for a live alert.

---

## Parameters

| Parameter | Default | Meaning |
| --- | --- | --- |
| `-WazuhManager <ip>` | *(none)* | enroll the agent to this manager |
| `-RegPassword <pw>` | *(none)* | authd registration password |
| `-AgentName <name>` | `$env:COMPUTERNAME` | agent name to enroll as |
| `-SuricataMsiPath <file>` | *(auto)* | use a pre-staged MSI (skip download) |
| `-SuricataMsiUrl <url>` | 8.0.3 MSI | override the MSI to install |
| `-CaptureInterfaceName <name>` | *(auto)* | pin the capture NIC |
| `-HomeNet '[x.x.x.x/yy]'` | stock RFC1918 | set HOME_NET |
| `-SelfTest` | off | wait for a live alert after install |
| `-NoPrompt` | off | don't ask for interface / HOME_NET |
| `-SkipNpcap` / `-SkipScheduledTask` | off | skip those steps |
| `-SkipWazuhEnroll` / `-ForceEnroll` | off | never / always enroll |
| `-StripFileMagic` | off | drop the unsupported `file.magic` rules |

---

## Verify

The installer prints a `VERIFY` block. Healthy:
```
rules        : 50305 rules successfully loaded, 9 rules failed   <- 9 = file.magic (no libmagic on Windows), expected
Suricata svc : Running
Wazuh agent  : Running
manager link : Established -> <manager>:1514
logcollector : tailing eve.json
```
`manager link: none` right after install is usually timing — re-check:
```powershell
Get-NetTCPConnection -RemotePort 1514 -State Established
```

On the **manager** (Linux shell):
```bash
sudo /var/ossec/bin/agent_control -lc && sudo grep -c "Suricata: Alert" /var/ossec/logs/alerts/alerts.json
```

---

## Testing

`Test-SuricataAlerts.ps1` injects four labeled **WAZUH-TEST** rules (sid 9000001-9000004), **waits for the engine to start capturing** (rule loading takes ~15-25 s), generates matching LAN traffic in 3 rounds, confirms each in `eve.json`, then removes the test rules. Each hit also reaches the manager as rule 86601.

Run it (single line):
```powershell
$u='https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-win/Test-SuricataAlerts.ps1';$f="$env:TEMP\Test-SuricataAlerts.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f
```
Confirm on the manager: `sudo grep WAZUH-TEST /var/ossec/logs/alerts/alerts.json`

Options: `-IncludeInternetTests` (real ET rule via testmynids — may be hidden by a VPN), `-Target <ip>`, `-KeepRules`.

---

## Maintenance

Registered automatically (skip with `-SkipScheduledTask`):
```powershell
Get-ScheduledTask -TaskName 'Suricata Daily Update And Log Rotation'    # check
Start-ScheduledTask -TaskName 'Suricata Daily Update And Log Rotation'  # run now
```

---

## Troubleshooting

| Symptom | Cause | Handling |
| --- | --- | --- |
| `no rules were loaded` | `rule-files` named non-existent files | installer writes `rule-files: [suricata.rules]` |
| MSI exit **1638** | another Suricata already installed | installer auto-uninstalls it first |
| MSI download stalls (VPN) | OISF unreachable over tunnel | pre-stage MSI / `-SuricataMsiPath` |
| 9 rules failed, `file.magic` | no libmagic on Windows | harmless; `-StripFileMagic` to silence |
| 0 alerts on manager, eve.json OK | missing eve.json `<localfile>` | installer adds it; check `logcollector: tailing eve.json` |
| self-test 0/4 | traffic fired before engine loaded rules | test waits for `Engine started` first |
| `manager link: none` | agent reconnecting after restart | wait ~30 s and re-check |
| `WazuhSvc cannot be stopped` | service stop race | installer force-stops/kills + restarts |
| Npcap wizard pops up | free Npcap has no silent mode | tick *WinPcap API-compatible Mode*, finish |

---

## Paths

| What | Where |
| --- | --- |
| Binaries + `suricata.yaml` | `C:\Program Files\Suricata\` |
| eve.json | `C:\ProgramData\Suricata\log\eve.json` |
| merged rules | `C:\ProgramData\Suricata\rules\suricata.rules` |
| maintenance script | `C:\ProgramData\Suricata\Suricata-Maintenance.ps1` |
| Wazuh agent config | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| Manager alerts | `/var/ossec/logs/alerts/alerts.json` (rule `86601`) |
