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
| [`suricata-install.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/suricata-install.ps1) | installer + configurator + verifier |
| [`Test-SuricataAlerts.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/Test-SuricataAlerts.ps1) | on-demand alert test (injects WAZUH-TEST rules, fires traffic, confirms) |
| [`uninstall.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/uninstall.ps1) | deep clean (service, MSI, configs, rules, eve.json, task, Defender/firewall rules) |
| [`agb-full-setup.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/agb-full-setup.ps1) | **one-line combined installer**: base Suricata install + AGB whitelist/blacklist auto-deploy |
| [`agb-white.rules`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/agb-white.rules) | Suricata `pass` rules (known-good domains/IPs) — **edit this on GitHub to change the whitelist** |
| [`agb-black.rules`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/agb-black.rules) | Suricata `alert` rules (known-bad C2 IPs/domains) — **edit this on GitHub to change the blacklist** |
| [`deploy-agb-rules.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/deploy-agb-rules.ps1) | pull-deploy logic: downloads the two rules above from GitHub, validates, restarts Suricata only if changed |
| [`install-agb-rules-task.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/install-agb-rules-task.ps1) | registers the daily 1:30 PM SYSTEM scheduled task that runs `deploy-agb-rules.ps1` |
| [`uninstall-agb-rules.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/uninstall-agb-rules.ps1) | removes ONLY the AGB rules auto-deploy (task, scripts, rule files); leaves base Suricata untouched |
| [`agb-full-uninstall.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/agb-full-uninstall.ps1) | **one-line combined uninstaller**: removes AGB auto-deploy + deep-cleans base Suricata |

> **Run everything from an Administrator PowerShell** (Win+X → *Terminal (Admin)*). All scripts declare `#Requires -RunAsAdministrator`.

---

## Quick start (single-line commands)

**Install (local IDS; ships to a manager the agent is already enrolled to):**
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/suricata-install.ps1';$f="$env:TEMP\suricata-install.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -SelfTest
```

**Install AND enroll the Wazuh agent to a manager:**
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/suricata-install.ps1';$f="$env:TEMP\suricata-install.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -WazuhManager <MANAGER_IP> -RegPassword 'YOUR_AUTHD_PASSWORD' -SelfTest
```

**Install fully unattended (no prompts):**
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/suricata-install.ps1';$f="$env:TEMP\suricata-install.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -NoPrompt -CaptureInterfaceName 'Wi-Fi' -HomeNet '[192.168.0.0/16]'
```

**Full setup — base Suricata install + AGB whitelist/blacklist auto-deploy, one command:**
```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-setup.ps1 -UseBasicParsing | iex
```
**Interactive by default** — prompts for capture interface and HOME_NET (press Enter on either to auto-pick/keep the stock default). Then downloads `agb-white.rules`/`agb-black.rules` and registers a daily **1:30 PM** scheduled task that keeps them in sync with GitHub. See [AGB whitelist/blacklist auto-deploy](#agb-whitelistblacklist-auto-deploy) below.

To pre-supply exact values non-interactively (piping via `| iex` can't pass parameters — download first):
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-setup.ps1';$f="$env:TEMP\agb-full-setup.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -CaptureInterfaceName 'Wi-Fi' -HomeNet '[192.168.0.0/16]'
```
Or skip both prompts and auto-pick everything: add `-NoPrompt` instead.

**Test alerts on demand:**
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/Test-SuricataAlerts.ps1';$f="$env:TEMP\Test-SuricataAlerts.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f
```

**Uninstall (deep clean; keeps Npcap + Wazuh agent):**
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/uninstall.ps1';$f="$env:TEMP\uninstall.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f
```

**Preview an uninstall (changes nothing):**
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/uninstall.ps1';$f="$env:TEMP\uninstall.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -WhatIfOnly
```

**Uninstall EVERYTHING (AGB rules auto-deploy + deep-clean base Suricata), one command:**
```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-uninstall.ps1 -UseBasicParsing | iex
```
Counterpart to `agb-full-setup.ps1`. Supports the same switches as `uninstall.ps1` (`-AlsoRemoveNpcap`, `-RemoveWazuhAgent`, `-WhatIfOnly`) — pass them after `| iex` doesn't work for piped scripts, so download it first if you need switches:
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-uninstall.ps1';$f="$env:TEMP\agb-full-uninstall.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -WhatIfOnly
```

**Remove ONLY the AGB rules auto-deploy (keep base Suricata install):**
```powershell
iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/uninstall-agb-rules.ps1 -UseBasicParsing | iex
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
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/Test-SuricataAlerts.ps1';$f="$env:TEMP\Test-SuricataAlerts.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f
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

## AGB whitelist/blacklist auto-deploy

A layered Suricata whitelist (`agb-white.rules`) + blacklist (`agb-black.rules`) pair, kept in sync across the fleet from **GitHub as the single source of truth**. Each agent independently pulls and deploys — no central push, no shared credentials, scales to any number of machines.

```
edit agb-white.rules / agb-black.rules on GitHub
        │
        ▼ (daily, 1:30 PM, per agent, SYSTEM-level scheduled task)
deploy-agb-rules.ps1 pulls raw files → validates (suricata -T) → restarts Suricata only if changed
```

**`agb-white.rules`** — Suricata `pass` rules, evaluated before `alert` rules, so matches are silently allowed. Currently allows the AGB dynamic-DNS hosts (`agb*.mywire.org`) so they never trip `ET DYN_DNS` noise (sid 2045987 / Wazuh rule 86601).

**`agb-black.rules`** — explicit `alert` rules for known-bad IPs/domains. Sensor-level defense-in-depth alongside manager-side Wazuh CDB IOC rules (`100311`/`100313`/`100974` for IPs, `100314` for domains) — even if `eve.json` shipping to the manager ever breaks, these still alert locally in `fast.log`/`eve.json`. sid range `1000100+` reserved for this file.

### Add an agent to the fleet
Run the combined one-liner (installs Suricata **and** sets up the auto-deploy):
```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-setup.ps1 -UseBasicParsing | iex
```
Or, if Suricata is already installed on that agent, just add the auto-deploy task:
```powershell
iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/install-agb-rules-task.ps1 -UseBasicParsing | iex
```

### Change the rules
Edit `agb-white.rules` / `agb-black.rules` directly on GitHub (web UI or a local clone + push). Every agent running the scheduled task picks up the change at its next 1:30 PM run — no redeploy step needed anywhere else.

### Check a single agent's deploy status
```powershell
Get-ScheduledTask -TaskName "AGB-Suricata-Rules-Deploy" | Select TaskName, State
Get-Content "C:\ProgramData\Suricata\rules\agb-deploy.log" -Tail 20
```

### Force an immediate deploy (don't wait for 1:30 PM)
```powershell
& "C:\ProgramData\Suricata\agb-scripts\deploy-agb-rules.ps1"
```

### Remove an agent from the fleet
```powershell
# AGB rules auto-deploy only, keep Suricata itself:
iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/uninstall-agb-rules.ps1 -UseBasicParsing | iex

# Everything (AGB auto-deploy + base Suricata deep-clean):
iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-uninstall.ps1 -UseBasicParsing | iex
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
