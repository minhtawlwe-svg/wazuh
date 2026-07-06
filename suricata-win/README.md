# suricata-win

Self-contained **Suricata IDS → Wazuh** deployment for Windows, plus an AGB whitelist/blacklist layer with auto-kill Active Response. Two entry points: `agb-full-setup.ps1` installs everything, `agb-full-uninstall.ps1` removes everything.

```
traffic → Suricata → eve.json → Wazuh agent → manager (rule 86601 "Suricata: Alert") → dashboard
                                                      │
                                       agb-black.rules hit / IOC match
                                                      ▼
                                     Active Response: kill process + block IP
```

No external installer dependency. Portable across any user account (machine-wide paths only).

---

## Repo contents

| File | What it does |
| --- | --- |
| [`agb-full-setup.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/agb-full-setup.ps1) | **the installer** — self-contained: Npcap, Suricata, ET Open ruleset, agb-white/agb-black rules, daily auto-deploy task, Active Response scripts, eve-log stats fix, all in one file |
| [`agb-full-uninstall.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/agb-full-uninstall.ps1) | **the uninstaller** — self-contained deep-clean of everything the installer put in place |
| [`agb-white.rules`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/agb-white.rules) | Suricata `pass` rules (known-good domains/IPs) — **edit this on GitHub to change the whitelist** |
| [`agb-black.rules`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/agb-black.rules) | Suricata `alert` rules (known-bad C2 IPs/domains) — **edit this on GitHub to change the blacklist** |
| [`deploy-agb-rules.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/deploy-agb-rules.ps1) | pull-deploy logic invoked by the daily scheduled task: downloads the two rules above from GitHub, validates, restarts Suricata only if changed — kept as its own file because the task calls it repeatedly, not a one-time install step |
| [`fix-eve-stats-overflow.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/fix-eve-stats-overflow.ps1) | standalone fix for agents installed **before** this bug was found: disables eve-log `stats` output, which silently blocks ALL Suricata data from ever reaching the manager (see Troubleshooting). Already baked into `agb-full-setup.ps1` for new installs — only needed as a patch for existing installs |
| [`Test-SuricataAlerts.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/Test-SuricataAlerts.ps1) | on-demand alert test (injects WAZUH-TEST rules, fires traffic, confirms) |
| [`wazuh-manager/`](https://github.com/minhtawlwe-svg/wazuh/tree/git-home/suricata-win/wazuh-manager) | **manager-side** files (see [Manager-side setup](#manager-side-setup) below) — deployed ONCE on the Wazuh manager, not per-agent |
| [`build-suricata-ips.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/build-suricata-ips.ps1) | **experimental, separate** — builds Suricata from source with real inline IPS/blocking support (WinDivert), which the official MSI above does not have. See [Suricata IPS mode (WinDivert)](#suricata-ips-mode-windivert) below |
| [`uninstall-all-suricata.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/uninstall-all-suricata.ps1) | removes **everything** — both the IDS install (by calling `agb-full-uninstall.ps1`) and the IPS build (deploy folder, build workspace, WinDivert driver, `SuricataIPS` service, and Wazuh wiring if present) |
| [`install-suricata-ips-service.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/install-suricata-ips-service.ps1) | **higher-risk** — registers the IPS build as a persistent Windows service (auto-starts on boot, runs continuously). `build-suricata-ips.ps1` does this by default at the end of its own run too; use this script to add it later to an already-built deployment. See [Running it continuously](#running-it-continuously) |

> **Run everything from an Administrator PowerShell** (Win+X → *Terminal (Admin)*). Both entry-point scripts declare `#Requires -RunAsAdministrator`.

---

## Quick start (single-line commands)

**Install everything** — Suricata + ET Open rules + agb-white/agb-black rules + daily auto-deploy + Active Response scripts:
```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-setup.ps1 -UseBasicParsing | iex
```
**Interactive by default** — prompts for capture interface and HOME_NET (press Enter on either to auto-pick/keep the stock default).

**Install AND enroll the Wazuh agent to a manager**, or pass other options non-interactively (piping via `| iex` can't pass parameters — download first):
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-setup.ps1';$f="$env:TEMP\agb-full-setup.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -WazuhManager <MANAGER_IP> -RegPassword 'YOUR_AUTHD_PASSWORD' -SelfTest
```

**Install fully unattended (no prompts):**
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-setup.ps1';$f="$env:TEMP\agb-full-setup.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -NoPrompt -CaptureInterfaceName 'Wi-Fi' -HomeNet '[192.168.0.0/16]'
```

**Test alerts on demand:**
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/Test-SuricataAlerts.ps1';$f="$env:TEMP\Test-SuricataAlerts.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f
```

**Uninstall everything** (deep clean; keeps Npcap + Wazuh agent):
```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-uninstall.ps1 -UseBasicParsing | iex
```

**Preview an uninstall (changes nothing), or pass other switches** (download first — piping can't pass parameters):
```powershell
$u='https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-uninstall.ps1';$f="$env:TEMP\agb-full-uninstall.ps1";[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr $u -OutFile $f -UseBasicParsing;powershell -ExecutionPolicy Bypass -File $f -WhatIfOnly
```

---

## Requirements

1. **Administrator PowerShell.**
2. **Wazuh agent installed** (`Get-Service WazuhSvc`). If not yet enrolled, the installer can enroll it with `-WazuhManager` / `-RegPassword`.
3. **Npcap** — installed automatically if missing, but the free build **cannot install silently**: a wizard appears → tick **"Install Npcap in WinPcap API-compatible Mode"** → Install → Finish.
4. **(Behind a VPN / slow OISF link)** pre-stage the MSI so the installer skips the download:
   download `Suricata-8.0.3-1-64bit.msi` from `https://www.openinfosecfoundation.org/download/windows/`, save it to `C:\ProgramData\Suricata\downloads\suricata.msi`, or pass `-SuricataMsiPath <path>`.

---

## What `agb-full-setup.ps1` does (step by step)

**Step 1 — base Suricata install:**
1. Data dirs + Defender exclusions under `C:\ProgramData\Suricata\` (`log` `rules` `state` `downloads`).
2. Npcap — skipped if present; otherwise interactive wizard.
3. Suricata MSI — uses a pre-staged `suricata.msi` if present (>5 MB); **auto-uninstalls any older Suricata first** (fixes MSI error 1638); silent `/qn` install.
4. Capture interface — auto-picks the fastest UP physical adapter (excludes virtual/VPN), or `-CaptureInterfaceName`.
5. ET Open ruleset — downloads the version-matched `emerging.rules.tar.gz`, merges all categories into a single `suricata.rules` (~50k signatures). `suricata-update` is broken on Windows, so this is direct.
6. Downloads `agb-white.rules` / `agb-black.rules` straight from GitHub into the rules dir.
7. `suricata.yaml` — sets `default-log-dir` / `default-rule-path`, optional `HOME_NET`, `rule-files: [suricata.rules, agb-white.rules, agb-black.rules]`, and **disables eve-log `stats` output** (see Troubleshooting — this is critical, not optional).
8. Service — installed with a quoted ImagePath, Automatic start.
9. Wazuh enrollment *(optional)* — sets `<address>` and runs `agent-auth`; skipped automatically if already enrolled.
10. eve.json binding — writes one clean `<localfile log_format="json">` block into `ossec.conf` and restarts the agent.

**Step 2 — AGB daily rule auto-deploy:**
11. Downloads `deploy-agb-rules.ps1` into `C:\ProgramData\Suricata\agb-scripts\`.
12. Registers scheduled task `AGB-Suricata-Rules-Deploy` (SYSTEM, daily **1:30 PM**) that runs it — pulls the latest `agb-white.rules`/`agb-black.rules` from GitHub and redeploys only if changed.
13. Registers Suricata's own ET Open refresh + log-rotation task (SYSTEM, daily **13:00**).

**Step 3 — Active Response:**
14. Downloads `agb-kill-block.ps1`/`.cmd` into the Wazuh agent's `active-response\bin\` — this is what actually kills a process/blocks an IP when the manager tells it to (see [AGB whitelist/blacklist auto-deploy](#agb-whitelistblacklist-auto-deploy)).

**Step 4 — Verify:** prints rule count, service states, manager link, logcollector status; `-SelfTest` waits for a live alert.

---

## Parameters (`agb-full-setup.ps1`)

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
| `-SkipNpcap` / `-SkipScheduledTask` | off | skip those steps (SkipScheduledTask skips BOTH scheduled tasks) |
| `-SkipWazuhEnroll` / `-ForceEnroll` | off | never / always enroll |
| `-StripFileMagic` | off | drop the unsupported `file.magic` rules |

## Parameters (`agb-full-uninstall.ps1`)

| Parameter | Meaning |
| --- | --- |
| `-AlsoRemoveNpcap` | also uninstall Npcap (interactive) |
| `-RemoveWazuhAgent` | also uninstall the Wazuh agent (rare) |
| `-WhatIfOnly` | list what WOULD be removed, change nothing |

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

Two scheduled tasks are registered automatically (skip both with `-SkipScheduledTask`):
```powershell
Get-ScheduledTask -TaskName 'Suricata Daily Update And Log Rotation'    # ET Open refresh + eve.json rotation, 13:00
Get-ScheduledTask -TaskName 'AGB-Suricata-Rules-Deploy'                 # agb-white/agb-black pull-deploy, 1:30 PM
Start-ScheduledTask -TaskName 'AGB-Suricata-Rules-Deploy'               # run either one now
```

---

## AGB whitelist/blacklist auto-deploy

A layered Suricata whitelist (`agb-white.rules`) + blacklist (`agb-black.rules`) pair, kept in sync across the fleet from **GitHub as the single source of truth**. Each agent independently pulls and deploys — no central push, no shared credentials, scales to any number of machines. A confirmed blacklist hit triggers **auto-kill** (process kill + firewall block) via a Wazuh Active Response — see [Manager-side setup](#manager-side-setup) for that half.

```
edit agb-white.rules / agb-black.rules on GitHub
        │
        ▼ (daily, 1:30 PM, per agent, SYSTEM-level scheduled task)
deploy-agb-rules.ps1 pulls raw files → validates (suricata -T) → restarts Suricata only if changed
        │
        ▼ (agb-black.rules hit ships to the manager)
Wazuh manager rule matches (100316 for agb-black.rules, or 100311/100313/100974/100314
for the CDB blocklist) → tagged group "c2_autokill"
        │
        ▼
Active Response fires on the agent → agb-kill-block.ps1 kills the process (if a PID is
available, e.g. Sysmon-sourced rule 100974) + blocks the IP via netsh firewall
```

**IMPORTANT — what alerts vs. what auto-kills:**
| | Behavior |
| --- | --- |
| **Whitelist match** (`agb-white.rules`) | Silent, no alert |
| **Confirmed blacklist match** (`agb-black.rules` signature -> rule `100316`, or manager `blocked_ips` CDB -> Sysmon-side rule `100974`) | **Auto-kill**: process killed (if PID known) + IP blocked via firewall |
| **Heuristic/behavioral match** (encoded PowerShell, interpreter→external-IP, reverse-shell command patterns) | **Alert only** — for human review; promote the IP/domain to the blacklist once confirmed, it will NOT auto-kill on its own |
| **No match on any list or pattern** | Silent |

**`agb-white.rules`** — Suricata `pass` rules, evaluated before `alert` rules, so matches are silently allowed. Currently allows the AGB dynamic-DNS hosts (`agb*.mywire.org`) so they never trip `ET DYN_DNS` noise (sid 2045987 / Wazuh rule 86601).

**`agb-black.rules`** — explicit `alert` rules for known-bad IPs/domains. Sensor-level defense-in-depth alongside manager-side Wazuh CDB IOC rules (`100311`/`100313`/`100974` for IPs, `100314` for domains) — even if `eve.json` shipping to the manager ever breaks, these still alert locally in `fast.log`/`eve.json`. sid range `1000100+` reserved for this file. **Note: Suricata itself only detects — it cannot kill/block. That enforcement happens on the manager side, see below.**

### Add an agent to the fleet
Run the installer — it covers Suricata, the auto-deploy task, and the Active Response scripts in one pass:
```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-setup.ps1 -UseBasicParsing | iex
```
An agent running this is only **half** the setup — the manager also needs the rules + Active Response binding configured once (see [Manager-side setup](#manager-side-setup)).

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

### Check the Active Response log (did it kill/block anything?)
```powershell
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\agb-kill-block.log" -Tail 20
Get-NetFirewallRule -DisplayName "AGB-BLOCK-*" | Select DisplayName, Enabled, Action
```

### Remove an agent from the fleet
```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/agb-full-uninstall.ps1 -UseBasicParsing | iex
```
This does NOT remove the manager-side rules/AR binding — that's a separate, one-time manager change (see below).

---

## Manager-side setup

The agent installer above only covers the Suricata sensor. The Wazuh **manager** needs a one-time setup to (a) actually watch for blacklist hits shipped in from every agent, (b) correlate them, and (c) trigger the Active Response that does the kill+block. Files live in [`wazuh-manager/`](https://github.com/minhtawlwe-svg/wazuh/tree/git-home/suricata-win/wazuh-manager):

**⚠️ Also check `analysisd.decoder_order_size` in `/var/ossec/etc/internal_options.conf` on the manager.** Default is `256` on some Wazuh installs — too low for busy agents. Suricata's rich `alert`/`tls` events (ET metadata arrays, cert chains) can exceed 256 flattened fields, causing `wazuh-analysisd: ERROR: Too many fields for JSON decoder.` and silently dropping the event with zero indication anywhere on the agent side. Raise it to the max allowed (`1024`) and restart `wazuh-manager`:
```bash
sudo sed -i 's/analysisd.decoder_order_size=256/analysisd.decoder_order_size=1024/' /var/ossec/etc/internal_options.conf
sudo /var/ossec/bin/wazuh-analysisd -t && sudo systemctl restart wazuh-manager
```
This is a manager-wide setting — check it once, benefits every connected agent.

| File | Deploys to (on the manager) |
| --- | --- |
| `local_rules_c2.xml` | `/var/ossec/etc/rules/local_rules_c2.xml` |
| `blocked_ips`, `interpreter_dest_allowlist` | `/var/ossec/etc/lists/` (each) — the only 2 CDB lists still used (domain-based IOC matching is inline pcre2 in rule `100314`, no CDB list needed) |
| `active-response/agb-kill-block.ps1` + `.cmd` | copied by each **agent's** `agb-full-setup.ps1` into its own `active-response\bin\` — NOT deployed on the manager itself |

**One-time manager setup** (Docker example — adjust container name for your setup):
```powershell
docker cp local_rules_c2.xml            <manager-container>:/var/ossec/etc/rules/local_rules_c2.xml
docker cp blocked_ips                    <manager-container>:/var/ossec/etc/lists/blocked_ips
docker cp interpreter_dest_allowlist      <manager-container>:/var/ossec/etc/lists/interpreter_dest_allowlist
docker exec <manager-container> chown wazuh:wazuh /var/ossec/etc/rules/local_rules_c2.xml /var/ossec/etc/lists/blocked_ips /var/ossec/etc/lists/interpreter_dest_allowlist
docker exec <manager-container> /var/ossec/bin/wazuh-analysisd -t
```
If that last command shows `EXIT:0` with no `ERROR` lines, restart the manager to load everything. Both CDB lists must also be registered in `ossec.conf`'s `<ruleset>` block (one `<list>etc/lists/...</list>` line each) if this is a fresh manager that's never had them before.

**Critical:** never declare `<decoded_as>json</decoded_as>` as a rule's own top-level condition in `local_rules_c2.xml` — Wazuh's stock rule `86600` already claims that decoder as its own top-level root and loads first on most managers, silently preventing a second competing top-level rule from ever being evaluated. Chain custom rules under `<if_sid>86600</if_sid>` (any Suricata event type) or `<if_sid>86601</if_sid>` (alert-type only) instead. This broke every IP/domain-matching rule in this file for a full day before being found — see the `project_intern_vm_suricata_agent040_mystery` note if working from a memory-backed session.

**Register the Active Response command + binding** in `ossec.conf` (once):
```xml
<command>
  <name>agb-kill-block</name>
  <executable>agb-kill-block.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>agb-kill-block</command>
  <location>local</location>
  <rules_group>c2_autokill</rules_group>
</active-response>
```
`location: local` means the AR runs on whichever agent generated the triggering alert — not centrally on the manager. `rules_group: c2_autokill` binds it to exactly the confirmed-blacklist rules (`100316` — matches `agb-black.rules`' own signature text, and `100974` — Sysmon-side `blocked_ips` match) — heuristic rules are deliberately never in this group, so they can never auto-kill.

**⚠️ Test before trusting it.** Run a beacon test against an IP already in `agb-black.rules` (e.g. a lab/test C2), then check the agent's `agb-kill-block.log` and `Get-NetFirewallRule -DisplayName "AGB-BLOCK-*"` to confirm it actually killed the process and blocked the IP before relying on this in a real incident.

---

## Suricata IPS mode (WinDivert)

**Everything above is IDS-only.** The official Suricata MSI installer only supports passive capture (Npcap) — it can alert, but cannot itself block or drop a packet. All blocking in this repo happens indirectly: Suricata alerts → ships to Wazuh → Active Response calls `netsh` a few seconds later. That's good enough for C2 beaconing (which repeats), but the very first packet always gets through.

Suricata has a real inline/IPS capture mode using a driver called **WinDivert**, which can drop a malicious packet instantly with zero dependency on Wazuh. This capability does **not** exist in the prebuilt MSI — it only exists if Suricata is compiled from source with WinDivert support explicitly enabled.

```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/build-suricata-ips.ps1 -UseBasicParsing | iex
```

**This is a separate, experimental build — it does not touch or replace the IDS-mode install above.** It's fully self-contained from scratch (installs Npcap too, if not already present) and produces a **ready-to-test, live-fire-verified** deployment in `C:\SuricataIPS\`: the binary, all runtime DLLs, a configured `suricata.yaml`, rules, and (if a Wazuh agent is present) automatic wiring into it. **By default it also registers and starts an always-on `SuricataIPS` Windows service** (filter: `outbound`) at the end of the same run — see the warning and confirmation step below; pass `-SkipService` to stop at a manual/foreground-test build instead. **Interactive by default** — prompts for capture interface and HOME_NET, same UX as `agb-full-setup.ps1` (pass `-NoPrompt` to auto-pick everything and skip the service confirmation too). Takes 20-60+ minutes on a clean machine (compiling ~250 Rust crates is the biggest cost), much faster on a re-run since it skips anything already in place; needs ~5 GB free disk.

**What it automates** (every one of these was a real error hit and fixed during development — see the script's own inline comments for the full "why"):
| Step | Gotcha it avoids |
| --- | --- |
| Windows Defender exclusions for `C:\msys64` and the deploy folder | Defender quarantines freshly-built binaries and the WinDivert download within seconds — a known AV false-positive pattern for build tools. On machines with **Tamper Protection ON**, Defender silently ignores scripted exclusion changes entirely — the script detects this and hands the two folders to you via the Windows Security GUI instead, which Tamper Protection does honor |
| MSYS2 + UCRT64 toolchain install | Retries automatically — MSYS2 mirrors are frequently unstable ("Operation too slow", DNS failures); pacman resumes from cache on retry |
| Every bash invocation | Wrapped so a native command's harmless *stderr* text doesn't get turned into a fatal PowerShell error, and `MSYSTEM=UCRT64` is set before anything runs so `cargo`/`rustc` actually resolve on PATH — both real bugs that looked exactly like AV interference until traced to their actual cause |
| Npcap driver | Installed from scratch if missing (interactive wizard — Npcap's free build has no silent-install mode) |
| **WinDivert 1.4.3 specifically, not the latest release (2.2.2)** | Suricata 8.0.3's C code is written against the old 1.x API — the current API is incompatible and fails with dozens of compile errors |
| **A genuine upstream Suricata bug: `--windivert` never marks IPS mode** | Confirmed by reading Suricata's own source — every other inline runmode (NFQ, IPFW, af-packet, netmap, dpdk) calls `EngineModeSetIPS()`, but neither `--windivert` nor `--windivert-forward` do. Without this, `eve.json`'s `alert.action` field always says `"allowed"` even for packets that were genuinely dropped. The script patches `suricata.c` to add the missing call, matching every other runmode |
| Locating the real binary | The top-level `src/suricata.exe` after a successful build is a libtool wrapper stub (~36 KB, won't run) — the real 100+ MB binary is hidden in `src/.libs/suricata.exe` |
| Assembling runtime DLLs + the WinDivert kernel driver | Dynamically-linked build needs `api-ms-win-crt-*.dll` plus several `ucrt64/bin` libraries; `WinDivert.dll` alone isn't enough either — `WinDivertOpen()` also needs `WinDivert64.sys` sitting next to it, or the engine fails to start entirely |
| Redeploying after a prior live test | The WinDivert kernel driver stays loaded (and locks its own `.sys` file) after `suricata.exe --windivert` exits — the script stops it first so a rebuild doesn't fail with "file in use" |
| `suricata.yaml` + rules + classification/reference configs | Generates a working config pointing at files that actually exist in the deploy folder, not the official MSI's install path |
| Daily rule refresh | Two scheduled tasks keep both rule files current, same timing as the IDS deployment |
| **Wazuh agent wiring** | If a Wazuh agent is installed (`C:\Program Files (x86)\ossec-agent\`), adds a `<localfile>` entry for this build's `eve.json` (separate from any IDS-mode Suricata's own entry) and restarts the agent, so IPS-mode drops reach your manager — hitting the same rules (`86601` → `100316` → the `c2_autokill` AR group) as the IDS deployment, since it's the same `agb-black.rules` signature text |

**Rules are deliberately split — only your curated blacklist actually blocks:**
| File | Source | Action | Effect |
| --- | --- | --- | --- |
| `rules\agb-white.rules` | Your `agb-white.rules` (same whitelist the IDS deployment uses) | `pass` (unmodified) | Suppresses known-good noise (e.g. `*.agb.mywire.org` DYN_DNS alerts) before it ever reaches the ET ruleset |
| `rules\suricata.rules` | Full ET Open ruleset (~50,000 signatures) | `alert` (unmodified) | Visibility only — logs, never blocks. Most ET signatures are tuned for alerting, not blocking; converting the entire IDS ruleset to blocking would be genuinely risky (noisy/informational signatures false-positiving on legitimate traffic) |
| `rules\agb-black-drop.rules` | Your `agb-black.rules` (same blacklist the IDS deployment auto-kills on) | `drop` (converted from `alert`) | **Actually blocks** — the same small, deliberate, already-trusted IOC set, now enforced inline instead of via the Wazuh Active Response round-trip |

All three refresh daily via scheduled tasks (`AGB-Suricata-IPS-ET-Refresh` at 13:00, `AGB-Suricata-IPS-Rules-Deploy` at 1:30 PM — same times as the IDS deployment's equivalents). If the `SuricataIPS` service is running, both tasks also restart it after refreshing — otherwise a continuously-running instance would keep enforcing stale rules indefinitely, silently defeating the point of a daily refresh.

**Live-fire verified** (2026-07-05): ran `.\suricata.exe -c suricata.yaml --windivert "ip.DstAddr == <test IP>"`, then tried to reach that IP from another window — connection genuinely failed, `fast.log` showed `[Drop]`, and `eve.json` correctly reported `"action":"blocked"`.

**By default, the script also registers and starts the `SuricataIPS` service at the end of the build** (see [Running it continuously](#running-it-continuously) below) — it will print a loud warning and require a typed `YES` before doing so (or skip it automatically if you pass `-NoPrompt`, treating that as pre-confirmed). Pass `-SkipService` if you'd rather stop at a manual, supervised test instead:
```powershell
cd C:\SuricataIPS
.\suricata.exe -c suricata.yaml --windivert "outbound"
```
This is safe to run broad because only `agb-black-drop.rules`' small, curated signature set can ever trigger an actual drop — the full ET Open ruleset stays alert-only regardless of filter scope. For an even narrower starting point (the one specifically live-fire verified), scope to a single test IP instead: `--windivert "ip.DstAddr == 152.42.235.124"`.

**Test on a disposable machine first**, not a machine you depend on for daily use — this applies whether you run it manually or as the default service. Inline mode sits directly in the traffic path — a crash there can affect connectivity through that interface, a materially different risk profile than IDS-only.

Other flags: `-SkipRulesSetup` if you only want the bare binary (e.g. to write your own curated rule set instead), `-SkipScheduledTask` to skip just the daily refresh tasks, `-SkipWazuhWiring` to keep this build fully standalone even if a Wazuh agent is present, `-WinDivertFilter` to change what the service watches (default `outbound`).

A full narrative write-up of the entire build (including every error exactly as it happened) exists as a Word document generated during development — ask for `Suricata-IPS-Mode-Build-Guide.docx` if you need the long-form version with screenshots-equivalent detail. Note it was written before several of the fixes above landed, so the script's own inline comments are the more current source of truth.

### Running it continuously

**This is a meaningfully bigger commitment than a manual test** — no window to watch, no easy stop button if a rule misfires or it crashes; a bad rule or a crash would now affect this machine's connectivity unattended until you notice. Only do this on a machine you've already tested thoroughly, ideally a disposable one.

That said, **it's the default** as of this build — `build-suricata-ips.ps1` registers and starts it automatically at the end of a normal run (after a typed `YES` confirmation, or automatically under `-NoPrompt`). Pass `-SkipService` to opt out and stop at a manual/foreground test instead. To add it later to an already-built deployment without rerunning the whole build:
```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/install-suricata-ips-service.ps1 -UseBasicParsing | iex
```
Both paths prompt for an explicit `YES` confirmation (repeating the warning above) before doing anything, unless `-NoPrompt`/`-Force` is passed. Registers a Windows service named **`SuricataIPS`** — deliberately *not* the generic `Suricata` name Suricata's own `--service-install` would use internally (that name is a hardcoded compile-time constant, not configurable, and could collide with a regular IDS-mode Suricata service if one's ever added on the same machine). Auto-starts on boot, restarts itself on crash (via `sc.exe failure`), uses the `outbound` filter by default (override with `-WinDivertFilter`).

```powershell
Get-Service SuricataIPS      # check status
Stop-Service SuricataIPS     # stop without uninstalling
```
To remove it: `.\install-suricata-ips-service.ps1 -Remove` (or run `uninstall-all-suricata.ps1`, which also cleans this up).

### Removing the IPS build (and/or everything else)
```powershell
[Net.ServicePointManager]::SecurityProtocol='Tls12';iwr https://raw.githubusercontent.com/minhtawlwe-svg/wazuh/git-home/suricata-win/uninstall-all-suricata.ps1 -UseBasicParsing | iex
```
Removes the IPS deploy folder (`C:\SuricataIPS\`), the build workspace (source tree, Rust cache, downloaded SDKs), the `SuricataIPS` service if installed, the Wazuh `ossec.conf` wiring if present, and the WinDivert kernel driver if it was ever registered — **and** runs `agb-full-uninstall.ps1` for the IDS-mode install, so this one command tears down everything. MSYS2 itself is kept by default (pass `-AlsoRemoveMsys2` to remove the whole toolchain, not just this project's use of it) since it's a general-purpose dev environment, not Suricata-specific.

---

## Troubleshooting

| Symptom | Cause | Handling |
| --- | --- | --- |
| `no rules were loaded` | `rule-files` named non-existent files | installer writes `rule-files: [suricata.rules, agb-white.rules, agb-black.rules]` |
| MSI exit **1638** | another Suricata already installed | installer auto-uninstalls it first |
| MSI download stalls (VPN) | OISF unreachable over tunnel | pre-stage MSI / `-SuricataMsiPath` |
| 9 rules failed, `file.magic` | no libmagic on Windows | harmless; `-StripFileMagic` to silence |
| 0 alerts on manager, eve.json OK | missing eve.json `<localfile>` | installer adds it; check `logcollector: tailing eve.json` |
| self-test 0/4 | traffic fired before engine loaded rules | test waits for `Engine started` first |
| `manager link: none` | agent reconnecting after restart | wait ~30 s and re-check |
| `WazuhSvc cannot be stopped` | service stop race | installer force-stops/kills + restarts |
| Npcap wizard pops up | free Npcap has no silent mode | tick *WinPcap API-compatible Mode*, finish |
| `Log file '...eve.json' is duplicated`, Suricata data silently stops shipping to the manager (even though the agent shows Active and eve.json is growing locally) | eve.json `<localfile>` defined BOTH in this agent's local `ossec.conf` AND in a manager-side GROUP's shared `agent.conf` | check group membership on the manager: `agent_groups -s -i <id>`; if the agent is in a group that also defines eve.json, remove the LOCAL `<localfile>` block (`agb-full-uninstall.ps1`'s step 7, or manually) and keep only the group-managed one - having it in both places is unpredictable, not just noisy |
| **ZERO Suricata alerts EVER reach the manager, for ANY agent** — agent shows Active, eve.json grows fine locally, agent log shows `Analyzing file: eve.json` with no errors, no duplicate warning either | Manager's `ossec.log` shows `wazuh-analysisd: ERROR: Too many fields for JSON decoder.` (check with `sudo grep -i "too many fields" /var/ossec/logs/ossec.log`) — Suricata's periodic `stats` eve.json record has hundreds of nested numeric fields (`decoder.*`, `tcp.*`, `app_layer.*`, `flow.*`); once flattened by Wazuh's generic JSON decoder it exceeds analysisd's hard field-count limit and the event is silently dropped ON THE MANAGER with zero indication on the agent side | already fixed in `agb-full-setup.ps1` for new installs. For an agent installed before this fix, run [`fix-eve-stats-overflow.ps1`](https://github.com/minhtawlwe-svg/wazuh/blob/git-home/suricata-win/fix-eve-stats-overflow.ps1) (elevated) to disable eve-log `stats` output and restart Suricata; `alert`/`flow`/`dns`/`http` events have far fewer fields and decode fine. This was THE root cause of a full day of debugging that looked like a shipping/duplicate-config/network problem on 2026-07-03 |

---

## Paths

| What | Where |
| --- | --- |
| Binaries + `suricata.yaml` | `C:\Program Files\Suricata\` |
| eve.json | `C:\ProgramData\Suricata\log\eve.json` |
| merged + agb rules | `C:\ProgramData\Suricata\rules\` (`suricata.rules`, `agb-white.rules`, `agb-black.rules`) |
| agb-scripts | `C:\ProgramData\Suricata\agb-scripts\deploy-agb-rules.ps1` |
| Suricata maintenance script | `C:\ProgramData\Suricata\Suricata-Maintenance.ps1` |
| Wazuh agent config | `C:\Program Files (x86)\ossec-agent\ossec.conf` |
| Active Response scripts | `C:\Program Files (x86)\ossec-agent\active-response\bin\agb-kill-block.ps1`/`.cmd` |
| Active Response log | `C:\Program Files (x86)\ossec-agent\active-response\agb-kill-block.log` |
| Manager alerts | `/var/ossec/logs/alerts/alerts.json` (rule `86601` base, `100311`-`100990` custom) |
