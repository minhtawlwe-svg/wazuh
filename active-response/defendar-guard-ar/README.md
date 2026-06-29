# Wazuh Active Response — Auto Re-Enable Windows Defender

**Purpose:** When Windows Defender real-time protection is turned OFF on an agent, Wazuh rule **100620** fires and an Active Response (AR) automatically turns it back ON, then logs the event.

**Author:** [redacted] · **Date:** 2026-06-26

---

## Quick Reference (TL;DR)

**On agent (elevated PowerShell, run each line):**
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
irm https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar/install.ps1 -OutFile $env:TEMP\install.ps1
Unblock-File $env:TEMP\install.ps1
& "$env:TEMP\install.ps1"
```

**On manager:**
```xml
<!-- inside <ossec_config> -->
<command>
  <name>reenable-defender</name>
  <executable>reenable-defender.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>reenable-defender</command>
  <location>local</location>
  <rules_id>100620</rules_id>
</active-response>
```

**Validate + restart:**
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```

```powershell
Restart-Service WazuhSvc   # on agent
```

---

## 1. Overview

| Item | Value |
|------|-------|
| Trigger rule | `100620` — *Defender real-time protection DISABLED* |
| Agent under control | `[agent-hostname]` |
| Manager | `[wazuh-manager-hostname-or-ip]` |
| AR action | Re-enable real-time / behavior / IOAV / script scanning + start `WinDefend` |
| AR location | `local` (runs on the agent that raised the alert) |

> **Detect-and-heal, not block.** Wazuh reacts within a few seconds; it cannot physically prevent the toggle.
> The true *prevention* layer is **Tamper Protection** (Section 7).

---

## Quick Install — Agent side

On the Wazuh **agent**, open **PowerShell as Administrator** and run each line:

```powershell
# 1. Force TLS 1.2 -- PowerShell 5.1 defaults to TLS 1.0/1.1 which GitHub decommisioned.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# 2. Save to disk and unblock -- downloaded files carry Mark-of-the-Web which trips AMSI
#    ("malicious content and has been blocked by your antivirus"). Unblock-File clears MOTW.
irm https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar/install.ps1 -OutFile $env:TEMP\install.ps1
Unblock-File $env:TEMP\install.ps1

# 3. Run
& "$env:TEMP\install.ps1"
```

> **All three lines matter.**
> - Without line 1: `Invoke-RestMethod: Unable to read data from the transport connection`.
> - Without line 2: `This script contains malicious content and has been blocked by your antivirus software.`
> - Do NOT pipe into `iex` instead — streaming flattens the body and breaks the parser
>   (`The string is missing the terminator: '@`).

> **The install is now a two-step download (outer zip bootstrap, inner installer).**
> Splitting orchestration from installation logic keeps AMSI heuristics from
> flagging the orchestrator. The bootstrap downloads `defender-guard.zip` and
> runs `_inner-install.ps1` from the extracted folder.
>
> **AMSI on hardened agents will block even the inner installer** if any
> script combines `Invoke-WebRequest` + `Register-ScheduledTask` + writing
> under `Program Files`. The shipped `defender-guard.cer` placeholder will
> NOT bypass that on its own -- you must sign the scripts once on a Windows
> dev box first:
>
> ```powershell
> # ONCE on any Windows dev machine (the one that will produce the zip)
> pwsh -File sign-and-pack.ps1
> ```
>
> That creates a self-signed cert, signs every `.ps1` / `.cmd` in this folder,
> exports the cert to `defender-guard.cer`, and rebuilds `defender-guard.zip`
> with the cert. Commit the regenerated zip + `.cer`. The inner installer
> trusts the cert into `LocalMachine\TrustedPeople` on first run -- from
> that point AMSI stops flagging the scripts because they have a valid
> publisher signature.
>
> **Manual rebuild of the unsigned zip** (no signing):
> ```powershell
> pwsh -File build-zip.ps1
> ```

This single command does everything end-to-end:

1. Downloads `install.ps1` (~3 KB) + `defender-guard.zip` (~10 KB) -- both from this repo
2. Verifies the Wazuh agent AR folder exists (aborts with hint if not)
3. Extracts the zip to `%TEMP%\defender-guard-stage\` and runs `_inner-install.ps1` out of it
4. Inner installer: trusts the publisher cert (if present) into LocalMachine\TrustedPeople
5. Places files in the right folders (`binDir` for the cmd wrapper, `psDir` for everything else)
6. Registers both Scheduled Tasks: `Defender-Guard-Event-Watch` and `Defender-Guard-Service-Watch`
7. Runs the Layer-0 Tamper Protection audit and shows the GUI/Intune/GPO path to enable it
8. Prints the final summary + verification commands

| File | Destination |
|------|-------------|
| `reenable-defender.cmd` | `C:\Program Files (x86)\ossec-agent\active-response\bin\` |
| `reenable-defender.ps1`, `watchdog-service.ps1`, `enforce-tamper-protection.ps1`, `tamper-protection-policy.xml` | `C:\Program Files\Sysinternals\` |

After it finishes, do the **manager-side** config in **Section 3**, then restart the agent (`Restart-Service WazuhSvc`).

> Manual file placement (without the installer) is documented in **Section 2**.

### INSTANT local enforcement — layered defense (recommended)

Layer 0 is the REAL prevention — Tamper Protection ON. Layer 1 is the failsafe in case it ever
turns off. Both layers are deployed automatically by `install.ps1` above.

#### Layer 0 — Tamper Protection (eliminates the 1 s window)

Tamper Protection is the only mechanism that REJECTS the disable call at the source. Once on,
no ~1 s gap exists because the disable attempt fails entirely. After `install.ps1` finishes, it
prints the current state; if Tamper is OFF, enable it via ONE of:

- **GUI** (single machine): Windows Security → Virus & threat protection → Manage settings → Tamper Protection = ON
- **Fleet (Intune):** Endpoint security → Antivirus → Tamper Protection = Enabled
- **Fleet (GPO):** Computer\Administrative Templates\Windows Components\Microsoft Defender
  Antivirus\Real-time Protection → Tamper Protection = Enabled

> **Why not a local script?** Microsoft by design does not allow a local script to flip Tamper
> Protection ON. Only GUI, Intune, or GPO can. This is by design — otherwise any privileged
> malware could disable it.

#### Layer 1 — Watchers (≤ 1 s reaction to any disable that slips through Layer 0)

`install.ps1` automatically registers **TWO** Scheduled Tasks (both run as SYSTEM, highest privileges):

| Task | Catches | Reaction time | Resource |
|------|---------|---------------|----------|
| `Defender-Guard-Event-Watch` | `Set-MpPreference ... = $true` flips logged in `Microsoft-Windows-Windows Defender/Operational` (Event 5001/5010/5012) | ~100 ms–1 s (Windows event log write delay) | 0 % CPU at idle, fires only on event |
| `Defender-Guard-Service-Watch` | `Stop-Service WinDefend` and any preference flip NOT caught by the event log | ≤ 1 s poll (`watchdog-service.ps1`) | ~20 MB RAM, ~0.01 % CPU |

To re-register the tasks later (e.g., after a schema bump) without re-downloading:
```powershell
irm https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar/install-watcher.ps1 -OutFile $env:TEMP\iw.ps1
Unblock-File $env:TEMP\iw.ps1
& "$env:TEMP\iw.ps1"
```

> **Performance:** `watchdog-service.ps1` polls via SCM (user-mode, no kernel impact). Same
> pattern as Nagios / Datadog / Zabbix / MDE sensors on millions of production machines.
> Resource use is negligible (~20 MB RAM, ~0.01 % CPU, zero disk IO at idle). Safe on laptops
> and weak VMs.

Uninstall watchers (files are kept):
```powershell
Unregister-ScheduledTask 'Defender-Guard-Event-Watch','Defender-Guard-Service-Watch' -Confirm:$false
```

> `reenable-defender.ps1` auto-detects AR-vs-standalone mode (Wazuh sends a JSON stdin line;
> the Scheduled Task launches with no stdin), so the same script handles both invocation paths.

---

## 2. Files and Locations

| File | Role | Destination (on agent) |
|------|------|------------------------|
| `reenable-defender.cmd` | Wrapper Wazuh calls | `C:\Program Files (x86)\ossec-agent\active-response\bin\` |
| `reenable-defender.ps1` | Does the actual work (AR + standalone) | `C:\Program Files\Sysinternals\` |
| `watchdog-service.ps1` | 1s poll watchdog (service liveness + preference re-enforce) | `C:\Program Files\Sysinternals\` |
| `_inner-install.ps1` | Real installer (extracted from `defender-guard.zip` by `install.ps1`) | dev / build only |
| `defender-guard.zip` | Distribution archive (built by `build-zip.ps1` / `sign-and-pack.ps1`) | downloaded at install time |
| `defender-guard.cer` | Publisher cert (generated by `sign-and-pack.ps1`); trusted on agent install | committed to repo (after signing) |
| `install.ps1` | Behavior-light bootstrap: download zip + extract + run inner | run once per agent |
| `install-watcher.ps1` | (deprecated) Re-register only the two Scheduled Tasks | run on agent only |
| `enforce-tamper-protection.ps1` | Audit + re-enforce; surfaces Tamper OFF status | `C:\Program Files\Sysinternals\` |
| `tamper-protection-policy.xml` | Intune OMA-URI + GPO ADMX snippets for Tamper Protection | manager / Intune side |
| `build-zip.ps1` | Rebuild `defender-guard.zip` from the live files (no signing) | dev box only |
| `sign-and-pack.ps1` | Sign every script with a self-signed cert + rebuild zip + export `.cer` | run once on dev box |

### reenable-defender.cmd
```bat
@echo off
REM Wrapper Wazuh calls; forwards stdin to the PowerShell AR script.
PowerShell.exe -ExecutionPolicy Bypass -NoProfile -File "C:\Program Files\Sysinternals\reenable-defender.ps1"
```

### reenable-defender.ps1 (key behavior)
- Reads Wazuh's JSON command from stdin with **`ReadLine()`** (never `ReadToEnd()` — it hangs as SYSTEM).
- On `add`: `Set-MpPreference -DisableRealtimeMonitoring $false` (+ behavior/IOAV/script), then `Start-Service WinDefend`.
- Writes its own `Starting` / `Ended` lines to `active-responses.log` via a shared `FileStream` (custom AR isn't auto-logged; the log may be tailed by logcollector).
- ASCII-only script (PS 5.1 mangles UTF-8-no-BOM).

> Both files are already deployed and verified on the reference agent.

---

## 3. Manager-Side Configuration

> Manager host is shared — always back up and check for an existing entry first.

```bash
ssh <wazuh-manager-user>@<wazuh-manager-ip>

# back up
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%F_%H%M)

# check for existing entry (must print nothing)
sudo grep -n 'reenable-defender' /var/ossec/etc/ossec.conf
```

Edit `sudo nano /var/ossec/etc/ossec.conf` and add **inside `<ossec_config>`**:

```xml
<command>
  <name>reenable-defender</name>
  <executable>reenable-defender.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>

<active-response>
  <command>reenable-defender</command>
  <location>local</location>
  <rules_id>100620</rules_id>
</active-response>
```

---

## 4. Validate and Restart

```bash
# validate XML (exit 0 = good)
sudo /var/ossec/bin/wazuh-analysisd -t ; echo "exit=$?"

# restart manager
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
```

On the agent, restart so it pulls the new AR config:
```powershell
Restart-Service WazuhSvc
```

---

## 5. Test

On the agent, as Administrator:
```powershell
Set-MpPreference -DisableRealtimeMonitoring $true     # triggers rule 100620
# wait ~5 seconds
(Get-MpComputerStatus).RealTimeProtectionEnabled       # expect: True
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Tail 6
```

**PASS criteria:** the log shows one of these patterns within ~1s (instant watcher / service watchdog) or ~5s (manager AR):
```
reenable-defender: Starting (AR). stdin=...         # from manager AR
reenable-defender: Starting (standalone).           # from event-trigger watcher
watchdog-service: RTP disabled -> re-issued ...    # from service watchdog (re-enforce loop)
reenable-defender: Verification Ended. RealTimeProtectionEnabled=True
```

Extra test for the service watchdog (catches `Stop-Service WinDefend`):
```powershell
Stop-Service WinDefend                              # service should auto-start within ~1s
Get-Service WinDefend                                # expect: Running
```

---

## 6. Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| No `reenable-defender` line in log | Manager config not loaded — re-check Section 3/4; restart agent. |
| `Access denied` placing files | Copy the `.cmd`/`.ps1` from an **elevated** PowerShell. |
| Disable command is *blocked* (RTP stays True, no AR needed) | Tamper Protection is on — that's the win, not a bug. |
| Manager won't start after edit | XML typo — restore `ossec.conf.bak.*` and re-validate with `wazuh-analysisd -t`. |
| Agent shows disconnected | `Restart-Service WazuhSvc`; confirm agent key still valid. |

---

## 7. Audit & Verify

Run on each agent to confirm the layered defense is active:

```powershell
# 1. Tamper Protection must be ON (real prevention)
powershell -ExecutionPolicy Bypass -File "C:\Program Files\Sysinternals\enforce-tamper-protection.ps1"

# 2. Both watchers registered
Get-ScheduledTask | Where-Object { $_.TaskName -like 'Defender-Guard-*' }

# 3. Real-time protection is currently ON
(Get-MpComputerStatus).RealTimeProtectionEnabled

# 4. Wazuh AR file present
Test-Path "C:\Program Files (x86)\ossec-agent\active-response\bin\reenable-defender.cmd"
```

---

## 8. Rollback

**Manager:**
```bash
sudo cp /var/ossec/etc/ossec.conf.bak.<timestamp> /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```
**Agent:** delete the deployed files, unregister both watchers, then `Restart-Service WazuhSvc`:
```powershell
Unregister-ScheduledTask 'Defender-Guard-Event-Watch','Defender-Guard-Service-Watch' -Confirm:$false
Remove-Item "C:\Program Files (x86)\ossec-agent\active-response\bin\reenable-defender.cmd"
Remove-Item "C:\Program Files\Sysinternals\reenable-defender.ps1"
Remove-Item "C:\Program Files\Sysinternals\watchdog-service.ps1"
Remove-Item "C:\Program Files\Sysinternals\install-watcher.ps1"
Remove-Item "C:\Program Files\Sysinternals\enforce-tamper-protection.ps1"
Remove-Item "C:\Program Files\Sysinternals\tamper-protection-policy.xml"
Restart-Service WazuhSvc
```

> Tamper Protection itself is a separate Intune/GPO policy — remove or disable it
> through the same channel you used to enable it.