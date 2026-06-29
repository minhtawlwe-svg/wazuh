# Wazuh Active Response — Auto Re-Enable Windows Defender

**Purpose:** When Windows Defender real-time protection is turned OFF on an agent, Wazuh rule **100620** fires and a layered local defense immediately forces it back ON.

**Author:** [redacted] · **Date:** 2026-06-26

---

## Quick Reference (TL;DR)

**On agent (elevated PowerShell):**
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Force a clean copy every run so a previous partial install doesn't get re-executed.
if (Test-Path $env:TEMP\install.ps1) { Remove-Item $env:TEMP\install.ps1 -Force }
irm https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/active-response/defendar-guard-ar/install.ps1 -OutFile $env:TEMP\install.ps1
Unblock-File $env:TEMP\install.ps1
& "$env:TEMP\install.ps1"
```

**On manager** (`/var/ossec/etc/ossec.conf` inside `<ossec_config>`):
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

**Validate + restart:**
```bash
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
```
```powershell
Restart-Service WazuhSvc   # on agent
```

---

## 1. Defense Layers

| Layer | Component | Reaction | Resource use |
|-------|-----------|----------|--------------|
| **0 - prevent** | Tamper Protection ON (Intune/GPO) | **0 ms** — disable is rejected at source | — |
| **1 - poll** | `Defender-Guard-Service-Watch` (Scheduled Task, 1 s poll) | **≤ 1 s** | ~20 MB RAM, ~0.01 % CPU |
| **2 - event** | `Defender-Guard-Event-Watch` (Scheduled Task, Event 5001/5010/5012) | **~100 ms** | 0 % CPU at idle |
| **3 - audit** | Wazuh manager AR (rule 100620) | **a few seconds** | log only |

All four are independent. Layer 0 stops the disable entirely. The rest are belt-and-suspenders coverage in case Tamper ever turns off.

The Wazuh manager AR is reactive (alert → manager → agent). Layer 1 + 2 react directly on the **agent**, so the very first disable attempt is re-enabled within ≤ 1 s, with no manager round-trip.

> **Tamper Protection is the only mechanism that completely eliminates the disable window.**
> Tamper ON → `Set-MpPreference -DisableRealtimeMonitoring $true` is REJECTED → no re-enable ever needed.
> It can only be enabled via GUI / Intune / GPO (not by a local script, by Microsoft design).
> Use `tamper-protection-policy.xml` to ship the policy via Intune or GPO.

---

## 2. Quick Install — Agent side

`install.ps1` does it all in one shot: downloads the four files, places them in the right folders, registers the two Scheduled Tasks, audits Tamper Protection, prints a summary.

| File | Destination |
|------|-------------|
| `reenable-defender.cmd` | `C:\Program Files (x86)\ossec-agent\active-response\bin\` |
| `reenable-defender.ps1` | `C:\Program Files\Sysinternals\` |
| `watchdog-service.ps1` | `C:\Program Files\Sysinternals\` |
| `enforce-tamper-protection.ps1` | `C:\Program Files\Sysinternals\` |
| `tamper-protection-policy.xml` | `C:\Program Files\Sysinternals\` |

After it finishes, do the **manager-side** config above, then restart the agent (`Restart-Service WazuhSvc`).

> **All three PowerShell lines matter.**
> - Without line 1: `Invoke-RestMethod: Unable to read data from the transport connection` (PS 5.1 default is TLS 1.0/1.1; GitHub decommisioned those).
> - Without line 2: `This script contains malicious content and has been blocked by your antivirus software` (Mark-of-the-Web triggers AMSI).
> - Do NOT pipe into `iex` — streaming flattens the body and breaks the parser (`The string is missing the terminator: '@`).
>
> **AMSI on hardened agents will block the script anyway.** When Defender AMSI is
> unsure about a script it creates a probe file `__PSScriptPolicyTest_<hash>.ps1`
> in `C:\Windows\SystemTemp\` to inspect it. If you see that path in alerts
> (Sysmon EventID 11, rule 92205), the AR launched but AMSI flagged the script.
> Persistent on this agent every AR run will leave that probe.
>
> **Fix once with a self-signed code-signing cert.**
>
> Run **once** on any Windows dev box (PowerShell 5.1 or 7+):
> ```powershell
> # cd into a fresh clone of this folder
> .\sign-once.ps1
> # follow the printed "Next steps" - commit and push the regenerated .ps1/.cmd + defender-guard.cer
> ```
> What that does:
> 1. Creates a self-signed code-signing cert (5-year, `CurrentUser\My`)
> 2. Exports the public cert as `defender-guard.cer`
> 3. Signs every `.ps1` and `.cmd` in the folder with `Set-AuthenticodeSignature`
>
> After you commit and push, agents that run `install.ps1` will:
> 1. Download `defender-guard.cer`
> 2. Import it into `LocalMachine\TrustedPeople`
> 3. From that point AMSI sees a trusted publisher for every signed script - no test probe, no quarantine, no `malicious content blocked` error

---

## 3. Files in this Repository

| File | Role |
|------|------|
| `reenable-defender.cmd` | Wrapper Wazuh calls. Prefers PowerShell 7, falls back to Windows PowerShell 5.1. |
| `reenable-defender.ps1` | Does the actual work. AR mode (reads JSON from stdin via `ReadLine()`) or standalone (no stdin). |
| `watchdog-service.ps1` | 1 s poll: keeps `WinDefend` alive + re-issues `Set-MpPreference -DisableRealtimeMonitoring $false`. |
| `enforce-tamper-protection.ps1` | Audit + re-enforce; surfaces Tamper OFF status with GUI/Intune/GPO enable path. |
| `tamper-protection-policy.xml` | Ready-to-paste Intune OMA-URI + GPO ADMX policy for Tamper Protection. |
| `install.ps1` | One-shot installer. Downloads, places, registers both Scheduled Tasks, imports publisher cert. |
| `sign-once.ps1` | Run once on a Windows dev box. Creates cert, signs every script, exports `.cer`. |
| `defender-guard.cer` | Public cert produced by `sign-once.ps1`; trusted by `install.ps1` on the agent. (Only present after you run `sign-once.ps1`.) |
| `ossec.conf` | Manager-side `<command>` + `<active-response>` blocks. |

### reenable-defender.cmd
```bat
@echo off
setlocal EnableExtensions

set SCRIPT_PATH=C:\Program Files\Sysinternals\reenable-defender.ps1

REM PowerShell 7 first, then Windows PowerShell 5.1 fallback
if exist "%ProgramFiles%\PowerShell\7\pwsh.exe" (
    "%ProgramFiles%\PowerShell\7\pwsh.exe" ^
        -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
        -WindowStyle Hidden -File "%SCRIPT_PATH%"
    goto :end
)

if exist "%ProgramFiles(x86)%\PowerShell\7\pwsh.exe" (
    "%ProgramFiles(x86)%\PowerShell\7\pwsh.exe" ^
        -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
        -WindowStyle Hidden -File "%SCRIPT_PATH%"
    goto :end
)

if exist "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" (
    "%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe" ^
        -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
        -WindowStyle Hidden -File "%SCRIPT_PATH%"
    goto :end
)

powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass ^
    -WindowStyle Hidden -File "%SCRIPT_PATH%"

:end
endlocal
```

---

## 4. Manager-Side Configuration

```bash
ssh <wazuh-manager-user>@<wazuh-manager-ip>

# back up
sudo cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak.$(date +%F_%H%M)

# check for existing entry (must print nothing)
sudo grep -n 'reenable-defender' /var/ossec/etc/ossec.conf
```

Edit `/var/ossec/etc/ossec.conf` and add inside `<ossec_config>`:
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

## 5. Validate and Restart

```bash
sudo /var/ossec/bin/wazuh-analysisd -t ; echo "exit=$?"
sudo systemctl restart wazuh-manager
sudo systemctl status wazuh-manager --no-pager
```

On the agent:
```powershell
Restart-Service WazuhSvc
```

---

## 6. Test

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true     # triggers rule 100620
Start-Sleep -Seconds 2
(Get-MpComputerStatus).RealTimeProtectionEnabled       # expect: True
Get-Content "C:\Program Files (x86)\ossec-agent\active-response\active-responses.log" -Tail 6

# Service watchdog (catches Stop-Service WinDefend)
Stop-Service WinDefend
Start-Sleep -Seconds 2
Get-Service WinDefend                                 # expect: Running
```

**PASS criteria:** one of these patterns within ~1 s (local watcher) or ~5 s (manager AR):
```
watchdog-service:  RTP disabled -> re-issued ...                # from service poll
reenable-defender: Starting (standalone).                       # from event-trigger watcher
reenable-defender: Starting (AR). stdin=...                    # from manager AR
reenable-defender: Verification Ended. RealTimeProtectionEnabled=True
```

---

## 7. Audit & Verify

```powershell
# 1. Tamper Protection state + recent events
powershell -ExecutionPolicy Bypass -File "C:\Program Files\Sysinternals\enforce-tamper-protection.ps1"

# 2. Both Scheduled Tasks
Get-ScheduledTask | Where-Object { $_.TaskName -like 'Defender-Guard-*' }

# 3. Real-time protection ON
(Get-MpComputerStatus).RealTimeProtectionEnabled

# 4. Wazuh AR wrapper present
Test-Path "C:\Program Files (x86)\ossec-agent\active-response\bin\reenable-defender.cmd"
```

---

## 8. Troubleshooting

| Symptom | Cause / Fix |
|---------|-------------|
| `Invoke-RestMethod: Unable to read data from the transport` | PS 5.1 default TLS 1.0; add `[Net.ServicePointManager]::SecurityProtocol = Tls12` BEFORE `irm`. |
| `This script contains malicious content and has been blocked by your antivirus` | Mark-of-the-Web; add `Unblock-File` after `irm`. |
| `The string is missing the terminator: '@` | Body streamed via `| iex`; use `-OutFile + &` instead. |
| `Registration of the ScheduledTask failed` | Run as Administrator; check `Get-ScheduledTask | ? State` |
| `Disable command is blocked (RTP stays True)` | Tamper Protection is ON — that's the win, not a bug. |
| Manager won't start after edit | XML typo — restore `ossec.conf.bak.*` and re-validate with `wazuh-analysisd -t`. |
| Agent shows disconnected | `Restart-Service WazuhSvc`; confirm agent key still valid. |

---

## 9. Rollback

**Manager:**
```bash
sudo cp /var/ossec/etc/ossec.conf.bak.<timestamp> /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```

**Agent:**
```powershell
Unregister-ScheduledTask 'Defender-Guard-Event-Watch','Defender-Guard-Service-Watch' -Confirm:$false
Remove-Item "C:\Program Files (x86)\ossec-agent\active-response\bin\reenable-defender.cmd"
Remove-Item "C:\Program Files\Sysinternals\reenable-defender.ps1"
Remove-Item "C:\Program Files\Sysinternals\watchdog-service.ps1"
Remove-Item "C:\Program Files\Sysinternals\enforce-tamper-protection.ps1"
Remove-Item "C:\Program Files\Sysinternals\tamper-protection-policy.xml"
Restart-Service WazuhSvc
```

> Tamper Protection itself is a separate Intune / GPO policy — remove or disable it through the same channel you used to enable it.
