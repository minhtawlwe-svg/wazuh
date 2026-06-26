# Wazuh Active Response — Auto Re-Enable Windows Defender

**Purpose:** When Windows Defender real-time protection is turned OFF on an agent, Wazuh rule **100620** fires and an Active Response (AR) automatically turns it back ON, then logs the event.

**Author:** AGB · **Date:** 2026-06-26

---

## 1. Overview

| Item | Value |
|------|-------|
| Trigger rule | `100620` — *Defender real-time protection DISABLED* |
| Agent under control | **MinH** (host `DESKTOP-MG5CSSO`) |
| Manager | intern-vm `<MANAGER_IP>` (native systemd Wazuh) |
| AR action | Re-enable real-time / behavior / IOAV / script scanning + start `WinDefend` |
| AR location | `local` (runs on the agent that raised the alert) |

> **Detect-and-heal, not block.** Wazuh reacts within a few seconds; it cannot physically prevent the toggle.
> The true *prevention* layer is **Tamper Protection** (Section 7).

---

## 2. Files and Locations

| File | Role | Destination (on agent) |
|------|------|------------------------|
| `reenable-defender.cmd` | Wrapper Wazuh calls | `C:\Program Files (x86)\ossec-agent\active-response\bin\` |
| `reenable-defender.ps1` | Does the actual work | `C:\Program Files\Sysinternals\` |

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

> Both files are already deployed and verified on **MinH**.

---

## 3. Manager-Side Configuration (intern-vm)

> intern-vm is a **shared box** — always back up and check for an existing entry first.

```bash
ssh cyberintern@<MANAGER_IP>

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

On the agent (**MinH**), restart so it pulls the new AR config:
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

**PASS criteria:** the log now shows
```
reenable-defender: Starting. stdin=...
reenable-defender: Re-enable attempted. RealTimeProtectionEnabled=True
reenable-defender: Ended.
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

## 7. Real Prevention — Tamper Protection (recommended)

An AR is reactive (a few-second gap). To *block* the disable outright:

- **GUI:** Windows Security → Virus & threat protection → Manage settings → **Tamper Protection = On**
- **Fleet:** Intune / GPO (`Defender` → Tamper Protection). By design it cannot be set by a local script.

Use **both**: Tamper Protection blocks the common path; rule 100620 + this AR catch and self-heal anything that slips through.

---

## 8. Rollback

**Manager:**
```bash
sudo cp /var/ossec/etc/ossec.conf.bak.<timestamp> /var/ossec/etc/ossec.conf
sudo systemctl restart wazuh-manager
```
**Agent:** delete the two deployed files and `Restart-Service WazuhSvc`.
