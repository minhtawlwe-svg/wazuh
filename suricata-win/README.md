# suricata-win

## What the installer does (step by step)

`Install-Suricata-Full-Auto.ps1` runs as Administrator with `StrictMode` and `Stop` error behavior. It logs to `C:\ProgramData\Suricata\install.log`.

### 1. Prepare data directories
Creates these paths under `C:\ProgramData\Suricata\`:
- `log\`        — Suricata eve.json output
- `rules\`      — rule files written by `suricata-update`
- `state\`      — `suricata-update` cache/index
- `downloads\`  — cached installers (Npcap exe, Suricata MSI)

### 2. Install Npcap (silent)
- Skipped if `-SkipNpcap`.
- Checks uninstall registry for an existing Npcap entry; if absent, downloads `https://npcap.com/dist/npcap-1.82.exe` and runs it with `/S /winpcap_mode=yes`.
- Required for Suricata packet capture on Windows.

### 3. Install Suricata (MSI, silent)
- Skipped if `-SkipSuricata`.
- Detects existing `suricata.exe` via `Get-Command` and a recursive search under `C:\Program Files*`.
- If missing, downloads the MSI from `https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.11-1-64bit.msi` and runs `msiexec /i ... /qn /norestart /L*v suricata-msi.log`.

### 4. Detect physical capture interfaces
- Calls `Get-NetAdapter -Physical`.
- Filters by name/description against a denylist of virtual adapters: `virtual|vmware|virtualbox|hyper-v|docker|veth|vethernet|loopback|npcap loopback|wi-fi direct|bluetooth|tap|tun|wireguard|zerotier|tailscale|hamachi|isatap|teredo`.
- Prefers adapters that are `Up`; falls back to all physical if none are up.
- Sorts by link speed (descending) and maps each adapter to `\Device\NPF_{<InterfaceGuid>}`.

### 5. Patch `suricata.yaml`
- Backs the original file up as `suricata.yaml.<timestamp>.bak`.
- Sets:
  - `default-log-dir: "C:\ProgramData\Suricata\log"`
  - `default-rule-path: "C:\ProgramData\Suricata\rules"`
- Replaces the `pcap:` block with one entry per detected interface (`threads: auto`, `promisc: yes`, `checksum-checks: auto`).
- Enables the `eve-log` block and forces its `filename:` to `eve.json`.

### 6. Install `suricata-update`
- Skipped if already on `PATH`.
- If Python is missing, installs `Python.Python.3.12` via `winget` (silent, accepting agreements).
- Upgrades `pip`, then `pip install --upgrade suricata-update`.

### 7. Pull initial ET Open rules
- Runs `suricata-update update-sources` (tolerates non-zero exit).
- Enables the `et/open` source.
- Runs `suricata-update --suricata-conf <yaml> --no-test --output <RuleRoot>`.

### 8. Start/restart the Suricata service
- If `Suricata` service exists, restarts it.
- Otherwise runs `suricata.exe --service-install -c <yaml> -i <first-interface>` and starts the service.
- Throws if the service still cannot be found.

### 9. Bind eve.json to Wazuh Agent
- Skipped if `-SkipWazuhConfig`.
- Locates `ossec.conf` at `C:\Program Files (x86)\ossec-agent\ossec.conf` or `C:\Program Files\ossec-agent\ossec.conf` (or `-WazuhConf` if passed).
- Backs the file up.
- Inserts a `<localfile>` block (json format, eve.json path) just before `</ossec_config>`. No-op if the path is already present.
- Restarts `WazuhSvc` if present.

### 10. Write the maintenance script
- Drops `C:\ProgramData\Suricata\Suricata-Maintenance.ps1` with these placeholders filled in:
  - `__DATA_ROOT__` → `C:\ProgramData\Suricata`
  - `__MAX_EVE_BYTES__` → 2GB (or `-MaxEveBytes`)
  - `__KEEP_ROTATED_LOGS__` → 3 (or `-KeepRotatedLogs`)
- The maintenance script does, every run:
  1. `suricata-update update-sources`
  2. `suricata-update enable-source et/open`
  3. `suricata-update --suricata-conf <yaml> --no-test --output <rules>`
  4. Restart the Suricata service.
  5. If `eve.json` ≥ limit, stop Suricata, rotate `eve.json` → `eve.json.1`, shift older archives up to `eve.json.<Keep>`, delete the oldest beyond `Keep`, then restart Suricata.
- Logs to `C:\ProgramData\Suricata\maintenance.log`.

### 11. Register the daily scheduled task
- Skipped if `-SkipScheduledTask`.
- Task name: `Suricata Daily Update And Log Rotation`.
- Trigger: daily at `-DailyTaskTime` (default `13:00`).
- Runs `powershell.exe -NoProfile -ExecutionPolicy Bypass -File <maintenance script>` as `SYSTEM` with highest privileges, `StartWhenAvailable`, ignore new instances, 2-hour time limit.

### 12. Finish
- Logs the final `eve.json` path. Any thrown error is logged and re-raised.

## Default parameters (overridable)

| Param | Default |
| --- | --- |
| `-SuricataMsiUrl` | `https://www.openinfosecfoundation.org/download/windows/Suricata-7.0.11-1-64bit.msi` |
| `-NpcapUrl` | `https://npcap.com/dist/npcap-1.82.exe` |
| `-InstallRoot` | `C:\Program Files\Suricata` |
| `-DataRoot` | `C:\ProgramData\Suricata` |
| `-WazuhConf` | autodetect |
| `-MaxEveBytes` | `2GB` |
| `-KeepRotatedLogs` | `3` |
| `-DailyTaskTime` | `03:15` |
| `-SkipNpcap` / `-SkipSuricata` / `-SkipWazuhConfig` / `-SkipScheduledTask` | off |

## One-line installer

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $branch="git-home"; $url="https://raw.githubusercontent.com/yekyawhan/wazuh/$branch/suricata-win/suricata-install.ps1"; Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\suricata-install.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\suricata-install.ps1"
```
