# suricata-win

Auto-install Suricata 8.0.5 on Windows with Wazuh Agent integration.

## Script

`suricata-install.ps1` (Admin PowerShell).

## What it does (step by step)

1. **Prepare data dirs** under `C:\ProgramData\Suricata\`: `log\`, `rules\`, `state\`, `downloads\`.
2. **Install Npcap** (interactive wizard — free build has no silent mode). Skipped with `-SkipNpcap`.
3. **Install Suricata** via MSI 8.0.5. Local MSI preferred (`-SuricataMsiPath` or `$PSScriptRoot\Suricata-8.0.5-1-64bit.msi`); URL download as fallback.
4. **Install `suricata-update`** via pip (Python auto-installed via winget if missing). Skipped silently if neither Python nor winget available.
5. **Install Wazuh Agent** if `-WazuhManager <ip>` is set. Enrolls via `agent-auth`, forces `<address>` in `ossec.conf`. Default empty → skipped.
6. **Detect capture NIC** (`Get-NetAdapter -Physical`, virtual denylist). Override with `-CaptureInterfaceName`.
7. **Patch `suricata.yaml`** (BOM-less UTF-8, single-quoted paths): `default-log-dir`, `default-rule-path`. Self-heals from intact `.bak` if YAML looks truncated.
8. **Pull ET Open rules** directly from `https://rules.emergingthreats.net/open/suricata-<ver>/` with fallback to `suricata-7.0.16/` if the version-specific directory is empty. Defender exclusion added for `$RuleRoot` + `$DownloadRoot`. Runs `suricata -T` non-fatal config test.
9. **Create/fix Suricata service**. If `--service-install` writes an unquoted binPath, force quoted `ImagePath` via registry. Throws if service does not reach `Running`.
10. **Bind eve.json to Wazuh** in `ossec.conf`. Strips any pre-existing Suricata `<localfile>` block before inserting. Skipped with `-SkipWazuhConfig`.
11. **Write `Suricata-Maintenance.ps1`** (BOM-less UTF-8).
12. **Register daily task** `Suricata Daily Update And Log Rotation` as SYSTEM, daily at `-DailyTaskTime` (default `13:00`). Skipped with `-SkipScheduledTask`.

## Maintenance script daily run

1. Update ET Open rules (same version-flexible URL fallback).
2. If `eve.json` ≥ `-MaxEveBytes` (default `2GB`):
   - Stop Suricata.
   - Shift `eve.json.<n>` → `eve.json.<n+1>`.
   - Delete beyond `-KeepRotatedLogs` (default `3`).
   - Move `eve.json` → `eve.json.1`.
   - Restart Suricata.

## Parameters

| Param | Default | Notes |
| --- | --- | --- |
| `-SuricataMsiUrl` | `https://www.openinfosecfoundation.org/download/windows/Suricata-8.0.5-1-64bit.msi` | |
| `-SuricataMsiPath` | `""` | Local MSI; wins over URL |
| `-NpcapUrl` | `https://npcap.com/dist/npcap-1.82.exe` | |
| `-InstallRoot` | `C:\Program Files\Suricata` | |
| `-DataRoot` | `C:\ProgramData\Suricata` | |
| `-WazuhConf` | autodetect | Override `ossec.conf` path |
| `-WazuhManager` | `""` | Set IP to install+enroll Wazuh Agent |
| `-WazuhAgentMsiUrl` | `https://packages.wazuh.com/4.x/windows/wazuh-agent-4.14.5-1.msi` | |
| `-WazuhAgentName` | `$env:COMPUTERNAME` | |
| `-CaptureInterfaceName` | `""` | Override NIC selection (e.g. `"VMware Network Adapter VMnet8"`) |
| `-MaxEveBytes` | `2GB` | Rotation threshold |
| `-KeepRotatedLogs` | `3` | Max `eve.json.N` kept |
| `-DailyTaskTime` | `13:00` | Daily task trigger |
| `-SkipNpcap` / `-SkipSuricata` / `-SkipWazuhAgentInstall` / `-SkipWazuhConfig` / `-SkipScheduledTask` | off | |

## One-line installer

Downloads `suricata-install.ps1` from `git-home` branch and runs it.

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $branch="git-home"; $url="https://raw.githubusercontent.com/yekyawhan/wazuh/$branch/suricata-win/suricata-install.ps1"; Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\suricata-install.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\suricata-install.ps1"
```

## Notes

- Npcap free build cannot silent-install. The wizard runs interactively and the script waits.
- `suricata-update` is installed for plan compliance but is broken on Windows (Errno 13). Rule updates use the direct ET Open tarball path.
- ET Open rules fallback: tries `suricata-<detected-version>/`, falls back to `suricata-7.0.16/`.
- MSI `8.0.5` is downloaded from OISF. Place `Suricata-8.0.5-1-64bit.msi` next to the script for offline install (filename must match exactly).
- Logs: `install.log` and `maintenance.log` under `$DataRoot`. BOM-less UTF-8.