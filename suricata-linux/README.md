# suricata-linux

Auto-install **Suricata 7.0.x** on Linux (Debian/Ubuntu + RHEL/Fedora/Rocky), wire it to an existing **Wazuh agent**, refresh ET Open rules daily, and rotate `eve.json` at 2 GB. Parallels [`suricata-win/`](../suricata-win/).

## What `install.sh` does (step by step)

Runs as **root** with `set -euo pipefail`. Logs to `/var/log/suricata-install.log`.

### 1. Pre-flight
- Refuses non-root.
- Reads `/etc/os-release`; accepts Debian/Ubuntu (`ID_LIKE=*debian*`) and RHEL/CentOS/Rocky/Fedora families. Aborts on anything else.

### 2. Install Suricata + suricata-update
- **Debian/Ubuntu** family: mirrors the Wazuh PoC — `add-apt-repository -y ppa:oisf/suricata-stable`, then `apt-get install -y suricata`. `suricata-update` is best-effort `pip install` (not required — direct ET Open tarball path is used).
- **RHEL/Rocky/Fedora** family: enables `epel-release`, then `dnf install -y suricata suricata-update` (falls back to `yum`). Suricata is in EPEL — no separate OISF repo needed.
- Skipped if `suricata` is already on PATH (or `-SkipSuricata`).

### 3. Detect capture interfaces
- Walks `/sys/class/net/*`, filters to interfaces with a backing `device/` entry.
- Denylist (regex): `lo|docker*|veth*|br-*|virbr*|vnet*|tun*|tap*|wg*|tailscale*|hamachi*|zerotier*|bond*|dummy*`.
- Sorted by `speed` descending (missing speed → 0). Override with `-Interface <name>`.

### 4. Patch `/etc/suricata/suricata.yaml`
- Self-heals from the newest intact `.bak` if the active file is missing `rule-files:` or `app-layer:` (corruption guard).
- Backs up to `suricata.yaml.YYYYMMDDHHMMSS.bak`.
- Replaces **only** the two safe key/value lines:
  - `default-log-dir: /var/log/suricata/`
  - `default-rule-path: /etc/suricata/rules/`
- **Never** regex-rewrites `af-packet:` or `eve-log:` blocks (a greedy regex previously truncated the whole file).

### 5. Pull initial ET Open rules
- Detects Suricata version via `suricata -V`.
- Downloads `https://rules.emergingthreats.net/open/suricata-<ver>/emerging.rules.tar.gz`.
- Extracts to `/var/lib/suricata/rules/.extract/`, concatenates `rules/*.rules` → `suricata.rules`.
- Runs `suricata -T -c /etc/suricata/suricata.yaml` (non-fatal; log only).

### 6. Start Suricata via systemd
- `systemctl daemon-reload && systemctl enable --now suricata`.
- Verifies `systemctl is-active suricata`.

### 7. Bind `eve.json` → Wazuh agent
- Skipped if `-SkipWazuhConfig` or no Wazuh agent is detected.
- Locates `/var/ossec/etc/ossec.conf` (override via `-WazuhConf`).
- Backs the file up.
- **Strips** any pre-existing `<localfile>...</localfile>` block mentioning `eve.json` (idempotent — never double-monitors or leaves a stale path).
- Inserts before `</ossec_config>`:
  ```xml
    <localfile>
      <log_format>json</log_format>
      <location>/var/log/suricata/eve.json</location>
    </localfile>
  ```
- Restarts `wazuh-agent`.

### 8. Write the maintenance script
- Drops `/usr/local/sbin/suricata-maintenance.sh` (executable, 0755).
- Placeholders filled in: `__LOG_DIR__` → `/var/log/suricata`, `__RULE_DIR__` → `/var/lib/suricata/rules`, `__MAX_EVE_BYTES__` → `-MaxEveBytes`, `__KEEP_ROTATED_LOGS__` → `-KeepRotatedLogs`.
- Every run:
  1. Re-download ET Open tarball (version-matched).
  2. Re-extract and re-merge rules.
  3. `systemctl restart suricata`.
  4. If `eve.json` ≥ limit, stop Suricata, rotate `eve.json` → `eve.json.1`, shift older archives up to `eve.json.<Keep>`, drop the oldest beyond `Keep`, then restart Suricata.
- Logs to `/var/log/suricata/maintenance.log`.

### 9. Register the systemd timer
- Skipped if `-SkipScheduledTask`.
- `/etc/systemd/system/suricata-maintenance.service` — `Type=oneshot`, runs the maintenance script.
- `/etc/systemd/system/suricata-maintenance.timer` — `OnCalendar=*-*-* HH:MM:00` (default `03:15`), `Persistent=true`, `AccuracySec=1min`.
- `systemctl daemon-reload && systemctl enable --now suricata-maintenance.timer`.

### 10. Install logrotate
- Drops `/etc/logrotate.d/suricata`:
  ```
  /var/log/suricata/*.json {
      daily
      missingok
      rotate 3
      size 2G
      compress
      notifempty
      sharedscripts
      postrotate
          systemctl restart suricata > /dev/null 2>&1 || true
      endscript
  }
  ```

### 11. Finish
- Logs the final `eve.json` path and prints a summary box (eve.json path, rules dir, yaml, ossec.conf, maintenance script, timer, install log).

## Default parameters (overridable)

| Flag | Default |
| --- | --- |
| `-Interface` | auto-detect (first physical, sorted by speed) |
| `-WazuhConf` | `/var/ossec/etc/ossec.conf` |
| `-SuricataRepoUrl` | (unused — Suricata comes from `ppa:oisf/suricata-stable` on Debian/Ubuntu and EPEL on RHEL family) |
| `-MaxEveBytes` | `2147483648` (2 GB) |
| `-KeepRotatedLogs` | `3` |
| `-DailyTaskTime` | `03:15` |
| `-SkipSuricata` / `-SkipWazuhConfig` / `-SkipScheduledTask` | off |

## One-line installer

**Default** (auto-detect everything; Wazuh agent must already be installed and enrolled):

```bash
curl -fsSL https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-linux/install.sh \
  | sudo bash
```

**Pin a capture interface** (e.g. server with multiple NICs):

```bash
curl -fsSL https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-linux/install.sh \
  | sudo bash -s -- -Interface eth0
```

**Skip the Wazuh ossec.conf patch** (pure-Suricata, no agent binding):

```bash
curl -fsSL https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-linux/install.sh \
  | sudo bash -s -- -SkipWazuhConfig
```

**Bring-your-own installer** (clone repo, then run locally):

```bash
git clone https://github.com/yekyawhan/wazuh.git
cd wazuh/suricata-linux
chmod +x install.sh uninstall.sh
sudo ./install.sh
```

## Uninstall

```bash
wget https://github.com/yekyawhan/wazuh/raw/refs/heads/git-home/suricata-linux/uninstall.sh
chmod +x uninstall.sh
sudo ./uninstall.sh
```

Or non-interactive:

```bash
curl -fsSL https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-linux/uninstall.sh \
  | sudo bash -s -- --force
```

Add `--purge-wazuh` to also remove the Wazuh agent (and `/var/ossec`) in the same pass.

## Prerequisites

- **Root** access.
- **Existing Wazuh agent** installed and enrolled (this installer only patches `ossec.conf` — it does not enroll).
- **Network** access to:
  - `https://launchpad.net` (Launchpad PPA `ppa:oisf/suricata-stable`) OR EPEL mirror for RHEL family
  - `https://rules.emergingthreats.net` (ET Open tarball)
- **Kernel** with `AF_PACKET` (any modern Linux).

## Files created on the target

```
/etc/suricata/suricata.yaml              # patched (log-dir + rule-path)
/etc/suricata/suricata.yaml.<ts>.bak     # backup
/var/lib/suricata/rules/suricata.rules   # ET Open merged
/var/lib/suricata/rules/emerging.rules.tar.gz
/var/log/suricata/eve.json               # live IDS output
/var/log/suricata/eve.json.1..N          # rotated
/var/log/suricata/maintenance.log
/var/log/suricata-install.log
/usr/local/sbin/suricata-maintenance.sh
/etc/systemd/system/suricata-maintenance.service
/etc/systemd/system/suricata-maintenance.timer
/etc/logrotate.d/suricata
/var/ossec/etc/ossec.conf                # patched (eve.json <localfile>)
/var/ossec/etc/ossec.conf.<ts>.bak       # backup
```