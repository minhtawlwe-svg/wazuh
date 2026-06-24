# suricata-linux

Auto-install **Suricata 8.0.x** on Linux (Debian/Ubuntu + RHEL/Fedora/Rocky), bind it to an **existing, running Wazuh agent**, load ET Open rules, refresh them daily, and rotate `eve.json` at 2 GB. Parallels [`suricata-win/`](../suricata-win/).

The installer is **interactive by default**: it lets you pick the capture interface from a menu and enter your monitored network range (`HOME_NET`). It is also fully scriptable via flags for unattended fleet rollout.

---

## Status

Verified end-to-end on Ubuntu 24.04 with Suricata 8.0.5 and Wazuh agent 4.14.5:

- Suricata capturing on the selected interface, scoped to a manually-entered `HOME_NET`.
- `eve.json` written by Suricata and ingested by the Wazuh agent.
- ~50,000 ET Open signatures loaded; `suricata -T` passes.
- Daily maintenance timer + logrotate active.
- Clean restart with automatic, **safe** rollback if (and only if) the agent genuinely fails to come up.

---

## What `install.sh` does (step by step)

Runs as **root** with `set -euo pipefail`. Logs every action to `/var/log/suricata-install.log`.

### 1. Pre-flight
- Refuses to run as non-root.
- Validates `-HomeNet` (if given) before touching anything — rejects malformed CIDR/IP lists early.
- Reads `/etc/os-release`; accepts Debian/Ubuntu (`ID_LIKE=*debian*`) and RHEL/CentOS/Rocky/Fedora families. Aborts on anything else.
- **Requires the Wazuh agent to be installed AND running.** If the agent is absent, the installer stops (it never installs Wazuh). If the agent is installed but stopped, it also stops — patching a dead agent is refused. Skipped only with `-SkipWazuhConfig`.

### 2. Install Suricata
- **Debian/Ubuntu**: adds `ppa:oisf/suricata-stable`, then installs `suricata`. Handles the common **file-conflict** where a standalone `suricata-update` package (or a pip copy) owns `/usr/bin/suricata-update`, which the OISF `suricata` package also ships — the conflicting package is removed and, if needed, the install retries with `--force-overwrite`. Interrupted `dpkg` state from a prior failed run is repaired first.
- **RHEL/Rocky/Fedora**: enables `epel-release`, then `dnf install -y suricata suricata-update` (falls back to `yum`).
- Installs `libxml2-utils` / `libxml2` for XML validation (best-effort).
- Considered "already installed" only if **both** the `suricata` binary **and** `/etc/suricata/suricata.yaml` are present. If the binary exists but the config is missing, the package is reinstalled (`--force-confmiss`) to restore the YAML. Skipped entirely with `-SkipSuricata`.

### 3. Select the capture interface
- Walks `/sys/class/net/*`, keeps interfaces with a backing `device/` entry, and applies a denylist (regex): `lo|docker*|veth*|br-*|virbr*|vnet*|tun*|tap*|wg*|tailscale*|hamachi*|zerotier*|bond*|dummy*`. Sorted by link speed, descending.
- **Interactive (default):** prints a numbered menu with each NIC's **IPv4 / state / speed** so you can recognise the right one, and you type the number or name.
- **`-Interface <name>`:** binds exactly that interface, no prompt.
- **`-NonInteractive` / no TTY:** silently uses the fastest detected interface.
- This is a **single-interface** model — exactly one capture interface is bound.

### 4. Enter HOME_NET (monitored network range)
- **Interactive (default):** prompts for one or more CIDRs, e.g. `10.20.30.0/24,10.50.0.0/16`. Press ENTER to leave the existing `suricata.yaml` value unchanged.
- **`-HomeNet "<cidr[,cidr]>"`:** sets it without prompting. Accepts a comma-separated CIDR/IP list or `any`.
- Input is validated; a bad entry is rejected and re-prompted (or aborts, with the flag).

### 5. Patch `/etc/suricata/suricata.yaml`
- Self-heals from the newest intact `.bak` (or `suricata --dump-config`) if the active file is missing `rule-files:` or `app-layer:` (corruption guard).
- Backs up to `suricata.yaml.YYYYMMDDHHMMSS.bak`.
- Sets the two path keys: `default-log-dir: /var/log/suricata/` and `default-rule-path: /etc/suricata/rules/`.
- **Binds the selected interface** into the first `af-packet:` entry and **sets HOME_NET** under `vars: → address-groups:` — using a **comment-preserving line editor** (it rewrites only the specific lines and keeps every stock comment intact; it never reserialises the file and never truncates it with a greedy regex).

### 6. Pull initial ET Open rules
- Detects the Suricata version via `suricata -V`.
- Downloads `https://rules.emergingthreats.net/open/suricata-<ver>/emerging.rules.tar.gz`.
- Extracts to `/etc/suricata/rules/.extract/`, concatenates `rules/*.rules` → `/etc/suricata/rules/suricata.rules`.
- Runs `suricata -T -c /etc/suricata/suricata.yaml` (non-fatal; logged).

### 7. Start Suricata — with output verification
- **Fixes log-directory ownership first.** Suricata drops privileges to its run-as user (typically `suricata`) after init; if `eve.json`/`fast.log`/`stats.log` were pre-created as root, the privilege-dropped process cannot write them and **eve-log silently fails while the service still reports `active`**. The installer chowns `/var/log/suricata` to the detected run-as user before starting.
- `systemctl enable --now suricata`, then verifies `is-active`.
- **Verifies eve-log actually opened** by checking `suricata.log` for `Permission denied` / `setup failed`. If found, it re-applies ownership and restarts once; if it still cannot open, it fails loudly with the exact diagnostic instead of reporting false success.

### 8. Bind `eve.json` → Wazuh agent
- Skipped with `-SkipWazuhConfig`.
- Backs up `ossec.conf` to `ossec.conf.YYYYMMDDHHMMSS.bak`.
- **Strips any existing eve.json `<localfile>` block, on any OS path** — Linux *or* a stale Windows path like `C:\ProgramData\Suricata\log\eve.json` left over from the PowerShell installer (case-insensitive). Also removes any now-empty `<ossec_config></ossec_config>` shell. This is idempotent: re-runs never duplicate the binding.
- Inserts before the **last** `</ossec_config>` (ossec.conf is a multi-root XML fragment):
  ```xml
    <localfile>
      <log_format>json</log_format>
      <location>/var/log/suricata/eve.json</location>
    </localfile>
  ```
- **Validates** the result with a **multi-root-aware** XML check (wraps the fragment in a synthetic root so multiple `<ossec_config>` blocks validate the way OSSEC parses them). If the result is not well-formed, it aborts and leaves the original untouched.
- **Preserves `ossec.conf` ownership/permissions.** The temp file is written as root; after replacing the live file, the original owner/group/mode (`wazuh:wazuh`, `0640`) is restored — a root-owned `ossec.conf` makes the agent fail to start.
- **Clean restart with safe rollback:** stops the agent, reaps any orphaned `wazuh-*` daemons, starts via `wazuh-control`, and polls until the agent is genuinely running. Only if it is still down after an extended grace check does it restore the backup and abort. A healthy-but-slow agent is **not** rolled back.

### 9. Write the maintenance script
- Drops `/usr/local/sbin/suricata-maintenance.sh` (0755) with all four placeholders filled: `__LOG_DIR__`, `__RULE_DIR__`, `__MAX_EVE_BYTES__`, `__KEEP_ROTATED_LOGS__`.
- Every run: re-download + re-merge ET Open rules (version-matched), restart Suricata, and rotate `eve.json` → `eve.json.1` (shifting older archives up to `eve.json.<Keep>`, dropping the oldest) once it reaches the size limit. Logs to `/var/log/suricata/maintenance.log`.

### 10. Register the systemd timer
- Skipped with `-SkipScheduledTask`.
- `suricata-maintenance.service` (`Type=oneshot`) + `suricata-maintenance.timer` (`OnCalendar=*-*-* HH:MM:00`, default `03:15`, `Persistent=true`).

### 11. Install logrotate
- Drops `/etc/logrotate.d/suricata` (daily, keep `<Keep>`, `size` derived from `-MaxEveBytes` as a human-readable suffix e.g. `2G`, compress, restart Suricata on rotate).

### 12. Finish
- Logs the final `eve.json` path and prints a summary box.

---

## Flags

| Flag | Default | Purpose |
| --- | --- | --- |
| `-Interface <name>` | interactive menu / fastest NIC | Bind a specific single capture interface (no prompt). |
| `-HomeNet <cidr[,cidr]>` | interactive prompt / unchanged | Set `HOME_NET`, e.g. `10.20.30.0/24,10.50.0.0/16` or `any`. |
| `-NonInteractive` | off | Never prompt; use fastest NIC and leave `HOME_NET` unchanged unless flags given. |
| `-WazuhConf <path>` | `/var/ossec/etc/ossec.conf` | ossec.conf location. |
| `-MaxEveBytes <bytes>` | `2147483648` (2 GB) | eve.json rotation threshold. |
| `-KeepRotatedLogs <n>` | `3` | Archived `eve.json.*` to keep. |
| `-DailyTaskTime <HH:MM>` | `03:15` | Maintenance timer time. |
| `-WazuhStartTimeout <sec>` | `45` | Seconds to wait for the agent to come up before the grace check. |
| `-SkipSuricata` | off | Use existing Suricata; skip install. |
| `-SkipWazuhConfig` | off | Skip the ossec.conf binding (pure-Suricata) and the Wazuh-running precheck. |
| `-SkipScheduledTask` | off | Skip the systemd maintenance timer. |
| `-SuricataRepoUrl <url>` | (reserved) | Currently unused. |

---

## Usage

### Interactive (recommended for a single sensor)

```bash
git clone https://github.com/yekyawhan/wazuh.git
cd wazuh/suricata-linux
chmod +x install.sh uninstall.sh
sudo ./install.sh
```

### Unattended (fleet rollout)

Provide the interface and range as flags, and silence prompts:

### One-liner

```bash
curl -fsSL https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-linux/install.sh \
  | sudo bash
```

> Note: piping through `bash` is not a TTY, so prompts are skipped automatically. Pass `-Interface`/`-HomeNet` explicitly when using the one-liner, or clone and run interactively.

### Re-binding only (Suricata already configured)

```bash
sudo ./install.sh -SkipSuricata -Interface eth0 -HomeNet "10.20.30.0/24"
```
```bash
sudo ./install.sh -NonInteractive -Interface eth0 -HomeNet "10.20.30.0/24"
```
You'll be asked to pick the interface and enter `HOME_NET`. Example session:

```
Select the capture interface for Suricata:
  No.  IFACE   IPv4             STATE  SPEED
  1)   eth1    192.168.10.5/24  up     1000Mb/s
  2)   eth0    10.20.30.5/24    up     1000Mb/s
Enter number or interface name [default: eth1]: eth0

Set HOME_NET (the network range(s) Suricata treats as internal).
Enter comma-separated CIDRs, e.g.  10.20.30.0/24,10.50.0.0/16
HOME_NET: 10.20.30.0/24
```

---

## Verify it's working

```bash
# Config is clean: exactly one eve.json binding, no Windows path
grep -c '/var/log/suricata/eve.json' /var/ossec/etc/ossec.conf   # -> 1
grep -c 'ProgramData' /var/ossec/etc/ossec.conf                  # -> 0

# Agent is up
sudo /var/ossec/bin/wazuh-control status

# Suricata is capturing on the chosen interface and writing events
sudo grep -E "capture|eth" /var/log/suricata/suricata.log | tail -3
sudo wc -l /var/log/suricata/eve.json

# Trigger and watch an alert (a port scan against this host works well)
sudo tail -f /var/log/suricata/eve.json | grep --line-buffered '"event_type":"alert"'
```

`eve.json` may read 0 lines for the first ~30–60 s after a restart — flow events flush on flow timeout, so give the interface a little traffic and wait.

---

## A note on shared (manager-pushed) config

A Wazuh agent merges config from **both** its local `ossec.conf` **and** config pushed by the manager (`/var/ossec/etc/shared/agent.conf`, compiled into `merged.mg`). If the manager's shared config for the agent's group already contains a Suricata eve.json `<localfile>`, you can end up reading `eve.json` twice (local + shared) → duplicate events.

Two things to watch:
- **Decide where the binding lives.** Either keep it local (this installer) **or** centralize it on the manager — not both. If the manager owns it, run the installer with `-SkipWazuhConfig`.
- **Scope shared bindings by OS.** A stale, unscoped Windows `<localfile>` in a shared group pushes a `C:\...` path to *every* agent in the group, including Linux sensors, producing a harmless-but-noisy `ERROR (1103)` on each start. Scope each path to its OS on the manager:

  ```xml
  <agent_config os="Linux">
    <localfile>
      <log_format>json</log_format>
      <location>/var/log/suricata/eve.json</location>
    </localfile>
  </agent_config>

  <agent_config os="Windows">
    <localfile>
      <log_format>json</log_format>
      <location>C:\ProgramData\Suricata\log\eve.json</location>
    </localfile>
  </agent_config>
  ```

---

## Capture topology (passive IDS)

This installer configures Suricata in passive `AF_PACKET` mode. The bound interface only sees traffic that physically reaches it:

- Bound to a **regular interface** → Suricata sees this host's own traffic (and broadcast/multicast on its segment). Good for validating the pipeline (e.g. scanning the host).
- Bound to a **SPAN/mirror port or network TAP** → Suricata sees the broader production traffic mirrored to it. This is the usual deployment for monitoring a network segment.

Pick the interface accordingly when prompted.

---

## Uninstall

```bash
wget https://github.com/yekyawhan/wazuh/raw/refs/heads/git-home/suricata-linux/uninstall.sh
chmod +x uninstall.sh
sudo ./uninstall.sh
```

Non-interactive:

```bash
curl -fsSL https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/suricata-linux/uninstall.sh \
  | sudo bash -s -- --force
```

Add `--purge-wazuh` to also remove the Wazuh agent (and `/var/ossec`) in the same pass.

---

## Prerequisites

- **Root** access.
- **Existing Wazuh agent**, installed, enrolled, **and running** (the installer patches `ossec.conf` and binds eve.json — it does not install or enroll Wazuh, and refuses to run against a stopped agent).
- **Network** access to:
  - Launchpad (PPA `ppa:oisf/suricata-stable`) on Debian/Ubuntu, or an EPEL mirror on the RHEL family.
  - `https://rules.emergingthreats.net` (ET Open rules).
- **Kernel** with `AF_PACKET` (any modern Linux).

---

## Files created on the target

```
/etc/suricata/suricata.yaml                # patched (log-dir, rule-path, af-packet interface, HOME_NET)
/etc/suricata/suricata.yaml.<ts>.bak       # backup(s)
/etc/suricata/rules/suricata.rules         # ET Open merged
/etc/suricata/rules/emerging.rules.tar.gz
/etc/suricata/rules/.extract/              # extraction scratch
/var/log/suricata/eve.json                 # live IDS output
/var/log/suricata/eve.json.1..N            # rotated archives
/var/log/suricata/fast.log
/var/log/suricata/stats.log
/var/log/suricata/suricata.log
/var/log/suricata/maintenance.log
/var/log/suricata-install.log
/usr/local/sbin/suricata-maintenance.sh
/etc/systemd/system/suricata-maintenance.service
/etc/systemd/system/suricata-maintenance.timer
/etc/logrotate.d/suricata
/var/ossec/etc/ossec.conf                  # patched (eve.json <localfile>, ownership preserved)
/var/ossec/etc/ossec.conf.<ts>.bak         # backup(s)
```
