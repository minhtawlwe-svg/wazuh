# Suricata-Wazuh Integration Planning (Linux)

## Goal
Automated Suricata deployment on Linux (Debian/Ubuntu + RHEL/Fedora/Rocky) with auto-detection of physical interfaces, daily ET Open rule refresh, logrotate-driven `eve.json` cleanup, and seamless Wazuh agent log integration.

## Architecture
- **Detector**: Suricata 7.0.x (Linux binary from OISF official repo)
- **Capture mode**: AF_PACKET (passive IDS, no iptables/nftables changes)
- **Rules**: Emerging Threats Open (ET Open) — direct tarball download (version-matched)
- **Integration**: Wazuh Agent (assumed pre-installed; installer patches `ossec.conf`)
- **Service supervision**: systemd unit `suricata.service` (OISF package ships it)
- **Maintenance**: systemd timer `suricata-maintenance.timer` (daily) + logrotate
- **Pipeline**: Suricata → eve.json → Wazuh Agent → Wazuh Manager → SOC Pipeline

## Implementation Steps
1.  **Infrastructure**: Create project directory `suricata-linux/` parallel to `suricata-win/`.
2.  **One-Line Installer**: Develop `install.sh` (bash strict mode) to handle:
    *   Root + distro detection (`/etc/os-release` → Debian/Ubuntu family or RHEL/Fedora/Rocky family).
    *   OISF official repository registration (APT or YUM, signed key).
    *   Install `suricata` + `suricata-update` via native package manager.
    *   Auto-detect physical capture interfaces (excluding Docker/virtual/bond/tunnel).
    *   Patch `/etc/suricata/suricata.yaml` conservatively (only `default-log-dir` + `default-rule-path`).
3.  **ET Open Rules**: Direct tarball download matching installed Suricata version (`https://rules.emergingthreats.net/open/suricata-<ver>/emerging.rules.tar.gz`). `suricata-update` is fragile across distros; tarball is identical.
4.  **Systemd Service**: `systemctl enable --now suricata`. Restart after each rules update.
5.  **Wazuh Binding**: Patch `/var/ossec/etc/ossec.conf` — strip any pre-existing Suricata `<localfile>` block, then insert `<localfile><log_format>json</log_format><location>/var/log/suricata/eve.json</location></localfile>` immediately before `</ossec_config>`. Restart `wazuh-agent`.
6.  **Daily Maintenance Timer**: Drop `suricata-maintenance.service` (Type=oneshot) + `suricata-maintenance.timer` (`OnCalendar=daily`, `*-*-* 03:15:00`, `Persistent=true`). The service invokes `/usr/local/sbin/suricata-maintenance.sh` which:
    *   Re-downloads ET Open tarball (version-matched).
    *   Re-extracts and re-merges rules.
    *   Restarts `suricata.service`.
    *   Rotates `eve.json` if it exceeds `MAX_EVE_BYTES` (default 2 GB), keeping the last 3 archives (`eve.json.1`, `eve.json.2`, `eve.json.3`).
7.  **logrotate**: Drop `/etc/logrotate.d/suricata` with `size 2G`, `rotate 3`, `postrotate` restart of `suricata`.
8.  **Storage Policy**:
    *   **eve.json limit**: 2 GB (`-MaxEveBytes`).
    *   **Rotation**: rename `eve.json` → `eve.json.1`, shift older archives up to `eve.json.<Keep>`, drop beyond.
    *   **Cleanup**: keep 3 archives by default.

## Next Discussion Topic
- Harden the `af-packet` block (custom thread/cluster settings) per environment.