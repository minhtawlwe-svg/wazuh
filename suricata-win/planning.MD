# Suricata-Wazuh Integration Planning (Windows)

## Goal
Automated Suricata deployment on Windows with auto-detection of physical interfaces, daily rule updates via ET Open, and seamless Wazuh log integration.

## Architecture
- **Detector**: Suricata 7.0.x (Windows binary)
- **Rules**: Emerging Threats Open (ET Open) - updated via suricata-update
- **Integration**: Wazuh Agent (log monitoring `eve.json`)
- **Pipeline**: Suricata → Wazuh Agent → Wazuh Manager → SOC Pipeline

## Implementation Steps
1.  **Infrastructure**: Create project directory `/home/y3kh/.claude/my-project/wazuh/suricata-win`.
2.  **One-Line Automator**: Develop `Install-Suricata-Full-Auto.ps1` to handle:
    *   Auto-detection of physical network interfaces (excluding Docker/virtual ones).
    *   Installation of Npcap, Suricata, and `suricata-update`.
    *   Automated configuration of `suricata.yaml`.
3.  **Wazuh Binding**: The automator script will automatically append the `eve.json` monitoring block to the Wazuh agent's `ossec.conf`.
4.  **Daily Maintenance**: The automator will create a Task Scheduler job to run daily for:
    *   Updating ET Open rules.
    *   Restarting the Suricata process to apply new rules.
5.  **Storage Policy**: Implement a log rotation and cleanup strategy for `eve.json`.
    *   **Limit**: Set a maximum log size of **2GB**.
    *   **Action**: When the limit is reached, rotate the log file (e.g., rename `eve.json` to `eve.json.1`) and restart Suricata to create a new log.
    *   **Cleanup**: Keep a maximum of 2-3 archived logs (`eve.json.1`, `eve.json.2`) and delete older ones.

## Next Discussion Topic
- Finalize the PowerShell script for the log rotation/cleanup mechanism.
