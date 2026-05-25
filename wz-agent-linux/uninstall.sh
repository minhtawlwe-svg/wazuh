#!/bin/bash

set -euo pipefail

# =====================================
# Wazuh Linux Agent Uninstaller (SOC)
# =====================================

LOG_FILE="/var/log/wazuh-uninstall.log"
FORCE_MODE=false

# -------------------------------------
# Parse arguments
# -------------------------------------
for arg in "$@"; do
    case $arg in
        --force|-f)
            FORCE_MODE=true
            shift
            ;;
    esac
done

# -------------------------------------
# Logging function
# -------------------------------------
log() {
    echo "[$(date '+%F %T')] $1" | tee -a "$LOG_FILE"
}

clear

echo "=========================================="
echo "    WAZUH AGENT UNINSTALLER (SOC)"
echo "=========================================="
echo ""

# -------------------------------------
# Require root
# -------------------------------------
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root or sudo"
    exit 1
fi

# -------------------------------------
# Check if installed
# -------------------------------------
if ! dpkg -l | grep -q wazuh-agent; then
    echo "[INFO] Wazuh Agent is not installed."
    exit 0
fi

# -------------------------------------
# Confirmation prompt
# -------------------------------------
if [ "$FORCE_MODE" = false ]; then
    echo "[WARNING] This will completely remove:"
    echo "  - Wazuh Agent"
    echo "  - Agent configuration"
    echo "  - Logs"
    echo "  - Keys"
    echo "  - Repository config"
    echo ""

    read -rp "Type DELETE to continue: " CONFIRM

    if [ "$CONFIRM" != "DELETE" ]; then
        echo "[ABORTED] Uninstall cancelled."
        exit 1
    fi
fi

log "Starting Wazuh uninstall..."

# -------------------------------------
# Stop service
# -------------------------------------
if systemctl list-units --full -all | grep -q wazuh-agent; then
    log "Stopping Wazuh Agent service..."
    systemctl stop wazuh-agent || true
    systemctl disable wazuh-agent || true
fi

# -------------------------------------
# Kill lingering processes
# -------------------------------------
log "Killing remaining Wazuh processes..."
pkill -9 -f wazuh || true
pkill -9 -f ossec || true

# -------------------------------------
# Purge package
# -------------------------------------
log "Removing package..."
apt-get purge -y wazuh-agent || true
apt-get autoremove -y

# -------------------------------------
# Remove configs and logs
# -------------------------------------
log "Removing Wazuh directories..."
rm -rf /var/ossec
rm -rf /etc/ossec-init.conf
rm -rf /var/log/wazuh*

# -------------------------------------
# Remove repo
# -------------------------------------
log "Removing repository..."
rm -f /etc/apt/sources.list.d/wazuh.list
rm -f /usr/share/keyrings/wazuh.gpg

apt-get update -y || true

# -------------------------------------
# Cleanup temp files
# -------------------------------------
log "Cleaning temp files..."
rm -f /tmp/wazuh-agent.key

# -------------------------------------
# Verify removal
# -------------------------------------
if dpkg -l | grep -q wazuh-agent; then
    log "[ERROR] Wazuh package still detected!"
    exit 1
fi

log "Wazuh Agent successfully removed."

echo ""
echo "=========================================="
echo "       UNINSTALL COMPLETED"
echo "=========================================="
echo "[SUCCESS] Wazuh Agent removed"
echo "[LOG] $LOG_FILE"
echo "=========================================="
