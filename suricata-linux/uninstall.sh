#!/bin/bash

set -euo pipefail

# =====================================
# Suricata Linux Uninstaller (SOC)
# Reverse of suricata-linux/install.sh
# =====================================

LOG_FILE="/var/log/suricata-uninstall.log"
FORCE_MODE=false
PURGE_WAZUH=0

# -------------------------------------
# Parse arguments
# -------------------------------------
for arg in "$@"; do
    case $arg in
        --force|-f)
            FORCE_MODE=true
            shift
            ;;
        --purge-wazuh)
            PURGE_WAZUH=1
            shift
            ;;
    esac
done

# -------------------------------------
# Logging
# -------------------------------------
log() {
    echo "[$(date '+%F %T')] $1" | tee -a "$LOG_FILE"
}

clear

echo "=========================================="
echo "    SURICATA LINUX UNINSTALLER (SOC)"
echo "=========================================="
echo ""

# -------------------------------------
# Require root
# -------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    echo "[ERROR] Please run as root or sudo"
    exit 1
fi

# -------------------------------------
# Confirm
# -------------------------------------
if [ "$FORCE_MODE" = false ]; then
    echo "[WARNING] This will remove:"
    echo "  - Suricata + suricata-update packages"
    echo "  - /etc/suricata config tree"
    echo "  - /var/log/suricata logs (eve.json + archives)"
    echo "  - /var/lib/suricata rules + state"
    echo "  - OISF repository (APT or YUM)"
    echo "  - systemd timer (suricata-maintenance.timer)"
    echo "  - logrotate rule (/etc/logrotate.d/suricata)"
    echo "  - Wazuh ossec.conf Suricata <localfile> block"
    if [ "$PURGE_WAZUH" -eq 1 ]; then
        echo "  - Wazuh Agent package + /var/ossec  (--purge-wazuh)"
    fi
    echo ""
    read -rp "Type DELETE to continue: " CONFIRM
    if [ "$CONFIRM" != "DELETE" ]; then
        echo "[ABORTED] Uninstall cancelled."
        exit 1
    fi
fi

log "Starting Suricata Linux uninstall..."

# -------------------------------------
# Stop Suricata + maintenance timer
# -------------------------------------
if systemctl list-unit-files suricata-maintenance.timer >/dev/null 2>&1; then
    log "Stopping maintenance timer..."
    systemctl stop suricata-maintenance.timer || true
    systemctl disable suricata-maintenance.timer || true
fi

if systemctl list-unit-files suricata.service >/dev/null 2>&1; then
    log "Stopping Suricata service..."
    systemctl stop suricata || true
    systemctl disable suricata || true
fi

# -------------------------------------
# Kill lingering processes
# -------------------------------------
log "Killing remaining Suricata processes..."
pkill -9 -f suricata || true

# -------------------------------------
# Purge packages (Debian-family)
# -------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    if dpkg -l 2>/dev/null | grep -q suricata; then
        log "Purging Suricata packages (apt)..."
        apt-get purge -y suricata suricata-update || true
        apt-get autoremove -y
    fi
# RHEL-family
elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
    if rpm -q suricata >/dev/null 2>&1; then
        log "Removing Suricata packages (rpm)..."
        (dnf remove -y suricata suricata-update || yum remove -y suricata suricata-update) || true
    fi
fi

# -------------------------------------
# Remove config / state / logs
# -------------------------------------
log "Removing Suricata directories..."
rm -rf /etc/suricata
rm -rf /var/lib/suricata
rm -rf /var/log/suricata
rm -f /var/log/suricata-install.log
rm -f /var/log/suricata-maintenance.log
rm -f /var/log/suricata-uninstall.log

# -------------------------------------
# Remove systemd units + maintenance script
# -------------------------------------
log "Removing systemd units + maintenance script..."
rm -f /etc/systemd/system/suricata-maintenance.service
rm -f /etc/systemd/system/suricata-maintenance.timer
rm -f /usr/local/sbin/suricata-maintenance.sh
systemctl daemon-reload || true

# -------------------------------------
# Remove logrotate rule
# -------------------------------------
log "Removing logrotate rule..."
rm -f /etc/logrotate.d/suricata

# -------------------------------------
# Remove OISF repository
# -------------------------------------
log "Removing OISF repository..."
# Launchpad PPA: add-apt-repository --remove ppa:oisf/suricata-stable (or rm the source list)
if command -v add-apt-repository >/dev/null 2>&1; then
    add-apt-repository --remove -y ppa:oisf/suricata-stable 2>/dev/null || true
fi
rm -f /etc/apt/sources.list.d/oisf-suricata-stable.list
rm -f /etc/apt/sources.list.d/oisf-ubuntu-suricata-stable-*.list
rm -f /etc/apt/trusted.gpg.d/oisf*
rm -f /usr/share/keyrings/oisf*
# EPEL (only if we explicitly added it)
if rpm -q epel-release >/dev/null 2>&1; then
    log "Note: epel-release is installed. Leaving in place (other packages may depend on it)."
fi
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y || true
fi

# -------------------------------------
# Strip Suricata <localfile> from ossec.conf
# -------------------------------------
if [ -r /var/ossec/etc/ossec.conf ]; then
    log "Stripping Suricata <localfile> from ossec.conf..."
    OSSEC_CONF=/var/ossec/etc/ossec.conf
    ts=$(date +%Y%m%d%H%M%S)
    cp -a "$OSSEC_CONF" "${OSSEC_CONF}.${ts}.uninst.bak"
    if command -v python3 >/dev/null 2>&1; then
        tmp=$(mktemp)
        python3 - "$OSSEC_CONF" "$tmp" <<'PY'
import re, sys
src, dst = sys.argv[1], sys.argv[2]
with open(src, 'r', encoding='utf-8') as f:
    content = f.read()
pat = re.compile(r'<localfile>(?:(?!</localfile>).)*?eve\.json(?:(?!</localfile>).)*?</localfile>\s*', re.DOTALL)
new = pat.sub('', content)
with open(dst, 'w', encoding='utf-8') as f:
    f.write(new)
PY
        mv "$tmp" "$OSSEC_CONF"
        if systemctl list-unit-files wazuh-agent.service >/dev/null 2>&1; then
            systemctl restart wazuh-agent || true
        fi
    else
        log "python3 unavailable — leaving ossec.conf untouched."
    fi
fi

# -------------------------------------
# Optional: purge Wazuh agent
# -------------------------------------
if [ "$PURGE_WAZUH" -eq 1 ]; then
    log "Purging Wazuh agent (--purge-wazuh)..."
    if systemctl list-unit-files wazuh-agent.service >/dev/null 2>&1; then
        systemctl stop wazuh-agent || true
        systemctl disable wazuh-agent || true
    fi
    pkill -9 -f wazuh || true
    pkill -9 -f ossec || true
    if command -v apt-get >/dev/null 2>&1; then
        apt-get purge -y wazuh-agent || true
        apt-get autoremove -y
    elif command -v dnf >/dev/null 2>&1 || command -v yum >/dev/null 2>&1; then
        (dnf remove -y wazuh-agent || yum remove -y wazuh-agent) || true
    fi
    rm -rf /var/ossec
    rm -f /etc/apt/sources.list.d/wazuh.list
    rm -f /usr/share/keyrings/wazuh.gpg
fi

# -------------------------------------
# Verify removal
# -------------------------------------
if command -v suricata >/dev/null 2>&1; then
    log "[WARNING] suricata binary still on PATH — check for alternative install."
fi
if [ -d /etc/suricata ] || [ -d /var/lib/suricata ]; then
    log "[WARNING] Some Suricata directories still present."
fi

log "Suricata Linux uninstall complete."

echo ""
echo "=========================================="
echo "       UNINSTALL COMPLETED"
echo "=========================================="
echo "[SUCCESS] Suricata removed"
echo "[LOG] $LOG_FILE"
echo "=========================================="