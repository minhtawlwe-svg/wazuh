#!/bin/bash

set -euo pipefail

# =====================================
# Suricata Linux Uninstaller (SOC)
# Reverse of install.sh (Suricata only, Wazuh-safe)
# =====================================

LOG_FILE="/var/log/suricata-uninstall.log"
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
    echo "  - /var/log/suricata logs"
    echo "  - /var/lib/suricata rules + state"
    echo "  - OISF repository (APT or YUM)"
    echo "  - systemd timer (suricata-maintenance.timer)"
    echo "  - logrotate rule (/etc/logrotate.d/suricata)"
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

log "Killing remaining Suricata processes..."
pkill -9 -f suricata || true

# -------------------------------------
# Purge packages
# -------------------------------------
if command -v apt-get >/dev/null 2>&1; then
    if dpkg -l 2>/dev/null | grep -q suricata; then
        log "Purging Suricata packages (apt)..."
        apt-get purge -y suricata suricata-update || true
        apt-get autoremove -y
    fi
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
if command -v add-apt-repository >/dev/null 2>&1; then
    add-apt-repository --remove -y ppa:oisf/suricata-stable 2>/dev/null || true
fi
rm -f /etc/apt/sources.list.d/oisf-suricata-stable.list
rm -f /etc/apt/sources.list.d/oisf-ubuntu-suricata-stable-*.list
rm -f /etc/apt/trusted.gpg.d/oisf*
rm -f /usr/share/keyrings/oisf*
rm -f /etc/yum.repos.d/oisf-suricata.repo
if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y || true
fi

# -------------------------------------
# Strip Suricata <localfile> from ossec.conf (Wazuh binding removal)
# -------------------------------------
if [ -r /var/ossec/etc/ossec.conf ]; then
    log "Checking if ossec.conf needs cleaning..."
    OSSEC_CONF=/var/ossec/etc/ossec.conf
    # Only if eve.json reference actually exists
    if grep -q "eve.json" "$OSSEC_CONF"; then
        log "Stripping Suricata <localfile> from ossec.conf..."
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
            # NOTE: We do NOT restart wazuh-agent here to be safe and avoid service disruption
            log "Binding removed from ossec.conf. User should check and restart wazuh-agent manually if needed."
        else
            log "python3 unavailable — cannot clean ossec.conf automatically."
        fi
    else
        log "ossec.conf binding not found — skip cleaning."
    fi
fi

# -------------------------------------
# Verify removal
# -------------------------------------
if command -v suricata >/dev/null 2>&1; then
    log "[WARNING] suricata binary still on PATH."
fi

log "Suricata Linux uninstall complete."

echo ""
echo "=========================================="
echo "       UNINSTALL COMPLETED"
echo "=========================================="
echo "[SUCCESS] Suricata removed"
echo "[LOG] $LOG_FILE"
echo "=========================================="