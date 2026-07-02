#!/bin/bash
# ==============================================================================
# Wazuh YARA Automated Installation, Configuration and Rules Update Script
# AGENT-SIDE installer for Ubuntu/Debian Linux agents.
# Manager-side config lives in yara/manager/ (apply once on the manager).
# Author: Ye Kyaw Han , Hsu Sandy Thein
# ==============================================================================

set -e # Exit immediately if a command exits with a non-zero status

# Where to pull yara_rules.yar from. Override before running if you host the
# rules on a local server, e.g.:  RULES_URL="http://10.3.11.48/rules/yara_rules.yar" ./install.sh
RULES_URL="${RULES_URL:-https://raw.githubusercontent.com/yekyawhan/wazuh/git-home/yara/rule-collection/yara_rules.yar}"

# ==============================================================================
# Setup Logging
# ==============================================================================
LOG_FILE="/var/log/yara-install.log"
exec > >(tee -a "$LOG_FILE") 2>&1

echo "[$(date)] Starting YARA automated setup script..."

# Check if script is run as root
if [ "$EUID" -ne 0 ]; then
    echo "[-] Please run this script as root (sudo)."
    exit 1
fi

echo "[*] Updating apt repositories and installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update
# 'jq' is required by the Active Response script
apt-get install -y make gcc autoconf libtool libssl-dev pkg-config jq curl wget

# Check if YARA is already installed to prevent re-compiling on subsequent runs
if ! command -v yara &> /dev/null; then
    echo "[*] YARA not found. Downloading and compiling from source..."
    mkdir -p /usr/local/src && cd /usr/local/src/
    curl -LO https://github.com/VirusTotal/yara/archive/v4.5.5.tar.gz
    tar -xzf v4.5.5.tar.gz
    rm -f v4.5.5.tar.gz

    cd yara-4.5.5/
    ./bootstrap.sh
    ./configure
    make
    make install

    echo "[*] Applying shared library fix (ldconfig)..."
    if ! grep -q "/usr/local/lib" /etc/ld.so.conf; then
        echo "/usr/local/lib" >> /etc/ld.so.conf
    fi
    ldconfig
else
    echo "[+] YARA is already installed. Skipping compilation."
fi

echo "[*] Downloading initial YARA rules from: $RULES_URL"
RULES_DIR="/var/ossec/yara/rules"
mkdir -p "$RULES_DIR"
curl -fsSL "$RULES_URL" -o "$RULES_DIR/yara_rules.yar"

echo "[*] Validating downloaded rules compile..."
yara -w "$RULES_DIR/yara_rules.yar" /dev/null > /dev/null
echo "[+] Rules compile OK."

echo "[*] Creating Wazuh Active Response script (/var/ossec/active-response/bin/yara.sh)..."
mkdir -p /var/ossec/active-response/bin/

# Use 'EOF' to prevent bash from evaluating variables during script creation
cat << 'EOF' > /var/ossec/active-response/bin/yara.sh
#!/bin/bash
# Wazuh - Yara active response
# Copyright (C) 2015-2022, Wazuh Inc.

#------------------------- Gather parameters -------------------------#
read INPUT_JSON
YARA_PATH=$(echo $INPUT_JSON | jq -r .parameters.extra_args[1])
YARA_RULES=$(echo $INPUT_JSON | jq -r .parameters.extra_args[3])
FILENAME=$(echo $INPUT_JSON | jq -r .parameters.alert.syscheck.path)

# Set LOG_FILE path and QUARANTINE_DIR
LOG_FILE="/var/ossec/logs/active-responses.log"
QUARANTINE_DIR="/var/ossec/active-response/quarantine"

size=0
actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo 0)
while [ "${size}" -ne "${actual_size}" ]; do
  sleep 1
  size=${actual_size}
  actual_size=$(stat -c %s "${FILENAME}" 2>/dev/null || echo 0)
done

#----------------------- Analyze parameters -----------------------#
if [[ ! $YARA_PATH ]] || [[ ! $YARA_RULES ]]; then
  echo "wazuh-yara: ERROR - Yara active response error. Yara path and rules parameters are mandatory." >> ${LOG_FILE}
  exit 1
fi

#------------------------- Main workflow --------------------------#
# Never scan or quarantine inside our own quarantine directory (loop guard)
case "${FILENAME}" in
  ${QUARANTINE_DIR}/*) exit 0 ;;
esac

# Execute Yara scan on the specified filename (Check if file still exists)
if [ -f "${FILENAME}" ]; then
  yara_output="$("${YARA_PATH}"/yara -w -r "$YARA_RULES" "$FILENAME")"
  if [[ $yara_output != "" ]]; then
    # Iterate every detected rule and append it to the LOG_FILE
    while read -r line; do
      echo "wazuh-yara: INFO - Scan result: $line" >> ${LOG_FILE}
    done <<< "$yara_output"

    # ------------------ QUARANTINE ------------------#
    mkdir -p ${QUARANTINE_DIR}
    BASENAME=$(basename "$FILENAME")
    mv "$FILENAME" "${QUARANTINE_DIR}/${BASENAME}"
    chmod 000 "${QUARANTINE_DIR}/${BASENAME}"
    echo "wazuh-yara: ACTION - File quarantined: ${QUARANTINE_DIR}/${BASENAME}" >> ${LOG_FILE}
  fi
fi
exit 0;
EOF

echo "[*] Setting correct permissions for Wazuh Active Response..."
chmod 750 /var/ossec/active-response/bin/yara.sh
chown root:wazuh /var/ossec/active-response/bin/yara.sh
mkdir -p /var/ossec/active-response/quarantine
chmod 750 /var/ossec/active-response/quarantine
chown root:wazuh /var/ossec/active-response/quarantine

echo "[*] Ensuring FIM realtime monitoring of /tmp,/media,/root in agent ossec.conf..."
OSSEC_CONF="/var/ossec/etc/ossec.conf"
if ! grep -q 'realtime="yes">/tmp,/media,/root' "$OSSEC_CONF"; then
    cp "$OSSEC_CONF" "${OSSEC_CONF}.bak.$(date +%s)"
    sed -i '0,\|</syscheck>|s||  <directories realtime="yes">/tmp,/media,/root</directories>\n</syscheck>|' "$OSSEC_CONF"
    echo "[+] FIM directories added (backup of ossec.conf saved)."
else
    echo "[+] FIM directories already configured."
fi

echo "[*] Setting up YARA rules auto-update script and Weekly Cronjob..."
cat << EOF > /usr/local/bin/update-yara-rules.sh
#!/bin/bash
# Script to update YARA rules
RULES_DIR="/var/ossec/yara/rules"
mkdir -p "\$RULES_DIR"

echo "[\$(date)] Updating YARA rules..." >> /var/log/yara-update.log

if curl -fsSL "$RULES_URL" -o "\$RULES_DIR/yara_rules.yar.new" && yara -w "\$RULES_DIR/yara_rules.yar.new" /dev/null > /dev/null 2>&1; then
    mv "\$RULES_DIR/yara_rules.yar.new" "\$RULES_DIR/yara_rules.yar"
    echo "[\$(date)] Restarting Wazuh agent..." >> /var/log/yara-update.log
    systemctl restart wazuh-agent
    echo "[\$(date)] YARA rules updated and agent restarted successfully." >> /var/log/yara-update.log
else
    rm -f "\$RULES_DIR/yara_rules.yar.new"
    echo "[\$(date)] ERROR: rules download or compile check failed; keeping old rules." >> /var/log/yara-update.log
fi
EOF

chmod +x /usr/local/bin/update-yara-rules.sh

# Add cron job to update automatically at 11:30 PM every Sunday (Weekly)
(crontab -l 2>/dev/null | grep -v "/usr/local/bin/update-yara-rules.sh" ; echo "30 23 * * 0 /usr/local/bin/update-yara-rules.sh") | crontab -

# Add cron job to clean up quarantine directory (files older than 30 days) daily at 1:00 AM
(crontab -l 2>/dev/null | grep -v "/var/ossec/active-response/quarantine" ; echo "0 1 * * * find /var/ossec/active-response/quarantine -type f -mtime +30 -delete") | crontab -

echo "[*] Restarting Wazuh agent to apply FIM config..."
systemctl restart wazuh-agent || echo "[-] wazuh-agent restart failed (is the agent installed?)"

echo "[+] Local YARA installation, Active Response, Quarantine Cleanup and Auto-Update configured successfully!"
echo "[!] REMINDER: apply yara/manager/*.xml on the Wazuh MANAGER (decoders, rules 100300/100301/108000-108002, and the yara_linux AR command) and restart wazuh-manager, or nothing will trigger."
