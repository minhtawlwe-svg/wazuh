#!/bin/bash
# ==============================================================================
# Wazuh YARA Automated Installation, Configuration and Rules Update Script
# PULLS RULES FROM LOCAL REPO (10.3.11.48)
# Compatible for Ubuntu/Debian VMs
# Author: Ye Kyaw Han , Hsu Sandy Thein
# ==============================================================================

set -e # Exit immediately if a command exits with a non-zero status

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
# Added 'jq' as it is required by the Active Response script
apt-get install -y make gcc autoconf libtool libssl-dev pkg-config jq curl wget

# Check if YARA is already installed to prevent re-compiling on subsequent runs
if ! command -v yara &> /dev/null; then
    echo "[*] YARA not found. Downloading and compiling from source..."
    cd /usr/local/bin/
    curl -LO https://github.com/VirusTotal/yara/archive/v4.5.5.tar.gz
    tar -xvzf v4.5.5.tar.gz
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

echo "[*] Downloading initial YARA rules from LOCAL SERVER (10.3.11.48)..."
RULES_DIR="/var/ossec/yara/rules"
mkdir -p "$RULES_DIR"

# Pull from Local Server instead of Internet
curl -sL "https://github.com/yekyawhan/wazuh/tree/git-home/yara/rulle-collection" -o "$RULES_DIR"

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

echo "[*] Setting up YARA rules auto-update script (Pulling from 10.3.11.48) and Weekly Cronjob..."
cat << 'EOF' > /usr/local/bin/update-yara-rules.sh
#!/bin/bash
# Script to update YARA rules from LOCAL SERVER (10.3.11.48)
RULES_DIR="/var/ossec/yara/rules"
mkdir -p "$RULES_DIR"

echo "[$(date)] Updating YARA rules from local server..." >> /var/log/yara-update.log

curl -sL "http://10.3.11.48/rules/yara_rules.yar" -o "$RULES_DIR/yara_rules.yar"

# Restart Wazuh Agent to properly load new rules into memory
echo "[$(date)] Restarting Wazuh agent..." >> /var/log/yara-update.log
systemctl restart wazuh-agent
echo "[$(date)] YARA rules updated and agent restarted successfully." >> /var/log/yara-update.log
EOF

chmod +x /usr/local/bin/update-yara-rules.sh

# Add cron job to update automatically at 11:30 PM every Sunday (Weekly)
(crontab -l 2>/dev/null | grep -v "/usr/local/bin/update-yara-rules.sh" ; echo "30 23 * * 0 /usr/local/bin/update-yara-rules.sh") | crontab -

# Add cron job to clean up quarantine directory (files older than 30 days) daily at 1:00 AM
(crontab -l 2>/dev/null | grep -v "/var/ossec/active-response/quarantine" ; echo "0 1 * * * find /var/ossec/active-response/quarantine -type f -mtime +30 -delete") | crontab -

echo "[+] Local YARA installation, Active Response, Quarantine Cleanup and Auto-Update configured successfully!"
