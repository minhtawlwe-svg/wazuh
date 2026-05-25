#!/bin/bash

set -e

# =====================================
# Wazuh Linux Agent Installer (PROD)
# =====================================

WAZUH_MANAGER="<MANAGER_IP>"

clear

echo "=========================================="
echo "     WAZUH AGENT INSTALLER (PROD)"
echo "=========================================="
echo ""
echo "[INFO] Wazuh Manager: ${WAZUH_MANAGER}"
echo ""

# -------------------------------------
# Require root
# -------------------------------------
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root or sudo"
    exit 1
fi

# -------------------------------------
# Ask for pre-generated agent key
# -------------------------------------
while true; do
    read -rp "👉 Paste Wazuh Agent Key: " AGENT_KEY

    if [ -n "$AGENT_KEY" ]; then
        break
    fi

    echo "[WARNING] Agent key cannot be empty"
done

echo ""
echo "[+] Agent key received"
echo ""

# -------------------------------------
# Install dependencies
# -------------------------------------
echo "[+] Installing dependencies..."
apt-get update -y
apt-get install -y curl gnupg apt-transport-https

# -------------------------------------
# Add Wazuh GPG key
# -------------------------------------
echo "[+] Adding Wazuh GPG key..."

mkdir -p /usr/share/keyrings

curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
| gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

# -------------------------------------
# Add Wazuh repository
# -------------------------------------
echo "[+] Adding Wazuh repository..."

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
> /etc/apt/sources.list.d/wazuh.list

# -------------------------------------
# Install Wazuh agent
# -------------------------------------
echo "[+] Installing Wazuh Agent..."

apt-get update -y
apt-get install -y wazuh-agent

# -------------------------------------
# Configure manager IP
# -------------------------------------
echo "[+] Configuring manager IP..."

sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|g" \
/var/ossec/etc/ossec.conf

# -------------------------------------
# Import pre-generated key
# -------------------------------------
echo "[+] Importing agent key..."

TMP_KEY_FILE="/tmp/wazuh-agent.key"

echo "$AGENT_KEY" > "$TMP_KEY_FILE"

/var/ossec/bin/manage_agents -i "$TMP_KEY_FILE"

rm -f "$TMP_KEY_FILE"

# -------------------------------------
# Enable & start service
# -------------------------------------
echo "[+] Starting Wazuh Agent..."

systemctl daemon-reload
systemctl enable wazuh-agent --now
systemctl restart wazuh-agent

sleep 3

# -------------------------------------
# Verify service
# -------------------------------------
echo ""
echo "[+] Checking service status..."

if systemctl is-active --quiet wazuh-agent; then
    echo "[SUCCESS] Wazuh Agent is running"
else
    echo "[ERROR] Wazuh Agent failed to start"
    exit 1
fi

echo ""
echo "=========================================="
echo "       INSTALLATION COMPLETED"
echo "=========================================="
echo "[INFO] Manager : ${WAZUH_MANAGER}"
echo "[INFO] Service : wazuh-agent"
echo "[SUCCESS] Agent installed successfully"
echo "=========================================="
