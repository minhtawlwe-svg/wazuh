#!/bin/bash

set -e

WAZUH_MANAGER="<MANAGER_IP>"

clear

echo "=========================================="
echo "     WAZUH AGENT INSTALLER (PROD)"
echo "=========================================="
echo ""
echo "[INFO] Wazuh Manager: ${WAZUH_MANAGER}"
echo ""

# -------------------------------
# Require root
# -------------------------------
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Please run as root"
    exit 1
fi

# -------------------------------
# Ask for agent key
# -------------------------------
while true; do
    echo "Paste Wazuh pre-generated agent key"
    echo "When finished press CTRL+D"
    echo "-----------------------------------"

    AGENT_KEY=$(cat)

    if [ -n "$AGENT_KEY" ]; then
        break
    fi

    echo ""
    echo "[WARNING] Agent key cannot be empty"
    echo ""
done

echo ""
echo "[+] Agent key received"
echo ""

# -------------------------------
# Install dependencies
# -------------------------------
echo "[+] Installing dependencies..."
apt-get update -y
apt-get install -y curl gnupg apt-transport-https

# -------------------------------
# Add repo securely
# -------------------------------
echo "[+] Adding Wazuh repository..."

curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
| gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
> /etc/apt/sources.list.d/wazuh.list

apt-get update -y

# -------------------------------
# Install Wazuh Agent
# -------------------------------
echo "[+] Installing Wazuh Agent..."
apt-get install -y wazuh-agent

# -------------------------------
# Configure manager
# -------------------------------
echo "[+] Configuring manager IP..."

sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|g" \
/var/ossec/etc/ossec.conf

# -------------------------------
# Import Agent Key
# -------------------------------
echo "[+] Importing agent key..."

TMP_KEY_FILE="/tmp/wazuh-agent.key"

echo "$AGENT_KEY" > "$TMP_KEY_FILE"

/var/ossec/bin/manage_agents -i "$TMP_KEY_FILE"

rm -f "$TMP_KEY_FILE"

# -------------------------------
# Enable/start service
# -------------------------------
echo "[+] Starting service..."

systemctl daemon-reload
systemctl enable wazuh-agent --now
systemctl restart wazuh-agent

sleep 3

# -------------------------------
# Verify
# -------------------------------
echo ""
echo "[+] Checking service status..."
systemctl --no-pager --full status wazuh-agent

echo ""
echo "=========================================="
echo "[SUCCESS] Wazuh Agent Installed"
echo "[INFO] Manager: ${WAZUH_MANAGER}"
echo "=========================================="
