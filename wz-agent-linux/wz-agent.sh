#!/bin/bash

WAZUH_MANAGER="<MANAGER_IP>"

echo "=========================================="
echo "     WAZUH AGENT INSTALLER (SOC)"
echo "=========================================="
echo ""
echo "[INFO] Manager: $WAZUH_MANAGER"
echo ""

# ----------------------------
# MUST RUN AS ROOT
# ----------------------------
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run as root"
    exit 1
fi

# ----------------------------
# SIMPLE SINGLE-LINE KEY INPUT (NO CTRL+D)
# ----------------------------
read -rp "👉 Paste Wazuh Agent Key: " AGENT_KEY

if [ -z "$AGENT_KEY" ]; then
    echo "[ERROR] Key cannot be empty"
    exit 1
fi

echo ""
echo "[+] Key received, continuing installation..."
echo ""

# ----------------------------
# INSTALL DEPENDENCIES
# ----------------------------
apt-get update -y
apt-get install -y curl gnupg apt-transport-https

# ----------------------------
# ADD WAZUH REPO
# ----------------------------
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
| gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
> /etc/apt/sources.list.d/wazuh.list

apt-get update -y
apt-get install -y wazuh-agent

# ----------------------------
# CONFIG MANAGER
# ----------------------------
sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|g" \
/var/ossec/etc/ossec.conf

# ----------------------------
# IMPORT KEY (REAL FIX)
# ----------------------------
TMP_FILE="/tmp/wazuh-agent.key"
echo "$AGENT_KEY" > "$TMP_FILE"

/var/ossec/bin/manage_agents -i "$TMP_FILE"

rm -f "$TMP_FILE"

# ----------------------------
# START SERVICE
# ----------------------------
systemctl daemon-reload
systemctl enable wazuh-agent --now
systemctl restart wazuh-agent

echo ""
echo "=========================================="
echo "[SUCCESS] Wazuh Agent Installed"
echo "=========================================="
