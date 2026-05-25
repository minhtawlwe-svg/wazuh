#!/bin/bash

# =========================
# Wazuh Agent Installer
# SOC Production Grade
# =========================

WAZUH_MANAGER="<MANAGER_IP>"

echo "====================================="
echo "     WAZUH AGENT INSTALLER (SOC)"
echo "====================================="
echo ""

# -------------------------
# Show manager info FIRST
# -------------------------
echo "[INFO] Wazuh Manager: ${WAZUH_MANAGER}"
echo ""

# -------------------------
# Ask key with retry loop
# -------------------------
WAZUH_KEY=""

while [ -z "$WAZUH_KEY" ]; do
    read -sp "👉 Enter Wazuh Agent Key (required): " WAZUH_KEY
    echo ""

    if [ -z "$WAZUH_KEY" ]; then
        echo "[WARNING] Key cannot be empty. Try again..."
        echo ""
    fi
done

echo ""
echo "[+] Key received. Starting installation..."
echo ""

# -------------------------
# Install prerequisites
# -------------------------
echo "[+] Installing prerequisites..."
apt-get update -y
apt-get install -y gnupg apt-transport-https curl lsb-release

# -------------------------
# Add Wazuh repo (secure method)
# -------------------------
echo "[+] Adding Wazuh GPG key..."
curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
| gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

echo "[+] Adding Wazuh repository..."
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
| tee /etc/apt/sources.list.d/wazuh.list

# -------------------------
# Install agent
# -------------------------
echo "[+] Installing Wazuh agent..."
apt-get update -y
apt-get install -y wazuh-agent

# -------------------------
# Configure manager
# -------------------------
echo "[+] Configuring manager IP..."
sed -i "s/<address>.*<\/address>/<address>${WAZUH_MANAGER}<\/address>/g" /var/ossec/etc/ossec.conf

# -------------------------
# Register key
# -------------------------
echo "[+] Registering agent key..."
echo "$WAZUH_KEY" > /var/ossec/etc/authd.pass

# -------------------------
# Enable service
# -------------------------
echo "[+] Enabling and starting service..."
systemctl daemon-reexec
systemctl daemon-reload
systemctl enable wazuh-agent --now

systemctl restart wazuh-agent

# -------------------------
# Verification
# -------------------------
echo ""
echo "[+] Checking service status..."
systemctl status wazuh-agent --no-pager

echo ""
echo "[SUCCESS] Wazuh Agent deployed successfully"
