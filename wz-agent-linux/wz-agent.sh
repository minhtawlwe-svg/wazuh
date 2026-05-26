#!/bin/bash

set -e

WAZUH_MANAGER="<MANAGER_IP>"

clear

echo "=========================================="
echo "     WAZUH AGENT INSTALLER (SOC)"
echo "=========================================="
echo ""
echo "[INFO] Manager: $WAZUH_MANAGER"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run as root"
    exit 1
fi

# --------------------------------
# Ask agent key
# --------------------------------
while true; do
    read -rp "👉 Paste Wazuh Agent Key: " AGENT_KEY

    if [ -n "$AGENT_KEY" ]; then
        break
    fi

    echo "[WARNING] Agent key cannot be empty"
done

echo ""
echo "[+] Key received, continuing installation..."
echo ""

# --------------------------------
# Setup repo (GPG-safe)
# --------------------------------
echo "[+] Setting up Wazuh repository key..."

mkdir -p /usr/share/keyrings

if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
else
    echo "[INFO] GPG key already exists, skipping..."
fi

cat > /etc/apt/sources.list.d/wazuh.list <<EOF
deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main
EOF

# --------------------------------
# Install agent
# --------------------------------
echo "[+] Installing Wazuh Agent..."

apt-get update -y
apt-get install -y wazuh-agent

# --------------------------------
# Configure manager
# --------------------------------
echo "[+] Configuring manager..."

sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|g" \
/var/ossec/etc/ossec.conf

# --------------------------------
# Import key (FIXED)
# --------------------------------
echo "[+] Importing agent key..."

printf '%s\n' "$AGENT_KEY" | /var/ossec/bin/manage_agents -i

echo ""
echo "[+] Agent key imported"

# --------------------------------
# Start service
# --------------------------------
echo "[+] Starting Wazuh Agent..."

systemctl daemon-reload
systemctl enable wazuh-agent --now
systemctl restart wazuh-agent

sleep 3

# --------------------------------
# Verify
# --------------------------------
echo ""
echo "[+] Checking status..."

if systemctl is-active --quiet wazuh-agent; then
    echo "[SUCCESS] Wazuh Agent is RUNNING"
else
    echo "[ERROR] Wazuh Agent failed to start"
    exit 1
fi

echo ""
echo "=========================================="
echo "[DONE] Installation completed successfully"
echo "=========================================="
