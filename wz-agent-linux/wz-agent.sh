#!/bin/bash

set -euo pipefail

WAZUH_MANAGER="<MANAGER_IP>"

clear

echo "=========================================="
echo "     WAZUH AGENT INSTALLER (SOC)"
echo "=========================================="
echo ""
echo "[INFO] Manager: ${WAZUH_MANAGER}"
echo ""

# -----------------------------
# Require root
# -----------------------------
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run as root or sudo"
    exit 1
fi

# -----------------------------
# Ask for agent key
# -----------------------------
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

# -----------------------------
# Install dependencies
# -----------------------------
echo "[+] Installing dependencies..."

apt-get update -y
apt-get install -y \
    curl \
    gnupg \
    apt-transport-https \
    expect

# -----------------------------
# Setup repo (safe GPG)
# -----------------------------
echo "[+] Setting up Wazuh repository..."

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

# -----------------------------
# Install agent
# -----------------------------
echo "[+] Installing Wazuh Agent..."

apt-get update -y
apt-get install -y wazuh-agent

# -----------------------------
# Configure manager
# -----------------------------
echo "[+] Configuring manager..."

sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|g" \
/var/ossec/etc/ossec.conf

# -----------------------------
# Import key (AUTO-CONFIRM)
# -----------------------------
echo "[+] Importing agent key..."

expect <<EOF
set timeout 20

spawn /var/ossec/bin/manage_agents

expect "Choose your action:*"
send "i\r"

expect "Paste it here*"
send "$AGENT_KEY\r"

expect "Confirm adding it?(y/n):"
send "y\r"

expect "Added."

expect eof
EOF

echo "[+] Agent key imported successfully"

# -----------------------------
# Start service
# -----------------------------
echo "[+] Starting Wazuh Agent..."

systemctl daemon-reload
systemctl enable wazuh-agent --now
systemctl restart wazuh-agent

sleep 5

# -----------------------------
# Verify
# -----------------------------
echo ""
echo "[+] Checking service status..."

if systemctl is-active --quiet wazuh-agent; then
    echo "[SUCCESS] Wazuh Agent is RUNNING"
else
    echo "[ERROR] Wazuh Agent failed to start"
    exit 1
fi

echo ""
echo "[INFO] Checking manager connectivity..."
tail -n 20 /var/ossec/logs/ossec.log | grep -Ei "Connected|connected|server|agent" || true

echo ""
echo "=========================================="
echo "[DONE] Installation completed successfully"
echo "=========================================="
echo "[INFO] Manager: ${WAZUH_MANAGER}"
echo "[INFO] Wait ~10–60 seconds for dashboard visibility"
echo "=========================================="
