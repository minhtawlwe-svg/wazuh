#!/bin/bash

set -e

# ==============================
# Wazuh Agent Installer (SOC)
# ==============================

WAZUH_MANAGER="<MANAGER_IP>"

clear

echo "=========================================="
echo "     WAZUH AGENT INSTALLER (SOC)"
echo "=========================================="
echo ""
echo "[INFO] Manager: $WAZUH_MANAGER"
echo ""

# -----------------------------
# Require root
# -----------------------------
if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run as root"
    exit 1
fi

# -----------------------------
# KEY INPUT (simple)
# -----------------------------
read -rp "👉 Paste Wazuh Agent Key: " AGENT_KEY

if [ -z "$AGENT_KEY" ]; then
    echo "[ERROR] Key cannot be empty"
    exit 1
fi

echo ""
echo "[+] Key received, continuing installation..."
echo ""

# =============================
# FIX 1: SAFE GPG HANDLING
# =============================
echo "[+] Setting up Wazuh repository key..."

mkdir -p /usr/share/keyrings

if [ ! -f /usr/share/keyrings/wazuh.gpg ]; then
    curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
    | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
else
    echo "[INFO] GPG key already exists, skipping..."
fi

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
> /etc/apt/sources.list.d/wazuh.list

# =============================
# INSTALL AGENT
# =============================
echo "[+] Installing Wazuh Agent..."

apt-get update -y
apt-get install -y wazuh-agent

# =============================
# CONFIG MANAGER
# =============================
echo "[+] Configuring manager..."

sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|g" \
/var/ossec/etc/ossec.conf

# =============================
# IMPORT KEY (manage_agents -i)
# =============================
echo "[+] Importing agent key..."

TMP_FILE="/tmp/wazuh_agent.key"

echo "$AGENT_KEY" > "$TMP_FILE"

/var/ossec/bin/manage_agents -i "$TMP_FILE"

rm -f "$TMP_FILE"

# =============================
# START SERVICE
# =============================
echo "[+] Starting Wazuh Agent..."

systemctl daemon-reload
systemctl enable wazuh-agent --now
systemctl restart wazuh-agent

sleep 2

# =============================
# VERIFY
# =============================
echo ""
echo "[+] Checking status..."

if systemctl is-active --quiet wazuh-agent; then
    echo "[SUCCESS] Wazuh Agent is RUNNING"
else
    echo "[ERROR] Agent failed to start"
    exit 1
fi

echo ""
echo "=========================================="
echo "[DONE] Installation completed successfully"
echo "=========================================="
