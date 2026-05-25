#!/bin/bash

WAZUH_MANAGER="<MANAGER_IP>"

echo "=========================================="
echo "   WAZUH AGENT INSTALLER (AUTO MODE)"
echo "=========================================="
echo "[INFO] Manager: $WAZUH_MANAGER"
echo ""

if [ "$EUID" -ne 0 ]; then
    echo "[ERROR] Run as root"
    exit 1
fi

echo "[INPUT] Paste key (CTRL+D to finish):"
AGENT_KEY=$(cat)

if [ -z "$AGENT_KEY" ]; then
    echo "[ERROR] Empty input"
    exit 1
fi

echo ""
echo "[+] Detecting key format..."

# -------------------------------
# AUTO DETECTION LOGIC
# -------------------------------

if echo "$AGENT_KEY" | grep -qE "^0[0-9]{2} "; then

    echo "[INFO] Detected: Wazuh CLIENT KEY (manage_agents format)"
    KEY_TYPE="CLIENT_KEY"

elif echo "$AGENT_KEY" | grep -qE "^[A-Za-z0-9+/=]{40,}$"; then

    echo "[INFO] Detected: Possible encoded/auth key"
    KEY_TYPE="ENCODED_KEY"

else

    echo "[INFO] Unknown format"
    KEY_TYPE="UNKNOWN"

fi

# -------------------------------
# INSTALL WAZUH AGENT
# -------------------------------
echo "[+] Installing Wazuh agent..."

apt-get update -y
apt-get install -y curl gnupg apt-transport-https

curl -fsSL https://packages.wazuh.com/key/GPG-KEY-WAZUH \
| gpg --dearmor -o /usr/share/keyrings/wazuh.gpg

echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
> /etc/apt/sources.list.d/wazuh.list

apt-get update -y
apt-get install -y wazuh-agent

sed -i "s|<address>.*</address>|<address>${WAZUH_MANAGER}</address>|g" \
/var/ossec/etc/ossec.conf

# -------------------------------
# KEY HANDLING LOGIC
# -------------------------------

TMP="/tmp/wazuh.key"
echo "$AGENT_KEY" > "$TMP"

if [ "$KEY_TYPE" = "CLIENT_KEY" ]; then

    echo "[+] Importing via manage_agents -i"
    /var/ossec/bin/manage_agents -i "$TMP"

elif [ "$KEY_TYPE" = "ENCODED_KEY" ]; then

    echo "[WARNING] Key format not compatible with manage_agents -i"
    echo "[INFO] Trying fallback: auth method NOT supported in this script"
    echo "[ERROR] Please use FULL client key from manager (manage_agents -e)"
    exit 1

else

    echo "[ERROR] Unsupported key format"
    exit 1

fi

rm -f "$TMP"

# -------------------------------
# START SERVICE
# -------------------------------
systemctl daemon-reload
systemctl enable wazuh-agent --now
systemctl restart wazuh-agent

echo ""
echo "[SUCCESS] Wazuh Agent Installed"
