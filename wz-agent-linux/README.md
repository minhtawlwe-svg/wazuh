# 🚀 Wazuh Linux Agent Auto Installer (SOC Production)

This repository provides an **interactive Linux installer script** for deploying Wazuh Agents in SOC / EDR environments.

It supports:
- Interactive key input (secure enrollment)
- Automatic Wazuh Manager configuration
- Retry-safe installation flow
- Official Wazuh repository setup
- Systemd service enablement
- Production-ready deployment structure

---

## ⚙️ Requirements

- Ubuntu / Debian Linux (tested)
- Root or sudo privileges
- Network access to Wazuh Manager

---

## 🌐 Default Configuration

- Wazuh Manager: `<MANAGER_IP>`
- Installation Mode: Interactive (key prompt)
- Package Source: Wazuh official repository (4.x)

---

## 🚀 One-Line Installation (Recommended)

Run this command on target Linux endpoint:

```bash
curl -fsSL https://github.com/yekyawhan/wazuh/raw/refs/heads/git-home/wz-agent-linux/wz-agent.sh | bash
```
## Uninstall script 
```bash
curl -fsSL https://github.com/yekyawhan/wazuh/raw/refs/heads/git-home/wz-agent-linux/uninstall.sh | sudo bash -s -- --force
```
