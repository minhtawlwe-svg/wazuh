# 🚀 Wazuh Windows Agent - Production Deployment Script

This repository provides an automated PowerShell script to install and configure the **Wazuh Agent on Windows endpoints** in a SOC/EDR environment.

It supports:
- Latest Wazuh Agent installation
- Silent deployment
- Centralized Wazuh Manager configuration
- Logging for audit & troubleshooting
- Optional force reinstall mode

---

## ⚙️ Requirements

- Windows 10 / Windows Server 2016+
- PowerShell 5.1+
- Administrator privileges
- Network access to Wazuh Manager

---

## 🌐 Default Configuration

- Wazuh Manager IP: `192.168.0.10`
- Installation Mode: Silent (`/qn`)
- MSI Source: Wazuh official repository (4.x latest)

---

## 📥 Installation Methods

### 🔥 1. One-Line Installation (Recommended)

### Run this in **PowerShell (Admin)**:

```powershell
iwr -useb https://github.com/yekyawhan/wazuh/raw/refs/heads/git-home/wz-agent-windows/production-wz-agent-install.ps1 | iex
