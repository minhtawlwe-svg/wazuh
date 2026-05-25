# 🧠 Custom Sysmon Tuned Configuration (SOC Production Ready)

## 🇺🇸 English

This configuration file is a **tuned Sysmon rule set** designed for SOC (Security Operations Center) environments.

It is optimized for:

- Wazuh SIEM
- Graylog
- Splunk
- TheHive
- Incident Response workflows

---

## 🎯 Purpose

The goal of this configuration is to provide:

- Reduced noise compared to full logging configs
- High-value security event visibility
- Better SIEM performance
- Easier threat detection & correlation

---

## ⚙ What This Config Monitors

This tuned Sysmon configuration focuses on:

### 🔹 Process Monitoring
- Process creation (Event ID 1)
- Execution visibility for all applications
- Reduced system noise

### 🔹 Network Monitoring
- Network connections (Event ID 3)
- Excludes common Windows system noise

### 🔹 File Activity
- File creation in:
  - Temp directories
  - Downloads folder
  - AppData (suspicious persistence locations)

### 🔹 Registry Monitoring
- Persistence-related registry keys:
  - Run / RunOnce
  - Services
  - Startup locations

### 🔹 Driver Activity
- Driver loading events (high-risk activity)

### 🔹 Memory / Low-level Access
- Raw access read events (advanced threat detection)

---

## 🧠 SOC Value

This configuration is designed to detect:

- Malware execution
- Persistence mechanisms
- Suspicious network activity
- Lateral movement indicators
- System compromise behavior

---

## ⚖ Comparison with Default Sysmon Config

| Feature | Default (SwiftOnSecurity) | This Config |
|--------|--------------------------|-------------|
| Noise Level | Low | Medium |
| Visibility | Partial | Focused |
| Storage Usage | Optimized | Slightly higher |
| SOC Suitability | Production ready | Tuned production-ready |
| Learning Use | Medium | High |

---

## 🚀 Usage

### 1. Download manually
```powershell
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/yekyawhan/wazuh/main/sysmon/config/custom-sysmon-tuned.xml" -OutFile sysmonconfig.xml
