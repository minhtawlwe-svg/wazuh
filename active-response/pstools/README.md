# Wazuh Active Response with PsTools Deployment (Windows)

This repository contains scripts to automate the deployment and configuration of Wazuh Active Response using Sysinternals PsTools on Windows agents.

## 🚀 One-Liner Installation
Run the following command in **PowerShell (Run as Administrator)** to deploy everything automatically:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $branch="git-home"; $url="https://raw.githubusercontent.com/yekyawhan/wazuh/$branch/active-response/pstools/deploy-ar.ps1"; Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\deploy-ar.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\deploy-ar.ps1"
```

## 📋 What this script does:
1. Installs **PowerShell 7** (if not present).
2. Downloads and extracts **Sysinternals PsTools** to `C:\Program Files\Sysinternals`.
3. Deploys custom AR scripts to the Wazuh Agent directory.
4. Verifies the installation and restarts the Wazuh Agent service.

## 🛠️ Step-by-Step Configuration (Manual)

After running the deployment script, you need to configure your **Wazuh Manager** (or individual agent `ossec.conf`) to trigger the Active Response.

### 1. Add Command to Wazuh Manager Configuration
Add the following command blocks to your manager's configuration to define the scripts:

```xml
<command>
  <name>pssuspend</name>
  <executable>pssuspend.cmd</executable>
  <timeout_allowed>yes</timeout_allowed>
</command>

<command>
  <name>get-forensics</name>
  <executable>get-forensics.cmd</executable>
  <timeout_allowed>no</timeout_allowed>
</command>
```

### 2. Add Active Response Trigger
Define when these commands should be executed based on alert IDs or groups:

```xml
<active-response>
  <command>pssuspend</command>
  <location>local</location>
  <rules_id>100001</rules_id> <!-- Replace with your specific Rule ID -->
</active-response>

<active-response>
  <command>get-forensics</command>
  <location>local</location>
  <rules_id>100002</rules_id> <!-- Replace with your specific Rule ID -->
</active-response>
```

### 3. File Locations on Agent
- **Scripts:** `C:\Program Files (x86)\ossec-agent\active-response\bin\`
- **PsTools:** `C:\Program Files\Sysinternals\`

---
*Maintained by Ko Ye*
