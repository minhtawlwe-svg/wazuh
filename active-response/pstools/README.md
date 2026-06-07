# Wazuh Active Response with PsTools Deployment (Windows)

This repository contains scripts to automate the deployment and configuration of Wazuh Active Response using Sysinternals PsTools on Windows agents.

## 🚀 One-Liner Installation
Run the following command in **PowerShell (Run as Administrator)** to deploy everything automatically:

```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; $branch="git-home"; $url="https://raw.githubusercontent.com/yekyawhan/wazuh/$branch/active-response/pstools/deploy-ar.ps1"; Invoke-WebRequest -Uri $url -OutFile "$env:TEMP\deploy-ar.ps1"; powershell -ExecutionPolicy Bypass -File "$env:TEMP\deploy-ar.ps1"
```

## 📋 What this script does:
1. **Verifies Administrator Privileges:** Prevents permission errors by making sure the script runs as Admin.
2. **Upgrades/Installs PowerShell 7:** Checks for `pwsh` and installs PowerShell v7.6.2 (MSI) silently if missing.
3. **Creates System Folders:** 
   - Generates `C:\Program Files\Sysinternals` (for security tools and PowerShell scripts).
   - Generates `C:\Program Files (x86)\ossec-agent\active-response\bin` (if it does not exist on the agent).
4. **Installs Sysinternals PsTools:** Downloads the official `PSTools.zip` from Microsoft, extracts all utility executables (like `PsSuspend64.exe`) directly into the `Sysinternals` directory, and cleans up the temporary zip file.
5. **Downloads Active Response Wrapper Scripts:** 
   - Places wrapper batch files (`pssuspend.cmd`, `get-forensics.cmd`) into Wazuh's Active Response `bin` folder.
   - Places core PowerShell logic scripts (`pssuspend_v2.ps1`, `ps-forensics.ps1`) into the `C:\Program Files\Sysinternals` folder for better centralization and security.
6. **Performs File Integrity Check:** Verifies all 5 required files are successfully downloaded and placed in the correct directories before continuing.
7. **Restarts Wazuh Agent Service:** Detects the service names (`Wazuh` or `WazuhAgent`), restarts it cleanly, and falls back to restarting via the executable if the service database is not accessible.

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
- **Active Response Wrapper Cmds:** `C:\Program Files (x86)\ossec-agent\active-response\bin\pssuspend.cmd`, `C:\Program Files (x86)\ossec-agent\active-response\bin\get-forensics.cmd`
- **Core PowerShell Logic Scripts:** `C:\Program Files\Sysinternals\pssuspend_v2.ps1`, `C:\Program Files\Sysinternals\ps-forensics.ps1`
- **Sysinternals Executables:** `C:\Program Files\Sysinternals\PsSuspend64.exe` (and other PsTools utilities)

---
*Maintained by Ko Ye*
