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

After running the deployment script, you need to configure your **Wazuh Manager** (or individual agent `ossec.conf`) and `local_rules.xml` to trigger the Active Response.

### 1. Add CDB List to Wazuh Manager Configuration
Ensure you have the custom software list registered in your manager's `ossec.conf` inside the `<ruleset>` section:
```xml
<ruleset>
  <!-- Other lists... -->
  <list>etc/lists/software_vendors</list>
</ruleset>
```
*(Also create the CDB list file under `/var/ossec/etc/lists/software_vendors` and add allowed vendor names, e.g., `Microsoft Corporation:`)*

### 2. Add Command Configurations to Wazuh Manager
Add the following command blocks to your manager's `ossec.conf` file to define the scripts:

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

### 3. Add Custom Rules to `local_rules.xml`
Add these custom rules inside your `/var/ossec/etc/rules/local_rules.xml` file to process Sysmon Event ID 1 (Process creation) events:

```xml
<group name="unwanted software,">
  <!-- Rule 100500: Base Rule - Unallowed Software (CDB List mismatch) -->
  <rule id="100500" level="10">
    <if_sid>61603</if_sid>
    <list field="win.eventdata.company" lookup="not_match_key">etc/lists/software_vendors</list>
    <description>$(win.eventdata.product) started but not allowed by the software policy.</description>
    <mitre>
      <id>T1036</id>
    </mitre>
    <options>no_full_log</options>
    <group>sysmon_event1,software_policy</group>
  </rule>

  <!-- Rule 100501: Path Check - Run from a Downloads folder -->
  <rule id="100501" level="12">
    <if_sid>100500</if_sid>
    <field name="win.eventdata.image" type="pcre2">(?i)\\Downloads\\</field>
    <description>Unallowed software executed from a Downloads directory.</description>
    <group>sysmon_event1,software_policy,downloads_threat</group>
  </rule>

  <!-- Rule 100599: Target Rule - Triggering Forensics -->
  <rule id="100599" level="12">
    <if_sid>100501</if_sid>
    <description>Highly suspicious unallowed software from Downloads. Triggering Forensics.</description>
    <group>sysmon_event1,software_policy,downloads_threat</group>
  </rule>
</group>
```

### 4. Add Active Response Mappings to `ossec.conf`
Configure when the manager triggers these actions on the agents by adding the following block to `ossec.conf`:

```xml
<!-- Trigger pssuspend (Kill app) when non-allowed software is run on Desktop/elsewhere (Rule 100500) -->
<active-response>
  <disabled>no</disabled>
  <command>pssuspend</command>
  <location>local</location>
  <rules_id>100500</rules_id>
</active-response>

<!-- Trigger pssuspend (Kill app) when non-allowed software is run from Downloads (Rule 100599) -->
<active-response>
  <disabled>no</disabled>
  <command>pssuspend</command>
  <location>local</location>
  <rules_id>100599</rules_id>
</active-response>

<!-- Trigger get-forensics (Collect data) only when non-allowed software is run from Downloads (Rule 100599) -->
<active-response>
  <disabled>no</disabled>
  <command>get-forensics</command>
  <location>local</location>
  <rules_id>100599</rules_id>
</active-response>
```

### 5. File Locations on Agent
- **Active Response Wrapper Cmds:** `C:\Program Files (x86)\ossec-agent\active-response\bin\pssuspend.cmd`, `C:\Program Files (x86)\ossec-agent\active-response\bin\get-forensics.cmd`
- **Core PowerShell Logic Scripts:** `C:\Program Files\Sysinternals\pssuspend_v2.ps1`, `C:\Program Files\Sysinternals\ps-forensics.ps1`
- **Sysinternals Executables:** `C:\Program Files\Sysinternals\PsSuspend64.exe` (and other PsTools utilities)

---
*Maintained by Ko Ye*
