# 🔧 Windows Sysmon Automated Installer (PowerShell)

---

⚡ One-Line Install (IMPORTANT)
```
irm "https://raw.githubusercontent.com/yekyawhan/wazuh/aed3939d2b571e17ba435b7c19f8b8fc3793d312/sysmon/install-sysmon.ps1" | iex
```

Manual install လုပ်ချင်ရင်
```
powershell -ExecutionPolicy Bypass -File .\install-sysmon.ps1
```
### Uninstall
```
.\install-sysmon.ps1 -Uninstall
```

## 🇲🇲 
ဒီ repository က Microsoft Sysmon ကို PowerShell နဲ့ အလိုအလျောက် install လုပ်ပေးတဲ့ script ဖြစ်ပါတယ်။

SOC / SIEM environment (Wazuh, Graylog, Splunk, TheHive) အတွက် ရည်ရွယ်ထားပါတယ်။

အောက်ပါလုပ်ဆောင်ချက်တွေကို automation လုပ်ပေးပါတယ် —

- Sysmon install
- Configuration setup
- Service check
- Event log verify
- Logging system
- Uninstall process

---

# 📁 Project Structure

```text
windows-sysmon-installer/
│
├── install-sysmon.ps1
├── README.md
├── LICENSE
├── screenshots/
│   └── sysmon-running.png
└── config/
    └── custom-sysmon.xml   (optional future)
