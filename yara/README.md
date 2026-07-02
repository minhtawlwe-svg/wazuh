# Wazuh + YARA Active Response (Linux)

Automatic malware scanning and quarantine: when a file lands in a monitored
directory, Wazuh FIM detects it, the manager triggers an Active Response on
the agent, YARA scans the file, and matches are logged + the file is
quarantined.

```
File dropped in /tmp,/media,/root,/home
        │  FIM realtime (agent syscheck)
        ▼
Manager rules 100300/100301 (syscheck 550/554)
        │  Active Response: yara_linux (location: local)
        ▼
Agent runs /var/ossec/active-response/bin/yara.sh
        │  yara -w -r yara_rules.yar <file>
        ▼
Match → active-responses.log → decoders → rules 108001 (level 12, match)
                                          108002 (level 10, quarantined)
File moved to /var/ossec/active-response/quarantine/ (chmod 000)
```

## Files

| File | Where it goes |
|---|---|
| `install.sh` | Run on each Linux **agent** (root). Installs YARA 4.5.5, rules, AR script, FIM config, weekly rules-update cron, quarantine-cleanup cron. |
| `rule-collection/yara_rules.yar` | Rules collection → `/var/ossec/yara/rules/yara_rules.yar` (installer downloads it) |
| `manager/local_decoder_yara.xml` | Append to **manager** `/var/ossec/etc/decoders/local_decoder.xml` |
| `manager/local_rules_yara.xml` | Append to **manager** `/var/ossec/etc/rules/local_rules.xml` |
| `manager/ossec-conf-ar-snippet.xml` | `<command>` + `<active-response>` blocks for **manager** `ossec.conf` |
| `agent/ossec-conf-fim-snippet.xml` | Manual reference — installer adds FIM dirs automatically |
| `test-yara-ar.sh` | End-to-end test (EICAR drop in /tmp) — run on an agent |

## Install

**1. Manager (once):**
```bash
# append decoder + rules, add AR command/active-response blocks to ossec.conf
sudo /var/ossec/bin/wazuh-logtest   # optional sanity
sudo systemctl restart wazuh-manager
```

**2. Each Linux agent:**
```bash
sudo bash install.sh
# or pull rules from a local server instead of GitHub:
sudo RULES_URL="http://10.3.11.48/rules/yara_rules.yar" bash install.sh
```

**3. Test:**
```bash
sudo bash test-yara-ar.sh
```
Expect a level-12 alert `YARA: file ... matched rule EICAR_Test_File` in the
dashboard and the file gone from /tmp into the quarantine dir.

## Rule IDs used
- `100300` / `100301` — FIM trigger (file modified / added in monitored dir)
- `108000` — YARA grouping (level 0)
- `108001` — YARA positive match (level 12)
- `108002` — file quarantined (level 10)

Change these in `manager/local_rules_yara.xml` **and** the `<rules_id>` in the
AR snippet if they collide with existing custom rules.

## Gotchas
- Manager config is mandatory — without the decoders/rules/AR command, agents
  detect FIM events but nothing scans.
- `extra_args` order matters: `yara.sh` reads index 1 (yara path) and index 3
  (rules file). Don't reorder.
- After editing `yara_rules.yar` on agents, restart `wazuh-agent` (the weekly
  update cron does this automatically, with a compile check first).
- Quarantined files are `chmod 000` and auto-deleted after 30 days (daily cron).
- The AR script skips files already inside the quarantine dir to avoid
  scan/quarantine loops.
