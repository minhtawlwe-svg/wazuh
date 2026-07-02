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
        │  yara -w -r -C index.yarc <file>   (precompiled ruleset)
        ▼
Match → active-responses.log → decoders → rules 108001 (level 12, match)
                                          108002 (level 10, quarantined)
File moved to /var/ossec/active-response/quarantine/ (chmod 000)
```

## Files

| File | Where it goes |
|---|---|
| `install.sh` | Run on each Linux **agent** (root). Installs YARA 4.5.5, rules, AR script, FIM config, daily rules-update cron (1:15 PM), quarantine-cleanup cron. |
| `rule-collection/agb-custom.yar` | Our own AGB rules |
| `rule-collection/signature-base/` | Vendored community signature collection (742 files, compile-verified) |
| `update-yara-rules.sh` | Rules updater → `/usr/local/bin/`. Pulls the whole `rule-collection/` from this repo **plus the Valhalla feed**, drops any file that doesn't compile, and builds the master `/var/ossec/yara/rules/index.yar` that AR scans with. Daily cron at 1:15 PM. |
| `refresh-signature-base.sh` | Maintenance helper — re-vendors the latest upstream community rules into `rule-collection/signature-base/` (run in a Linux container/VM with yara installed, then commit + push) |
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
```
Rules come from three sources, merged into `/var/ossec/yara/rules/index.yar`:
our own `rule-collection/agb-custom.yar`, the vendored community set in
`rule-collection/signature-base/`, and the **Valhalla feed** downloaded live
on each update. Push changes to GitHub and the daily 1:15 PM cron rolls them
out to all agents. To refresh the vendored community set, run
`refresh-signature-base.sh` and push.

The community rules use external variables (`filename`, `filepath`,
`extension`, `filetype`, `owner`); the AR script and all compile checks
define them with `-d`. Files that still fail with stock yara (THOR-only or
module-dependent) are dropped automatically, and any file whose rule names
collide in the combined index is pruned.

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
- After editing `agb-custom.yar`, push to GitHub; the daily 1:15 PM update cron
  pulls it, rebuilds `index.yar`, and restarts `wazuh-agent` (compile-checked).
- **Valhalla**: set your real API key via `VALHALLA_APIKEY` in
  `update-yara-rules.sh` (the committed value is the `demo` key = sample rules
  only). If the feed is down or the key is empty, the update continues with the
  repo rules only.
- Performance: the updater precompiles all rules into `index.yarc` with `yarac`
  once per daily run, and `yara.sh` scans with `-C index.yarc` — no per-scan
  recompile. Measured ~12x faster (0.82s -> 0.065s per file). If `yarac` is
  missing or the `.yarc` isn't built yet, scans fall back to text `index.yar`.
- Quarantined files are `chmod 000` and auto-deleted after 30 days (daily cron).
- The AR script skips files already inside the quarantine dir to avoid
  scan/quarantine loops.
