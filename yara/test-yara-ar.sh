#!/bin/bash
# End-to-end test of the Wazuh + YARA Active Response pipeline.
# Run as root on an AGENT after install.sh (agent side) and the manager
# config (yara/manager/*.xml) are both in place.
#
# Drops an EICAR test file into /tmp; expected chain:
#   FIM 554 -> manager rule 100301 -> AR yara_linux on agent ->
#   yara.sh matches EICAR_Test_File -> log line -> manager rules 108001/108002
#   -> file moved to /var/ossec/active-response/quarantine/

set -e
[ "$EUID" -ne 0 ] && { echo "Run as root."; exit 1; }

AR_LOG="/var/ossec/logs/active-responses.log"
QDIR="/var/ossec/active-response/quarantine"
TESTFILE="/tmp/yara-ar-test-$(date +%s).txt"

echo "[*] Pre-check: yara binary and rules..."
command -v yara >/dev/null || { echo "[-] yara not installed"; exit 1; }
yara -w -d filename="" -d filepath="" -d extension="" -d filetype="" -d owner="" \
    /var/ossec/yara/rules/index.yar /dev/null >/dev/null || { echo "[-] rules do not compile"; exit 1; }
echo "[+] OK"

echo "[*] Dropping EICAR test file: $TESTFILE"
# Assembled in two parts so this script itself never contains the full EICAR string
printf '%s%s' 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST' '-FILE!$H+H*' > "$TESTFILE"

echo "[*] Waiting up to 60s for Active Response..."
for i in $(seq 1 60); do
    if grep -q "$(basename "$TESTFILE")" "$AR_LOG" 2>/dev/null; then
        echo ""
        echo "[+] PASS - AR fired. Log lines:"
        grep "$(basename "$TESTFILE")" "$AR_LOG"
        [ -f "$QDIR/$(basename "$TESTFILE")" ] && echo "[+] PASS - file quarantined in $QDIR" || echo "[-] WARN - file not found in quarantine"
        exit 0
    fi
    sleep 1; printf "."
done

echo ""
echo "[-] FAIL - no AR log entry after 60s. Check:"
echo "    1. Manager has yara/manager/*.xml applied + wazuh-manager restarted"
echo "    2. Agent ossec.conf has realtime FIM on /tmp + wazuh-agent restarted"
echo "    3. tail -f $AR_LOG   and   /var/ossec/logs/ossec.log for errors"
rm -f "$TESTFILE"
exit 1
