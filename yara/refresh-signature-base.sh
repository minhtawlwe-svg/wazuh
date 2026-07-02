#!/bin/bash
# One-shot helper (run in container): vendor compile-verified signature-base
# files into rule-collection/signature-base/ and verify the combined compile.
set -eu
EXTVARS=(-d filename="" -d filepath="" -d extension="" -d filetype="" -d owner="")
TMP=$(mktemp -d)
curl -fsSL https://github.com/Neo23x0/signature-base/archive/refs/heads/master.tar.gz | tar -xz -C "$TMP"
SRC=$(find "$TMP" -maxdepth 2 -type d -name yara | head -1)
DEST=/kit/rule-collection/signature-base
mkdir -p "$DEST"; rm -f "$DEST"/*.yar
kept=0; dropped=0
for f in "$SRC"/*.yar; do
    b=$(basename "$f")
    case "$b" in
        thor_inverse_matches.yar|yara_mixed_ext_vars.yar|configured_vulns_ext_vars.yar|expl_*_vuln_*.yar)
            dropped=$((dropped+1)); continue ;;
    esac
    if yara -w "${EXTVARS[@]}" "$f" /dev/null >/dev/null 2>&1; then
        cp "$f" "$DEST/"; kept=$((kept+1))
    else
        dropped=$((dropped+1))
    fi
done
echo "KEPT=$kept DROPPED=$dropped"
# combined compile check incl. our own rules
IDX=$(mktemp --suffix=.yar)
echo 'include "/kit/rule-collection/yara_rules.yar"' > "$IDX"
for f in "$DEST"/*.yar; do echo "include \"$f\""; done >> "$IDX"
if yara -w "${EXTVARS[@]}" "$IDX" /dev/null >/dev/null 2>&1; then
    echo "COMBINED-COMPILE-OK"
else
    echo "COMBINED-NEEDS-PRUNE"; exit 1
fi
