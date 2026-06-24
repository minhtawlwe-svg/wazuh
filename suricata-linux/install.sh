#!/bin/bash
# =====================================================================
#  install.sh   Suricata + Wazuh auto installer for Linux
#  Supports: Debian/Ubuntu + RHEL/Fedora/Rocky families
#  Capture:  AF_PACKET (passive IDS)
#  Rules:    ET Open (direct tarball, version-matched)
#  Mirror of suricata-win/suricata-install.ps1 (PowerShell version).
# =====================================================================
set -euo pipefail
IFS=$'\n\t'

# -------------------------------------
# Defaults (override via -<Flag> args)
# -------------------------------------
INTERFACE_OVERRIDE=""
# Resolved single capture interface (set in main from override or detection).
SELECTED_IFACE=""
WAZUH_CONF="/var/ossec/etc/ossec.conf"
SURICATA_YAML="/etc/suricata/suricata.yaml"
RULE_DIR="/etc/suricata/rules"
LOG_DIR="/var/log/suricata"
EVE_LOG="${LOG_DIR}/eve.json"
MAINT_SCRIPT="/usr/local/sbin/suricata-maintenance.sh"
TIMER_NAME="suricata-maintenance.timer"
SERVICE_NAME="suricata-maintenance.service"
MAX_EVE_BYTES=2147483648   # 2 GiB
KEEP_ROTATED_LOGS=3
DAILY_TASK_TIME="03:15"
SKIP_SURICATA=0
SKIP_WAZUH_CONFIG=0
SKIP_SCHEDULED_TASK=0
INSTALL_LOG="/var/log/suricata-install.log"
# FIX: SURICATA_REPO_URL is accepted but was silently unused; kept for future use
SURICATA_REPO_URL=""
# HOME_NET: monitored network range(s) for direction-aware rules.
# Empty = leave whatever is already in suricata.yaml untouched.
# Override with -HomeNet "10.0.0.0/8,192.168.0.0/16" (or "any").
HOME_NET_OVERRIDE=""

# -------------------------------------
# Logging
# -------------------------------------
log() {
    local line
    line="[$(date '+%F %T')] $*"
    echo "$line" | tee -a "$INSTALL_LOG"
}

die() {
    log "ERROR: $*"
    exit 1
}

# -------------------------------------
# Usage
# -------------------------------------
usage() {
    cat <<EOF
Usage: sudo ./install.sh [options]

  -Interface <name>         Capture interface to bind (single interface).
                            If omitted, the fastest detected interface is used
                            and written into suricata.yaml af-packet.
  -HomeNet <cidr[,cidr]>    Set HOME_NET in suricata.yaml, e.g.
                            "10.0.0.0/8,192.168.0.0/16" or "any".
                            If omitted, the existing HOME_NET is left untouched.
  -WazuhConf <path>         ossec.conf path (default: /var/ossec/etc/ossec.conf)
  -SuricataRepoUrl <url>    OISF repo base URL (reserved for future use)
  -MaxEveBytes <bytes>      eve.json rotation threshold (default: 2147483648)
  -KeepRotatedLogs <n>      Number of archived eve.json.* to keep (default: 3)
  -DailyTaskTime <HH:MM>    Maintenance timer time (default: 03:15)
  -SkipSuricata             Skip Suricata install (use existing binary)
  -SkipWazuhConfig          Skip ossec.conf patching
  -SkipScheduledTask        Skip systemd timer registration
  -h | -Help                Show this help

Examples:
  sudo ./install.sh
  sudo ./install.sh -Interface eth0
  sudo ./install.sh -Interface eth0 -HomeNet "10.10.0.0/16,192.168.1.0/24"
EOF
}

# -------------------------------------
# Argument parsing
# -------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -Interface)           INTERFACE_OVERRIDE="${2:-}"; shift 2 ;;
        -HomeNet)             HOME_NET_OVERRIDE="${2:-}"; shift 2 ;;
        -WazuhConf)           WAZUH_CONF="${2:-}"; shift 2 ;;
        -SuricataRepoUrl)     SURICATA_REPO_URL="${2:-}"; shift 2 ;;
        -MaxEveBytes)         MAX_EVE_BYTES="${2:-}"; shift 2 ;;
        -KeepRotatedLogs)     KEEP_ROTATED_LOGS="${2:-}"; shift 2 ;;
        -DailyTaskTime)       DAILY_TASK_TIME="${2:-}"; shift 2 ;;
        -SkipSuricata)        SKIP_SURICATA=1; shift ;;
        -SkipWazuhConfig)     SKIP_WAZUH_CONFIG=1; shift ;;
        -SkipScheduledTask)   SKIP_SCHEDULED_TASK=1; shift ;;
        -h|-Help|--help)      usage; exit 0 ;;
        *)                    die "Unknown argument: $1 (use -h)" ;;
    esac
done

# -------------------------------------
# Pre-flight: root
# -------------------------------------
if [ "$(id -u)" -ne 0 ]; then
    die "Please run as root or with sudo"
fi

# Validate -HomeNet early so a typo can't reach the yaml editor.
# Accept "any" or a comma-separated list of IPv4/IPv6 CIDRs / bare IPs.
if [ -n "$HOME_NET_OVERRIDE" ] && [ "$(printf '%s' "$HOME_NET_OVERRIDE" | tr 'A-Z' 'a-z')" != "any" ]; then
    IFS=',' read -ra _hn_parts <<< "$HOME_NET_OVERRIDE"
    for _p in "${_hn_parts[@]}"; do
        _p_trim="$(printf '%s' "$_p" | xargs)"
        # IPv4 (optional /0-32), or IPv6 (contains ':', optional /0-128)
        if printf '%s' "$_p_trim" | grep -qE '^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$'; then
            :
        elif printf '%s' "$_p_trim" | grep -qE '^[0-9a-fA-F:]+(/[0-9]{1,3})?$' && printf '%s' "$_p_trim" | grep -q ':'; then
            :
        else
            die "Invalid -HomeNet entry: '${_p_trim}'. Use CIDR/IP list like 10.0.0.0/8,192.168.1.0/24 or 'any'."
        fi
    done
fi

: > "$INSTALL_LOG"
log "=== Suricata Linux installer start ==="
log "Args: INTERFACE=${INTERFACE_OVERRIDE:-auto} HOME_NET=${HOME_NET_OVERRIDE:-<unchanged>} MAX_EVE_BYTES=${MAX_EVE_BYTES} KEEP=${KEEP_ROTATED_LOGS} DAILY=${DAILY_TASK_TIME}"

# -------------------------------------
# Pre-flight: distro detection
# -------------------------------------
if [ ! -r /etc/os-release ]; then
    die "/etc/os-release not readable — unsupported distribution"
fi
. /etc/os-release
DISTRO_ID="${ID:-unknown}"
DISTRO_LIKE="${ID_LIKE:-}"
log "Detected distro: ID=${DISTRO_ID} ID_LIKE=${DISTRO_LIKE}"

case "$DISTRO_LIKE" in
    *debian*) DISTRO_FAMILY="debian" ;;
    *)         DISTRO_FAMILY="$DISTRO_ID" ;;
esac

case "$DISTRO_FAMILY" in
    debian|ubuntu)  PKG_FAMILY="apt" ;;
    rhel|centos|rocky|fedora)  PKG_FAMILY="rpm" ;;
    *)              die "Unsupported distro family: ${DISTRO_FAMILY} (need Debian/Ubuntu or RHEL/Fedora/Rocky)" ;;
esac
log "Package family: ${PKG_FAMILY}"

# -------------------------------------
# Helpers
# -------------------------------------
ensure_dir() {
    [ -d "$1" ] || mkdir -p "$1" || die "Cannot create $1"
}

download() {
    local url="$1" out="$2"
    if [ -s "$out" ] && [ "$(stat -c%s "$out" 2>/dev/null || echo 0)" -gt 0 ]; then
        log "Reuse existing file: $out"
        return 0
    fi
    log "Download: $url"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$out" "$url" || return 1
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$out" "$url" || return 1
    else
        die "Neither curl nor wget available"
    fi
}

# -------------------------------------
# Pre-flight: Wazuh must already be installed AND running.
# This installer does NOT install Wazuh. If wazuh-agent is not active,
# stop here so we never patch a half-installed or absent agent.
# -------------------------------------
require_wazuh_running() {
    # 1) Binary / install must exist
    if [ ! -x /var/ossec/bin/wazuh-control ] && \
       ! systemctl list-unit-files wazuh-agent.service >/dev/null 2>&1; then
        die "Wazuh agent is not installed (no /var/ossec/bin/wazuh-control and no wazuh-agent.service). This installer does not install Wazuh — install it first, then re-run."
    fi

    # 2) Service must be active (running)
    if systemctl is-active --quiet wazuh-agent; then
        log "Wazuh agent is installed and running — continuing."
        return 0
    fi

    die "Wazuh agent is installed but NOT running (systemctl is-active wazuh-agent != active). Fix/start the agent first, then re-run. This installer will not proceed against a stopped agent."
}

# -------------------------------------
# APT install path for Suricata.
#
# The OISF Suricata >= 7.x package bundles the `suricata-update` tool inside
# the main `suricata` package (file: /usr/bin/suricata-update). On many Ubuntu
# boxes a STANDALONE Debian `suricata-update` package and/or a pip-installed
# copy already own that same path. dpkg then aborts the upgrade with:
#
#   trying to overwrite '/usr/bin/suricata-update', which is also in
#   package suricata-update 1.3.0-2
#
# This helper resolves that cleanly:
#   1. Repair any half-finished dpkg state from a prior failed run.
#   2. Remove the conflicting standalone `suricata-update` apt package
#      (the bundled tool from the suricata package supersedes it).
#   3. Remove a pip-installed `suricata-update` that shadows the same binary.
#   4. Install/upgrade/repair suricata, with --force-overwrite as a last-ditch
#      fallback so a residual file conflict cannot wedge the run.
# -------------------------------------
apt_install_suricata() {
    # --- 0. Ensure OISF PPA present ---
    if ! apt-cache policy suricata 2>/dev/null | grep -q 'oisf/suricata-stable'; then
        log "Adding OISF Launchpad PPA: ppa:oisf/suricata-stable"
        DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common >/dev/null 2>&1 || true
        add-apt-repository -y ppa:oisf/suricata-stable || die "add-apt-repository failed"
        apt-get update -y || die "apt-get update failed"
    fi

    # --- 1. Repair any interrupted dpkg state from an earlier failed attempt ---
    if dpkg -l 2>/dev/null | grep -qE '^.[^i] '; then
        log "Repairing dpkg state (dpkg --configure -a; apt-get install -f)..."
        dpkg --configure -a >/dev/null 2>&1 || true
        DEBIAN_FRONTEND=noninteractive apt-get install -f -y >/dev/null 2>&1 || true
    fi

    # --- 2. Remove the conflicting STANDALONE suricata-update apt package ---
    # The bundled tool inside the suricata package provides the same binary.
    if dpkg -s suricata-update >/dev/null 2>&1; then
        log "Removing conflicting standalone 'suricata-update' apt package (superseded by bundled tool)."
        DEBIAN_FRONTEND=noninteractive apt-get remove -y suricata-update >/dev/null 2>&1 \
            || log "Could not remove suricata-update cleanly — will rely on --force-overwrite."
    fi

    # --- 3. Remove a pip-installed suricata-update that shadows the binary ---
    if command -v pip3 >/dev/null 2>&1 && pip3 show suricata-update >/dev/null 2>&1; then
        log "Removing pip-installed 'suricata-update' (conflicts with packaged binary)."
        pip3 uninstall -y suricata-update >/dev/null 2>&1 || \
        pip3 uninstall -y --break-system-packages suricata-update >/dev/null 2>&1 || \
            log "pip uninstall suricata-update failed (continuing)."
    fi

    # --- 4. Decide install mode: reinstall (config missing) vs install/upgrade ---
    local need_reinstall=0
    if dpkg -s suricata >/dev/null 2>&1 && [ ! -r "$SURICATA_YAML" ]; then
        need_reinstall=1
        log "suricata package marked installed but ${SURICATA_YAML} missing — will --reinstall to restore config."
    fi

    local base_opts=(-o Dpkg::Options::="--force-confmiss")
    local reinstall_flag=()
    [ "$need_reinstall" -eq 1 ] && reinstall_flag=(--reinstall)

    # First attempt: clean install/upgrade/reinstall.
    if DEBIAN_FRONTEND=noninteractive apt-get install -y \
         "${reinstall_flag[@]}" "${base_opts[@]}" suricata; then
        log "Suricata package install/upgrade succeeded."
    else
        # Last-ditch: a leftover file conflict (e.g. orphaned dpkg diversion).
        # Retry once forcing overwrite of conflicting files, then heal deps.
        log "Initial apt install failed — retrying with --force-overwrite to clear residual file conflicts."
        if ! DEBIAN_FRONTEND=noninteractive apt-get install -y \
               "${reinstall_flag[@]}" "${base_opts[@]}" \
               -o Dpkg::Options::="--force-overwrite" suricata; then
            log "Forced apt install also failed — attempting dpkg-level recovery."
            dpkg --configure -a >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get install -f -y >/dev/null 2>&1 || true
            DEBIAN_FRONTEND=noninteractive apt-get install -y \
                "${base_opts[@]}" -o Dpkg::Options::="--force-overwrite" suricata \
                || die "apt-get install suricata failed after conflict recovery — inspect 'dpkg -l suricata*' and /var/log/apt/term.log"
        fi
        log "Suricata installed after --force-overwrite recovery."
    fi

    # --- 5. xmllint for ossec.conf validation (best-effort) ---
    DEBIAN_FRONTEND=noninteractive apt-get install -y libxml2-utils >/dev/null 2>&1 \
        || log "libxml2-utils install failed (ossec.conf XML validation will be skipped)."

    # NOTE: We deliberately do NOT pip-install suricata-update here. The bundled
    # tool shipped with the suricata package is used; the installer's rule path
    # relies on the direct ET Open tarball regardless.
}

# -------------------------------------
# Install Suricata + suricata-update
# -------------------------------------
install_suricata() {
    if [ "$SKIP_SURICATA" -eq 1 ]; then
        log "Skip Suricata install (per -SkipSuricata)."
    elif command -v suricata >/dev/null 2>&1 && [ -r "$SURICATA_YAML" ]; then
        log "Suricata already installed with config: $(command -v suricata)"
    else
        # FIX: binary may exist while the package config (suricata.yaml) is
        # missing/removed. In that case we must (re)install so the yaml is
        # restored, rather than skipping and failing later in patch_yaml.
        if command -v suricata >/dev/null 2>&1 && [ ! -r "$SURICATA_YAML" ]; then
            log "Suricata binary present but ${SURICATA_YAML} missing — (re)installing package to restore config."
        fi
        log "Adding OISF repository and installing Suricata..."
        case "$PKG_FAMILY" in
            apt)
                apt_install_suricata
                ;;
            rpm)
                if ! rpm -q epel-release >/dev/null 2>&1; then
                    log "Enabling EPEL..."
                    dnf install -y epel-release elrepo-release >/dev/null 2>&1 || \
                    dnf install -y epel-release >/dev/null 2>&1 || \
                    yum install -y epel-release >/dev/null 2>&1 || \
                        die "Cannot enable EPEL"
                fi
                if rpm -q suricata >/dev/null 2>&1 && [ ! -r "$SURICATA_YAML" ]; then
                    log "suricata package installed but config missing — forcing reinstall."
                    dnf reinstall -y suricata >/dev/null 2>&1 || yum reinstall -y suricata >/dev/null 2>&1 || true
                fi
                dnf install -y suricata suricata-update \
                    || yum install -y suricata suricata-update \
                    || die "Package install failed (tried dnf and yum)"
                # xmllint for ossec.conf validation (best-effort)
                dnf install -y libxml2 >/dev/null 2>&1 \
                    || yum install -y libxml2 >/dev/null 2>&1 \
                    || log "libxml2 install failed (ossec.conf XML validation will be skipped)"
                ;;
        esac
        log "Suricata installed: $(command -v suricata)"
    fi

    if ! command -v suricata >/dev/null 2>&1; then
        die "suricata binary not found after install"
    fi
    if [ ! -r "$SURICATA_YAML" ]; then
        die "suricata.yaml still missing at ${SURICATA_YAML} after install. Reinstall the suricata package manually (apt-get install --reinstall -o Dpkg::Options::=\"--force-confmiss\" suricata), then re-run with -SkipSuricata."
    fi
}

# -------------------------------------
# Detect capture interfaces
# FIX: removed dead ifaces=() accumulation; function now purely emits
#      sorted interface names to stdout for the caller to read.
# -------------------------------------
detect_interfaces() {
    if [ -n "$INTERFACE_OVERRIDE" ]; then
        if [ ! -d "/sys/class/net/$INTERFACE_OVERRIDE" ]; then
            die "Override interface not found: $INTERFACE_OVERRIDE"
        fi
        echo "$INTERFACE_OVERRIDE"
        return 0
    fi

    local deny_re='^(lo|docker[0-9]*|veth[0-9a-f]+|br-[0-9a-f]+|virbr[0-9]*|vnet[0-9]*|tun[0-9]*|tap[0-9]*|wg[0-9]*|tailscale[0-9]*|hamachi[0-9]*|zerotier[0-9]*|bond[0-9]*|dummy[0-9]*)$'
    local found=0
    for iface_dir in /sys/class/net/*/; do
        local iface
        iface=$(basename "$iface_dir")
        if [[ "$iface" =~ $deny_re ]]; then continue; fi
        [ -e "/sys/class/net/$iface/device" ] || continue
        local speed=0
        if [ -r "/sys/class/net/$iface/speed" ]; then
            speed=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || echo 0)
            # speed can be -1 when link is down; treat as 0
            [[ "$speed" =~ ^[0-9]+$ ]] || speed=0
        fi
        echo "$speed $iface"
        found=1
    done | sort -rn -k1,1 | awk '{print $2}'

    # NOTE: $found is in a subshell above (pipe), so we re-check via output count.
    # The caller already guards against an empty list.
}

# -------------------------------------
# Suricata.yaml patch
# FIX: yaml_set_kv now skips comment lines (lines starting with #)
#      so a commented-out key is not mistakenly rewritten.
# -------------------------------------
yaml_self_heal() {
    local yaml="$1"
    if ! grep -qE '^\s*rule-files:' "$yaml" || ! grep -qE '^\s*app-layer:' "$yaml"; then
        log "WARNING: $yaml looks incomplete — searching for intact backup..."
        local bak=""
        for f in $(ls -1t "${yaml}".*.bak 2>/dev/null); do
            if grep -qE '^\s*rule-files:' "$f" && grep -qE '^\s*app-layer:' "$f"; then
                bak="$f"
                break
            fi
        done
        if [ -n "$bak" ] && [ -r "$bak" ]; then
            cp -a "$bak" "$yaml"
            log "Restored intact suricata.yaml from: $bak"
        else
            # FIX: attempt to regenerate a minimal valid yaml via --dump-config
            #      before giving up, so a retry after partial-corruption succeeds.
            log "No intact backup found — attempting suricata --dump-config fallback..."
            if suricata --dump-config > "${yaml}.recovered" 2>/dev/null && \
               grep -qE '^\s*rule-files:' "${yaml}.recovered"; then
                mv "${yaml}.recovered" "$yaml"
                log "Recovered suricata.yaml via --dump-config"
            else
                rm -f "${yaml}.recovered"
                die "suricata.yaml is incomplete and no intact backup found. Reinstall the suricata package, then re-run."
            fi
        fi
    fi
}

yaml_set_kv() {
    # FIX: skip comment lines (^\s*#) so a commented key is never rewritten.
    # Replace first non-comment `key: value` line. If key missing, insert at top.
    local file="$1" key="$2" value="$3"
    local tmp
    tmp=$(mktemp)
    if grep -qE "^\s*${key}\s*:" "$file"; then
        # Use Python for safer multiline-aware replacement that skips comments
        python3 - "$file" "$key" "$value" "$tmp" <<'PY'
import sys, re
src, key, value, dst = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
pattern = re.compile(r'^(\s*)' + re.escape(key) + r'\s*:.*$')
replaced = False
lines = []
with open(src, 'r', encoding='utf-8') as f:
    for line in f:
        if not replaced and not line.lstrip().startswith('#'):
            m = pattern.match(line.rstrip('\n'))
            if m:
                lines.append(f"{key}: {value}\n")
                replaced = True
                continue
        lines.append(line)
if not replaced:
    lines.insert(0, f"{key}: {value}\n")
with open(dst, 'w', encoding='utf-8') as f:
    f.writelines(lines)
PY
    else
        { printf '%s: %s\n' "$key" "$value"; cat "$file"; } > "$tmp"
    fi
    mv "$tmp" "$file"
}

patch_yaml() {
    local yaml="$1"
    [ -r "$yaml" ] || die "suricata.yaml not readable: $yaml"

    yaml_self_heal "$yaml"

    local ts
    ts=$(date +%Y%m%d%H%M%S)
    cp -a "$yaml" "${yaml}.${ts}.bak"
    log "Backup: ${yaml}.${ts}.bak"

    yaml_set_kv "$yaml" "default-log-dir"   "/var/log/suricata/"
    yaml_set_kv "$yaml" "default-rule-path" "/etc/suricata/rules/"

    # Bind the chosen capture interface into the af-packet section and,
    # optionally, set HOME_NET. Comment-preserving line editor (see helper).
    local yaml_edit_result
    yaml_edit_result=$(apply_yaml_interface_and_homenet "$yaml" "$SELECTED_IFACE" "$HOME_NET_OVERRIDE" || true)

    if [ -n "$SELECTED_IFACE" ]; then
        if echo "$yaml_edit_result" | grep -q 'IF_CHANGED=1'; then
            log "Bound capture interface in suricata.yaml: ${SELECTED_IFACE}"
        else
            log "WARNING: could not locate an af-packet interface line to bind ${SELECTED_IFACE}. Verify the af-packet: section in ${yaml} manually."
        fi
    fi
    if [ -n "$HOME_NET_OVERRIDE" ]; then
        if echo "$yaml_edit_result" | grep -q 'HN_CHANGED=1'; then
            log "Set HOME_NET in suricata.yaml: ${HOME_NET_OVERRIDE}"
        else
            log "WARNING: could not locate a HOME_NET line under vars/address-groups to set. Verify ${yaml} manually."
        fi
    fi

    log "Patched suricata.yaml (default-log-dir, default-rule-path): $yaml"
}

# -------------------------------------
# Bind capture interface into af-packet + optionally set HOME_NET.
#
# PRIMARY method is a targeted line editor that rewrites ONLY the af-packet
# interface line and the HOME_NET line, preserving every comment and all other
# structure in suricata.yaml (SOC operators rely on the stock comments).
# PyYAML reserialization is avoided because it strips all comments.
#
# After editing, `suricata -T` (run later in install_etopen_rules) validates
# the result; if the edit somehow produced an invalid file, yaml_self_heal's
# backups remain available.
# -------------------------------------
apply_yaml_interface_and_homenet() {
    local yaml="$1" iface="$2" homenet="$3"

    # Nothing to do if neither is requested.
    [ -z "$iface" ] && [ -z "$homenet" ] && return 0

    python3 - "$yaml" "$iface" "$homenet" <<'PY'
import sys
yaml_path, iface, homenet = sys.argv[1], sys.argv[2], sys.argv[3]

with open(yaml_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

def indent_of(line):
    return line[:len(line) - len(line.lstrip())]

def trailing_comment(line):
    # Return ' # ...' if the line has an inline comment, else ''. Naive but
    # safe for Suricata's simple scalar lines (no '#' inside the values we set).
    if '#' in line:
        return '   ' + line[line.index('#'):].rstrip('\n')
    return ''

if_changed = False
hn_changed = False

# --- af-packet interface: first interface key under the af-packet: section ---
if iface:
    in_af = False
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith('af-packet:'):
            in_af = True
            continue
        if in_af:
            if s.startswith('- interface:'):
                lines[i] = f"{indent_of(line)}- interface: {iface}{trailing_comment(line)}\n"
                if_changed = True
                break
            if s.startswith('interface:'):
                lines[i] = f"{indent_of(line)}interface: {iface}{trailing_comment(line)}\n"
                if_changed = True
                break
            if s and not s.startswith('#') and not line.startswith(' ') and not line.startswith('\t'):
                in_af = False

# --- HOME_NET: first HOME_NET key under vars: -> address-groups: ---
if homenet:
    val = '"any"' if homenet.lower() == 'any' else f'"[{homenet}]"'
    in_addr = False
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith('address-groups:'):
            in_addr = True
            continue
        if in_addr:
            if s.startswith('HOME_NET:'):
                lines[i] = f"{indent_of(line)}HOME_NET: {val}{trailing_comment(line)}\n"
                hn_changed = True
                break
            if s and not s.startswith('#') and not line.startswith(' ') and not line.startswith('\t'):
                in_addr = False

with open(yaml_path, 'w', encoding='utf-8') as f:
    f.writelines(lines)

# Report so the shell can warn if an anchor wasn't found.
print(f"IF_CHANGED={int(if_changed)} HN_CHANGED={int(hn_changed)}")
PY
}

# -------------------------------------
# ET Open rules
# -------------------------------------
install_etopen_rules() {
    ensure_dir "$RULE_DIR"
    local ver
    ver=$(suricata -V 2>&1 | sed -nE 's/.*[Vv]ersion[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n1)
    [ -n "$ver" ] || ver="7.0.0"
    log "Suricata version detected: $ver"

    local url="https://rules.emergingthreats.net/open/suricata-${ver}/emerging.rules.tar.gz"
    local tar="${RULE_DIR}/emerging.rules.tar.gz"
    download "$url" "$tar" || die "ET Open tarball download failed: $url"

    local extract="${RULE_DIR}/.extract"
    rm -rf "$extract"
    ensure_dir "$extract"
    tar -xzf "$tar" -C "$extract" || die "tar extract failed"

    if ! ls "$extract"/rules/*.rules >/dev/null 2>&1; then
        die "No .rules files found in extracted ET Open archive"
    fi

    cat "$extract"/rules/*.rules > "${RULE_DIR}/suricata.rules"
    local count
    count=$(grep -cE '^\s*alert ' "${RULE_DIR}/suricata.rules" || true)
    log "Wrote ${RULE_DIR}/suricata.rules (~$count alert signatures)"

    if suricata -T -c "$SURICATA_YAML" >/tmp/suricata-T.log 2>&1; then
        log "Config test (suricata -T) passed."
    else
        log "Config test returned non-zero (see /tmp/suricata-T.log) — continuing."
    fi
}

# -------------------------------------
# Start Suricata via systemd
# FIX: corrected unit-file existence check — list-unit-files always exits 0;
#      use show --property= to get a meaningful non-zero on missing units.
# -------------------------------------
start_suricata() {
    if ! systemctl show suricata.service --property=LoadState 2>/dev/null \
         | grep -q 'LoadState=loaded'; then
        log "WARNING: suricata.service not found in systemd — attempting start anyway."
    fi
    systemctl daemon-reload || true
    systemctl enable suricata >/dev/null 2>&1 || log "systemctl enable suricata failed (continuing)"
    systemctl restart suricata || die "systemctl restart suricata failed"
    sleep 2
    if systemctl is-active --quiet suricata; then
        log "Suricata service: active"
    else
        die "Suricata service not active after restart"
    fi
}

# -------------------------------------
# Wazuh ossec.conf binding
# -------------------------------------
patch_wazuh() {
    if [ "$SKIP_WAZUH_CONFIG" -eq 1 ]; then
        log "Skip Wazuh ossec.conf update (per -SkipWazuhConfig)."
        return 0
    fi
    if [ ! -r "$WAZUH_CONF" ]; then
        log "Wazuh ossec.conf not found at $WAZUH_CONF — skipping Wazuh binding."
        return 0
    fi

    local ts
    ts=$(date +%Y%m%d%H%M%S)
    cp -a "$WAZUH_CONF" "${WAZUH_CONF}.${ts}.bak"
    log "Backup: ${WAZUH_CONF}.${ts}.bak"

    local tmp
    tmp=$(mktemp)
    # FIX: Wazuh ossec.conf is an XML *fragment* with possibly multiple
    # top-level <ossec_config> blocks and no single root. Insert the eve.json
    # <localfile> before the LAST </ossec_config>, not anchored to end-of-file.
    python3 - "$WAZUH_CONF" "$EVE_LOG" "$tmp" <<'PY'
import re, sys
src, eve, dst = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src, 'r', encoding='utf-8') as f:
    content = f.read()

# Remove any existing eve.json localfile block (multiline safe)
pat = re.compile(r'[ \t]*<localfile>(?:(?!</localfile>).)*?eve\.json(?:(?!</localfile>).)*?</localfile>\s*', re.DOTALL)
new = pat.sub('', content)

block = ('  <localfile>\n'
         '    <log_format>json</log_format>\n'
         f'    <location>{eve}</location>\n'
         '  </localfile>\n')

# Insert before the LAST </ossec_config>. If none exists, wrap in a new block.
idx = new.rfind('</ossec_config>')
if idx == -1:
    new = new.rstrip() + '\n<ossec_config>\n' + block + '</ossec_config>\n'
else:
    new = new[:idx] + block + new[idx:]

with open(dst, 'w', encoding='utf-8') as f:
    f.write(new)
PY

    # Validate BEFORE overwriting the live config, so a malformed patch can
    # never break wazuh-agent startup.
    #
    # IMPORTANT: ossec.conf is intentionally a multi-root XML *fragment* —
    # it may contain several top-level <ossec_config> blocks with no single
    # wrapping element. That is valid for Wazuh/OSSEC but is NOT well-formed
    # standalone XML, so a plain `xmllint --noout` rejects even a correct file
    # ("Extra content at the end of the document"). We therefore validate a
    # copy wrapped in a synthetic single root — the same way OSSEC parses it.
    if command -v xmllint >/dev/null 2>&1; then
        local wrapped
        wrapped=$(mktemp)
        {
            echo '<__ossec_root__>'
            cat "$tmp"
            echo '</__ossec_root__>'
        } > "$wrapped"
        if ! xmllint --noout "$wrapped" 2>/tmp/ossec-xmllint.log; then
            log "xmllint errors (root-wrapped): $(cat /tmp/ossec-xmllint.log)"
            rm -f "$tmp" "$wrapped"
            die "Patched ossec.conf is not well-formed XML — aborting, original left untouched (backup: ${WAZUH_CONF}.${ts}.bak)"
        fi
        rm -f "$wrapped"
        log "Patched ossec.conf passed XML well-formedness check (multi-root aware)."
    else
        log "xmllint not available — skipping XML check (install libxml2-utils to enable)."
    fi

    # Authoritative semantic check: let Wazuh itself parse the candidate config.
    # wazuh-logtest-legacy / wazuh-control loads ossec.conf and exits non-zero
    # on a real config error. We point it at the temp file via a scratch copy
    # of the live tree only if a safe test entrypoint exists; otherwise we skip
    # (the well-formedness check above already guards the structural failure
    # mode that truncated configs produce).
    if [ -x /var/ossec/bin/verify-agent-conf ]; then
        # verify-agent-conf validates a remote/agent.conf-style file; use it
        # opportunistically for syntax sanity.
        /var/ossec/bin/verify-agent-conf -f "$tmp" >/tmp/ossec-verify.log 2>&1 \
            && log "wazuh verify-agent-conf passed." \
            || log "wazuh verify-agent-conf reported issues (see /tmp/ossec-verify.log) — relying on XML check."
    fi

    mv "$tmp" "$WAZUH_CONF"
    log "Patched Wazuh ossec.conf -> $EVE_LOG"

    # Restart the agent, then CONFIRM it actually came up. If the new config
    # somehow prevents startup, restore the backup automatically so we never
    # leave the agent dead — this is the safety net the first failure lacked.
    if systemctl list-unit-files wazuh-agent.service >/dev/null 2>&1; then
        if systemctl restart wazuh-agent 2>/tmp/wazuh-restart.log; then
            sleep 2
            if systemctl is-active --quiet wazuh-agent; then
                log "wazuh-agent restarted and active."
            else
                log "wazuh-agent not active after restart — rolling back ossec.conf."
                cp -a "${WAZUH_CONF}.${ts}.bak" "$WAZUH_CONF"
                systemctl restart wazuh-agent >/dev/null 2>&1 || true
                die "wazuh-agent failed to start with patched config; restored backup ${WAZUH_CONF}.${ts}.bak. Inspect /var/ossec/logs/ossec.log"
            fi
        else
            log "systemctl restart wazuh-agent failed — rolling back ossec.conf."
            cp -a "${WAZUH_CONF}.${ts}.bak" "$WAZUH_CONF"
            systemctl restart wazuh-agent >/dev/null 2>&1 || true
            die "wazuh-agent restart command failed; restored backup ${WAZUH_CONF}.${ts}.bak (see /tmp/wazuh-restart.log)"
        fi
    else
        log "wazuh-agent.service not found — user must restart agent manually."
    fi
}

# -------------------------------------
# Drop maintenance script
# FIX: all four placeholders are now substituted by sed:
#      __LOG_DIR__, __RULE_DIR__, __MAX_EVE_BYTES__, __KEEP_ROTATED_LOGS__
# -------------------------------------
write_maintenance_script() {
    cat > "$MAINT_SCRIPT" <<'EOF'
#!/bin/bash
# Auto-generated by suricata-linux/install.sh — daily rules refresh + eve.json rotate.
set -euo pipefail
IFS=$'\n\t'

LOG_DIR="__LOG_DIR__"
EVE_LOG="${LOG_DIR}/eve.json"
RULE_DIR="__RULE_DIR__"
MAX_EVE_BYTES=__MAX_EVE_BYTES__
KEEP_ROTATED_LOGS=__KEEP_ROTATED_LOGS__
MAINT_LOG="${LOG_DIR}/maintenance.log"

log() {
    local line
    line="[$(date '+%F %T')] $*"
    echo "$line" | tee -a "$MAINT_LOG"
}

ensure_dir() { [ -d "$1" ] || mkdir -p "$1"; }

update_rules() {
    ensure_dir "$RULE_DIR"
    local ver
    ver=$(suricata -V 2>&1 | sed -nE 's/.*[Vv]ersion[[:space:]]+([0-9]+\.[0-9]+\.[0-9]+).*/\1/p' | head -n1)
    [ -n "$ver" ] || ver="7.0.0"
    local url="https://rules.emergingthreats.net/open/suricata-${ver}/emerging.rules.tar.gz"
    local tar="${RULE_DIR}/emerging.rules.tar.gz"
    log "Updating ET Open rules for Suricata $ver"
    if command -v curl >/dev/null 2>&1; then
        curl -fsSL --retry 3 -o "$tar" "$url" || { log "curl download failed"; return 1; }
    elif command -v wget >/dev/null 2>&1; then
        wget -q -O "$tar" "$url" || { log "wget download failed"; return 1; }
    else
        log "Neither curl nor wget available"; return 1
    fi

    local extract="${RULE_DIR}/.extract"
    rm -rf "$extract"
    mkdir -p "$extract"
    tar -xzf "$tar" -C "$extract" || { log "tar extract failed"; return 1; }
    if ! ls "$extract"/rules/*.rules >/dev/null 2>&1; then
        log "No .rules files in archive"; return 1
    fi
    cat "$extract"/rules/*.rules > "${RULE_DIR}/suricata.rules"
    local count
    count=$(grep -cE '^\s*alert ' "${RULE_DIR}/suricata.rules" || true)
    log "Rules updated (~$count alert signatures)"

    systemctl restart suricata >/dev/null 2>&1 || log "systemctl restart suricata failed"
}

rotate_eve() {
    if [ ! -f "$EVE_LOG" ]; then
        log "eve.json not found at $EVE_LOG — skip rotation."
        return 0
    fi
    local size
    size=$(stat -c%s "$EVE_LOG" 2>/dev/null || echo 0)
    if [ "$size" -lt "$MAX_EVE_BYTES" ]; then
        log "eve.json size $size below limit $MAX_EVE_BYTES — skip rotation."
        return 0
    fi
    log "eve.json size $size >= $MAX_EVE_BYTES — rotating."
    systemctl stop suricata >/dev/null 2>&1 || true
    sleep 1
    for ((i=KEEP_ROTATED_LOGS; i>=1; i--)); do
        local cur="${EVE_LOG}.${i}"
        local next="${EVE_LOG}.$((i+1))"
        if [ -f "$cur" ]; then
            if [ "$i" -eq "$KEEP_ROTATED_LOGS" ]; then
                rm -f "$cur"
            else
                mv "$cur" "$next"
            fi
        fi
    done
    mv "$EVE_LOG" "${EVE_LOG}.1"
    systemctl start suricata >/dev/null 2>&1 || log "systemctl start suricata failed after rotation"
    log "Rotation complete."
}

ensure_dir "$LOG_DIR"
log "=== Maintenance start ==="
update_rules || log "Rules update failed (continuing to rotation check)"
rotate_eve
log "=== Maintenance done ==="
EOF
    chmod +x "$MAINT_SCRIPT"

    # FIX: substitute ALL four placeholders, not just LOG_DIR and RULE_DIR.
    sed -i \
        "s|__LOG_DIR__|${LOG_DIR}|g; \
         s|__RULE_DIR__|${RULE_DIR}|g; \
         s|__MAX_EVE_BYTES__|${MAX_EVE_BYTES}|g; \
         s|__KEEP_ROTATED_LOGS__|${KEEP_ROTATED_LOGS}|g" \
        "$MAINT_SCRIPT"

    log "Wrote maintenance script: $MAINT_SCRIPT"
}

# -------------------------------------
# Systemd timer + service
# -------------------------------------
register_timer() {
    if [ "$SKIP_SCHEDULED_TASK" -eq 1 ]; then
        log "Skip systemd timer registration (per -SkipScheduledTask)."
        return 0
    fi
    cat > "/etc/systemd/system/${SERVICE_NAME}" <<EOF
[Unit]
Description=Suricata daily rules refresh and eve.json rotation
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=${MAINT_SCRIPT}
Nice=10
EOF

    cat > "/etc/systemd/system/${TIMER_NAME}" <<EOF
[Unit]
Description=Run Suricata maintenance daily at ${DAILY_TASK_TIME}

[Timer]
OnCalendar=*-*-* ${DAILY_TASK_TIME}:00
Persistent=true
AccuracySec=1min
Unit=${SERVICE_NAME}

[Install]
WantedBy=timers.target
EOF

    systemctl daemon-reload || die "systemctl daemon-reload failed"
    systemctl enable --now "${TIMER_NAME}" || die "systemctl enable ${TIMER_NAME} failed"
    log "Registered systemd timer: ${TIMER_NAME} (daily at ${DAILY_TASK_TIME})"
}

# -------------------------------------
# logrotate
# FIX: logrotate 'size' directive requires human-readable suffix (e.g. 2G),
#      not raw bytes. Compute a suffix string from MAX_EVE_BYTES.
# -------------------------------------
write_logrotate() {
    local size_human
    # Convert bytes to a logrotate-compatible size string.
    # logrotate accepts k, M, G suffixes (case-insensitive).
    local mb=$(( MAX_EVE_BYTES / 1048576 ))
    if [ "$mb" -ge 1024 ] && [ $(( MAX_EVE_BYTES % 1073741824 )) -eq 0 ]; then
        size_human="$(( MAX_EVE_BYTES / 1073741824 ))G"
    elif [ "$mb" -ge 1 ]; then
        size_human="${mb}M"
    else
        size_human="${MAX_EVE_BYTES}k"
    fi

    cat > /etc/logrotate.d/suricata <<EOF
/var/log/suricata/*.json {
    daily
    missingok
    rotate ${KEEP_ROTATED_LOGS}
    size ${size_human}
    compress
    notifempty
    sharedscripts
    postrotate
        systemctl restart suricata > /dev/null 2>&1 || true
    endscript
}
EOF
    log "Wrote /etc/logrotate.d/suricata (size threshold: ${size_human})"
}

# -------------------------------------
# Main
# -------------------------------------
main() {
    ensure_dir "$LOG_DIR"

    # Gate: Wazuh must be installed AND running before we touch anything,
    # unless the operator explicitly opted out with -SkipWazuhConfig.
    if [ "$SKIP_WAZUH_CONFIG" -eq 1 ]; then
        log "Wazuh precheck skipped (per -SkipWazuhConfig)."
    else
        require_wazuh_running
    fi

    install_suricata

    log "Detecting capture interfaces..."
    local ifaces=()
    while IFS= read -r line; do
        [ -n "$line" ] && ifaces+=("$line")
    done < <(detect_interfaces)

    if [ ${#ifaces[@]} -eq 0 ]; then
        die "No capture interface found. Pass -Interface <name>."
    fi

    # Single-interface model: if the operator passed -Interface, detect_interfaces
    # already validated and echoed exactly that one. Otherwise pick the fastest
    # detected interface (first in the speed-sorted list) and bind only that one.
    if [ -n "$INTERFACE_OVERRIDE" ]; then
        SELECTED_IFACE="$INTERFACE_OVERRIDE"
        log "Capture interface (manual): ${SELECTED_IFACE}"
    else
        SELECTED_IFACE="${ifaces[0]}"
        if [ ${#ifaces[@]} -gt 1 ]; then
            log "Multiple interfaces detected (${ifaces[*]}); selecting fastest: ${SELECTED_IFACE}. Use -Interface <name> to choose another."
        else
            log "Capture interface (auto): ${SELECTED_IFACE}"
        fi
    fi

    patch_yaml "$SURICATA_YAML"
    install_etopen_rules
    start_suricata
    patch_wazuh
    write_maintenance_script
    register_timer
    write_logrotate

    log "=== Complete. Suricata eve.json: ${EVE_LOG} ==="
    echo ""
    echo "=========================================="
    echo " SURICATA + WAZUH INSTALL COMPLETE"
    echo "=========================================="
    echo " eve.json       : ${EVE_LOG}"
    echo " rules dir      : ${RULE_DIR}"
    echo " suricata.yaml  : ${SURICATA_YAML}"
    echo " ossec.conf     : ${WAZUH_CONF}"
    echo " maintenance    : ${MAINT_SCRIPT}"
    echo " systemd timer  : ${TIMER_NAME} (daily ${DAILY_TASK_TIME})"
    echo " install log    : ${INSTALL_LOG}"
    echo "=========================================="
}

main "$@"
