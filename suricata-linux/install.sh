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

  -Interface <name>         Override auto-detected capture interface
  -WazuhConf <path>         ossec.conf path (default: /var/ossec/etc/ossec.conf)
  -SuricataRepoUrl <url>    OISF repo base URL
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
EOF
}

# -------------------------------------
# Argument parsing
# -------------------------------------
while [ $# -gt 0 ]; do
    case "$1" in
        -Interface)           INTERFACE_OVERRIDE="${2:-}"; shift 2 ;;
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

: > "$INSTALL_LOG"
log "=== Suricata Linux installer start ==="
log "Args: INTERFACE=${INTERFACE_OVERRIDE:-auto} MAX_EVE_BYTES=${MAX_EVE_BYTES} KEEP=${KEEP_ROTATED_LOGS} DAILY=${DAILY_TASK_TIME}"

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
# Install Suricata + suricata-update
# -------------------------------------
install_suricata() {
    if [ "$SKIP_SURICATA" -eq 1 ]; then
        log "Skip Suricata install (per -SkipSuricata)."
    elif command -v suricata >/dev/null 2>&1; then
        log "Suricata already installed: $(command -v suricata)"
    else
        log "Adding OISF repository and installing Suricata..."
        case "$PKG_FAMILY" in
            apt)
                # OISF ships Suricata on Launchpad PPA ppa:oisf/suricata-stable
                # (the packages.openinfosecfoundation.org domain does not exist).
                # Mirror the Wazuh PoC: https://documentation.wazuh.com/current/proof-of-concept-guide/integrate-network-ids-suricata.html
                if ! apt-cache policy suricata 2>/dev/null | grep -q 'oisf/suricata-stable'; then
                    log "Adding OISF Launchpad PPA: ppa:oisf/suricata-stable"
                    DEBIAN_FRONTEND=noninteractive apt-get install -y software-properties-common >/dev/null 2>&1 || true
                    add-apt-repository -y ppa:oisf/suricata-stable || die "add-apt-repository failed"
                    apt-get update -y || die "apt-get update failed"
                fi
                DEBIAN_FRONTEND=noninteractive apt-get install -y suricata \
                    || die "apt-get install suricata failed"
                # suricata-update is a separate Python package; best-effort.
                # Not required: the installer uses the direct ET Open tarball path.
                if command -v pip3 >/dev/null 2>&1; then
                    pip3 install --quiet --upgrade --break-system-packages suricata-update 2>/dev/null || \
                    pip3 install --quiet --upgrade suricata-update 2>/dev/null || \
                        log "pip install suricata-update failed (continuing on direct tarball path)"
                elif command -v pip >/dev/null 2>&1; then
                    pip install --quiet --upgrade suricata-update 2>/dev/null || \
                        log "pip install suricata-update failed (continuing on direct tarball path)"
                else
                    log "pip not present; skipping suricata-update (direct tarball path used instead)"
                fi
                ;;
            rpm)
                # Suricata is in EPEL on RHEL/Rocky/Fedora (no separate repo needed).
                if ! rpm -q epel-release >/dev/null 2>&1; then
                    log "Enabling EPEL..."
                    dnf install -y epel-release elrepo-release >/dev/null 2>&1 || \
                    dnf install -y epel-release >/dev/null 2>&1 || \
                    yum install -y epel-release >/dev/null 2>&1 || \
                        die "Cannot enable EPEL"
                fi
                dnf install -y suricata suricata-update \
                    || yum install -y suricata suricata-update \
                    || die "Package install failed (tried dnf and yum)"
                ;;
        esac
        log "Suricata installed: $(command -v suricata)"
    fi

    if ! command -v suricata >/dev/null 2>&1; then
        die "suricata binary not found after install"
    fi
}

# -------------------------------------
# Detect capture interfaces (parallel to Windows Get-CaptureInterfaces)
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
    local ifaces=()
    for iface_dir in /sys/class/net/*/; do
        local iface
        iface=$(basename "$iface_dir")
        if [[ "$iface" =~ $deny_re ]]; then continue; fi
        # Must be a real device with a link (ethernet or wireless), not a phantom alias
        [ -e "/sys/class/net/$iface/device" ] || continue
        # state UP preferred
        ifaces+=("$iface")
    done

    if [ ${#ifaces[@]} -eq 0 ]; then
        die "No capture interface found. Pass -Interface <name>."
    fi

    # Sort by speed desc (missing speed treated as 0)
    local sorted=()
    for iface in "${ifaces[@]}"; do
        local speed=0
        if [ -r "/sys/class/net/$iface/speed" ]; then
            speed=$(cat "/sys/class/net/$iface/speed" 2>/dev/null || echo 0)
        fi
        echo "$speed $iface"
    done | sort -rn -k1,1 | awk '{print $2}'
}

# -------------------------------------
# Suricata.yaml patch (mirrors Windows Set-SuricataYaml — conservative)
# -------------------------------------
yaml_self_heal() {
    local yaml="$1"
    if ! grep -qE '^\s*rule-files:' "$yaml" || ! grep -qE '^\s*app-layer:' "$yaml"; then
        log "WARNING: $yaml looks incomplete — searching for intact backup..."
        local bak
        bak=$(ls -1t "${yaml}".*.bak 2>/dev/null | while read -r f; do
            if grep -qE '^\s*rule-files:' "$f" && grep -qE '^\s*app-layer:' "$f"; then
                echo "$f"; break
            fi
        done | head -n1)
        if [ -n "$bak" ] && [ -r "$bak" ]; then
            cp -a "$bak" "$yaml"
            log "Restored intact suricata.yaml from: $bak"
        else
            die "suricata.yaml is incomplete and no intact backup found. Reinstall the suricata package, then re-run."
        fi
    fi
}

yaml_set_kv() {
    # Replace single-line `key: value` (first match only). If key missing, insert before first top-level section.
    local file="$1" key="$2" value="$3"
    local tmp
    tmp=$(mktemp)
    if grep -qE "^\s*${key}\s*:" "$file"; then
        sed -E "0,/^\s*${key}\s*:.*$/s||${key}: ${value}|" "$file" > "$tmp"
    else
        # Insert at top (Suricata tolerates leading key/value pairs)
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

    # Single-line path keys only. Do NOT regex af-packet or eve-log blocks
    # (a greedy regex previously truncated the whole file).
    yaml_set_kv "$yaml" "default-log-dir"   "/var/log/suricata/"
    yaml_set_kv "$yaml" "default-rule-path" "/etc/suricata/rules/"

    log "Patched suricata.yaml (default-log-dir, default-rule-path): $yaml"
}

# -------------------------------------
# ET Open rules (mirror Windows Invoke-RuleUpdate — direct tarball)
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

    # Config test (non-fatal — record exit code only)
    if suricata -T -c "$SURICATA_YAML" >/tmp/suricata-T.log 2>&1; then
        log "Config test (suricata -T) passed."
    else
        log "Config test returned non-zero (see /tmp/suricata-T.log) — continuing."
    fi
}

# -------------------------------------
# Start Suricata via systemd
# -------------------------------------
start_suricata() {
    if [ ! -f /etc/systemd/system/suricata.service ] && \
       ! systemctl list-unit-files suricata.service >/dev/null 2>&1; then
        log "WARNING: suricata.service not found in systemd unit path; trying direct exec."
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
    # Strip any pre-existing Suricata eve.json <localfile> block (multiline safe)
    python3 - "$WAZUH_CONF" "$EVE_LOG" "$tmp" <<'PY'
import re, sys
src, eve, dst = sys.argv[1], sys.argv[2], sys.argv[3]
with open(src, 'r', encoding='utf-8') as f:
    content = f.read()
# Remove any existing <localfile>...</localfile> whose body mentions eve.json
pat = re.compile(r'<localfile>(?:(?!</localfile>).)*?eve\.json(?:(?!</localfile>).)*?</localfile>\s*', re.DOTALL)
new = pat.sub('', content)
block = f'    <localfile>\n      <log_format>json</log_format>\n      <location>{eve}</location>\n    </localfile>\n'
if re.search(r'</ossec_config>', new):
    new = re.sub(r'\s*</ossec_config>\s*$', f'\n{block}</ossec_config>\n', new, count=1)
else:
    new = new + '\n' + block
with open(dst, 'w', encoding='utf-8') as f:
    f.write(new)
PY
    mv "$tmp" "$WAZUH_CONF"
    log "Patched Wazuh ossec.conf -> $EVE_LOG"

    if systemctl list-unit-files wazuh-agent.service >/dev/null 2>&1; then
        systemctl restart wazuh-agent || log "systemctl restart wazuh-agent failed (continuing)"
        log "Restarted wazuh-agent."
    else
        log "wazuh-agent.service not found — user must restart agent manually."
    fi
}

# -------------------------------------
# Drop maintenance script (template + sed replace)
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
    # Shift archives: eve.json.K -> eve.json.(K+1); drop beyond KEEP
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
    # Placeholders were literal above; insert real values now
    sed -i "s|__LOG_DIR__|${LOG_DIR}|g; s|__RULE_DIR__|${RULE_DIR}|g" "$MAINT_SCRIPT"
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
# -------------------------------------
write_logrotate() {
    cat > /etc/logrotate.d/suricata <<EOF
/var/log/suricata/*.json {
    daily
    missingok
    rotate ${KEEP_ROTATED_LOGS}
    size ${MAX_EVE_BYTES}
    compress
    notifempty
    sharedscripts
    postrotate
        systemctl restart suricata > /dev/null 2>&1 || true
    endscript
}
EOF
    log "Wrote /etc/logrotate.d/suricata"
}

# -------------------------------------
# Main
# -------------------------------------
main() {
    ensure_dir "$LOG_DIR"
    install_suricata

    log "Detecting capture interfaces..."
    local ifaces=()
    while IFS= read -r line; do
        [ -n "$line" ] && ifaces+=("$line")
    done < <(detect_interfaces)
    log "Capture interfaces: ${ifaces[*]:-<none>}"

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