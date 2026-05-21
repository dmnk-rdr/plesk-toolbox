#!/usr/bin/env bash
# motd section: OS, kernel, uptime, IPs
PTBOX_ROOT="${PTBOX_ROOT:-/opt/plesk-toolbox}"
CACHE_DIR="${MOTD_CACHE_DIR:-/var/cache/server-motd}"
# shellcheck source=../../../lib/common.sh
. "${PTBOX_ROOT}/lib/common.sh" 2>/dev/null || exit 0

os="unknown"
if [[ -r /etc/os-release ]]; then
    # shellcheck source=/dev/null
    . /etc/os-release
    os="${PRETTY_NAME:-${NAME:-unknown}}"
fi
kernel="$(uname -r)"
uptime_s="$(cut -d' ' -f1 /proc/uptime 2>/dev/null || echo 0)"
days=$(( ${uptime_s%.*} / 86400 ))
hours=$(( (${uptime_s%.*} % 86400) / 3600 ))
uptime_h="${days}d ${hours}h"

primary_ip="$(ip -4 -o route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if ($i=="src") print $(i+1)}')"
primary_ip="${primary_ip:-n/a}"
public_ip="$(cat "${CACHE_DIR}/public_ip" 2>/dev/null || echo '')"

printf '\n'
label_line "os"       "$os"
label_line "kernel"   "$kernel"
label_line "uptime"   "$uptime_h"
label_line "ipv4"     "$primary_ip${public_ip:+  (public: $public_ip)}"

# Plesk version if available
if command -v plesk >/dev/null 2>&1; then
    pv="$(plesk version 2>/dev/null | awk -F: '/Product version/ {gsub(/ /,"",$2); print $2; exit}')"
    [[ -n "$pv" ]] && label_line "plesk" "$pv"
fi
