#!/usr/bin/env bash
# motd section: branded header
PTBOX_ROOT="${PTBOX_ROOT:-/opt/plesk-toolbox}"
# shellcheck source=../../../lib/common.sh
. "${PTBOX_ROOT}/lib/common.sh" 2>/dev/null || { C_RST=''; C_BOLD=''; C_CYN=''; }
_load_config 2>/dev/null || true

: "${MOTD_BRAND:=Plesk Server}"
hostname="$(hostname -f 2>/dev/null || hostname)"

printf '\n'
printf '%s╔══════════════════════════════════════════════════════════════╗%s\n' "$C_CYN" "$C_RST"
printf '%s║%s %s%-60s%s %s║%s\n' "$C_CYN" "$C_RST" "$C_BOLD" "$MOTD_BRAND" "$C_RST" "$C_CYN" "$C_RST"
printf '%s║%s %-60s %s║%s\n' "$C_CYN" "$C_RST" "$hostname" "$C_CYN" "$C_RST"
printf '%s╚══════════════════════════════════════════════════════════════╝%s\n' "$C_CYN" "$C_RST"
