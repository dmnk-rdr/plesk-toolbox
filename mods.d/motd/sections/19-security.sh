#!/usr/bin/env bash
# motd section: pending updates + recent bans
PTBOX_ROOT="${PTBOX_ROOT:-/opt/plesk-toolbox}"
CACHE_DIR="${MOTD_CACHE_DIR:-/var/cache/server-motd}"
# shellcheck source=../../../lib/common.sh
. "${PTBOX_ROOT}/lib/common.sh" 2>/dev/null || exit 0

updates="$(cat "${CACHE_DIR}/updates.count" 2>/dev/null || echo 0)"
if (( updates > 0 )); then
    label_line "updates" "${C_YEL:-}${updates} pending${C_RST:-}"
else
    label_line "updates" "${C_GRN:-}system up to date${C_RST:-}"
fi

if command -v fail2ban-client >/dev/null 2>&1; then
    jails="$(cat "${CACHE_DIR}/f2b.jails" 2>/dev/null | paste -sd, -)"
    [[ -n "$jails" ]] && label_line "fail2ban" "${jails}"
fi
