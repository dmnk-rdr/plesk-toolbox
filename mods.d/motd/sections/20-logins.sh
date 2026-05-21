#!/usr/bin/env bash
# motd section: last 5 logins
PTBOX_ROOT="${PTBOX_ROOT:-/opt/plesk-toolbox}"
CACHE_DIR="${MOTD_CACHE_DIR:-/var/cache/server-motd}"
# shellcheck source=../../../lib/common.sh
. "${PTBOX_ROOT}/lib/common.sh" 2>/dev/null || exit 0

last_file="${CACHE_DIR}/last.txt"
[[ -s "$last_file" ]] || exit 0

printf '\n  %s%-14s%s\n' "${C_DIM:-}" "recent logins" "${C_RST:-}"
sed 's/^/    /' "$last_file"
printf '\n'
