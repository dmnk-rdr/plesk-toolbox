#!/usr/bin/env bash
# motd section: critical service status
PTBOX_ROOT="${PTBOX_ROOT:-/opt/plesk-toolbox}"
# shellcheck source=../../../lib/common.sh
. "${PTBOX_ROOT}/lib/common.sh" 2>/dev/null || exit 0
_load_config 2>/dev/null || true

# MOTD_SERVICES can be a bash array or space-separated string from config
if declare -p MOTD_SERVICES 2>/dev/null | grep -q 'declare -a'; then
    services=("${MOTD_SERVICES[@]}")
else
    read -r -a services <<< "${MOTD_SERVICES:-nginx apache2 mariadb postfix dovecot fail2ban sw-cp-server psa}"
fi

# Alias declared service names to whatever unit the distro actually installs
# (Debian/Ubuntu uses apache2/mysql; CentOS/RHEL uses httpd/mariadb).
declare -A _MOTD_SVC_ALIASES=(
    [apache2]="apache2 httpd"
    [httpd]="httpd apache2"
    [mariadb]="mariadb mysql mysqld"
    [mysql]="mysql mariadb mysqld"
)

_motd_resolve_unit() {
    local name="$1"
    local candidates="${_MOTD_SVC_ALIASES[$name]:-$name}"
    local c
    for c in $candidates; do
        if systemctl list-unit-files --type=service 2>/dev/null \
            | awk '{print $1}' | grep -qx "${c}.service"; then
            printf '%s' "$c"; return 0
        fi
    done
    return 1
}

printf '\n  %s%-14s%s ' "${C_DIM:-}" "services" "${C_RST:-}"
for svc in "${services[@]}"; do
    unit="$(_motd_resolve_unit "$svc")" || continue
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        printf '%s●%s %s  ' "${C_GRN:-}" "${C_RST:-}" "$unit"
    else
        printf '%s●%s %s  ' "${C_RED:-}" "${C_RST:-}" "$unit"
    fi
done
printf '\n'
