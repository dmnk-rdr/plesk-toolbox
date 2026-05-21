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

printf '\n  %s%-14s%s ' "${C_DIM:-}" "services" "${C_RST:-}"
for svc in "${services[@]}"; do
    # Only render if unit exists
    if ! systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "${svc}.service"; then
        continue
    fi
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        printf '%s●%s %s  ' "${C_GRN:-}" "${C_RST:-}" "$svc"
    else
        printf '%s●%s %s  ' "${C_RED:-}" "${C_RST:-}" "$svc"
    fi
done
printf '\n'
