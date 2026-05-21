# audits.d/sec/32-plesk-fail2ban.sh - fail2ban / IP ban service status
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "security: fail2ban"

if ! command -v fail2ban-client >/dev/null 2>&1; then
    emit "sec.plesk.panel_fail2ban" "medium" "warn" "fail2ban not installed" \
        "enable in Plesk: Tools & Settings → IP Address Banning (Fail2Ban)"
    return 0
fi

if ! systemctl is-active --quiet fail2ban 2>/dev/null; then
    emit "sec.plesk.panel_fail2ban" "high" "fail" "fail2ban.service not active" \
        "systemctl enable --now fail2ban"
    return 0
fi

# Report active jails
jails="$(fail2ban-client status 2>/dev/null | awk -F: '/Jail list/ {gsub(/[ \t]/,"",$2); print $2}')"
if [[ -z "$jails" ]]; then
    emit "sec.plesk.panel_fail2ban" "medium" "warn" "fail2ban running but no jails active"
else
    count="$(tr ',' '\n' <<< "$jails" | wc -l)"
    emit "sec.plesk.panel_fail2ban" "medium" "pass" "fail2ban active, ${count} jail(s): ${jails}"
fi

# Recent bans: try sqlite db if present
if [[ -r /var/lib/fail2ban/fail2ban.sqlite3 ]] && command -v sqlite3 >/dev/null 2>&1; then
    recent="$(sqlite3 /var/lib/fail2ban/fail2ban.sqlite3 \
        "SELECT COUNT(*) FROM bans WHERE timeofban > strftime('%s','now','-24 hours');" 2>/dev/null || echo 0)"
    emit "sec.plesk.panel_fail2ban_recent" "info" "pass" "${recent} bans in last 24h"
fi
