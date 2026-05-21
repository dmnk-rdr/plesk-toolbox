# audits.d/sec/30-plesk-panel.sh - Plesk panel security settings
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "security: Plesk panel"

if ! _plesk_available; then
    emit "sec.plesk.available" "high" "skip" "plesk CLI not found"
    return 0
fi

version="$(_plesk_version || echo unknown)"
emit "sec.plesk.version" "info" "pass" "Plesk ${version}"

# Admin panel 2FA
if plesk bin server_pref --show-2fa 2>/dev/null | grep -qi 'enabled: *true'; then
    emit "sec.plesk.panel_2fa" "high" "pass" "2FA enabled on panel"
else
    emit "sec.plesk.panel_2fa" "high" "warn" "panel 2FA not enabled" \
        "enable in Plesk: Tools & Settings → Two-factor Authentication"
fi

# Panel cert: is a real cert installed (not the default self-signed)?
default_cert="/usr/local/psa/admin/conf/httpsd.pem"
if [[ -r "$default_cert" ]]; then
    subject="$(openssl x509 -in "$default_cert" -noout -subject 2>/dev/null | sed 's/^subject= *//')"
    if grep -qi 'plesk\|localhost' <<< "$subject"; then
        emit "sec.plesk.panel_cert" "medium" "warn" \
            "panel cert looks self-signed (${subject})" \
            "replace with Let's Encrypt cert for the panel hostname"
    else
        emit "sec.plesk.panel_cert" "medium" "pass" "panel cert: ${subject}"
    fi
fi

# Admin email: must not be left as root@localhost
admin_email="$(plesk bin admin --info 2>/dev/null | awk -F: '/email/ {sub(/^ /,"",$2); print $2; exit}')"
if [[ -z "$admin_email" || "$admin_email" == "root@localhost" ]]; then
    emit "sec.plesk.admin_email" "low" "warn" "admin email: ${admin_email:-unset}" \
        "set a real admin email (Tools & Settings → Server Administrator)"
else
    emit "sec.plesk.admin_email" "low" "pass" "admin email set"
fi
