# audits.d/health/40-plesk-license.sh - Plesk license status and expiry
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "health: Plesk license"

if ! _plesk_available; then
    emit "health.plesk.license" "medium" "skip" "plesk CLI not found"
    return 0
fi

info="$(plesk bin license --info 2>/dev/null || true)"
if [[ -z "$info" ]]; then
    emit "health.plesk.license" "medium" "warn" "license info unreadable"
    return 0
fi

status="$(awk -F: '/^Status/ {sub(/^ /,"",$2); print $2; exit}' <<< "$info")"
exp_date="$(awk -F: '/^Expiration date/ {sub(/^ /,"",$2); print $2; exit}' <<< "$info")"

if [[ "${status,,}" != "ok" && "${status,,}" != "active" ]]; then
    emit "health.plesk.license_status" "high" "fail" "license status: ${status:-unknown}" \
        "contact Plesk support / reseller"
else
    emit "health.plesk.license_status" "high" "pass" "license status: ${status}"
fi

if [[ -n "$exp_date" ]]; then
    end_epoch="$(date -d "$exp_date" +%s 2>/dev/null || echo 0)"
    now_epoch="$(date +%s)"
    days=$(( (end_epoch - now_epoch) / 86400 ))
    msg="expires in ${days}d (${exp_date})"
    if   (( days < 0 ));   then emit "health.plesk.license_expiry" "high"   "fail" "$msg"
    elif (( days < 14 ));  then emit "health.plesk.license_expiry" "high"   "warn" "$msg"
    elif (( days < 45 ));  then emit "health.plesk.license_expiry" "medium" "warn" "$msg"
    else                         emit "health.plesk.license_expiry" "info"  "pass" "$msg"
    fi
fi
