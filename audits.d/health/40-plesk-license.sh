# audits.d/health/40-plesk-license.sh - Plesk license status + expiry
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "health: Plesk license"

if ! _plesk_available; then
    emit "health.plesk.license" "medium" "skip" "plesk CLI not found"
    return 0
fi

# `plesk bin license -c` returns 0 if the installed key is valid, 1 otherwise.
if plesk bin license -c >/dev/null 2>&1; then
    emit "health.plesk.license_status" "high" "pass" "license is valid"
else
    emit "health.plesk.license_status" "high" "fail" "license check failed" \
        "run: plesk bin license -c (or contact reseller / Plesk support)"
fi

# `plesk bin keyinfo --list` dumps key=value pairs we can parse.
info="$(plesk bin keyinfo --list 2>/dev/null || true)"
if [[ -z "$info" ]]; then
    emit "health.plesk.license_info" "low" "skip" "keyinfo --list returned nothing"
    return 0
fi

edition="$(awk -F': *' '/^edition-name:/ {print $2; exit}' <<< "$info")"
[[ -n "$edition" ]] && emit "health.plesk.license_edition" "info" "pass" "edition: ${edition}"

# lim_date is YYYYMMDD; convert to days remaining.
lim_date="$(awk -F': *' '/^lim_date:/ {print $2; exit}' <<< "$info")"
if [[ "$lim_date" =~ ^[0-9]{8}$ ]]; then
    y="${lim_date:0:4}"; m="${lim_date:4:2}"; d="${lim_date:6:2}"
    end_epoch="$(date -d "${y}-${m}-${d}" +%s 2>/dev/null || echo 0)"
    now_epoch="$(date +%s)"
    days=$(( (end_epoch - now_epoch) / 86400 ))
    msg="expires in ${days}d (${y}-${m}-${d})"
    if   (( days < 0 ));   then emit "health.plesk.license_expiry" "high"   "fail" "$msg" \
                                     "renew the Plesk license"
    elif (( days < 14 ));  then emit "health.plesk.license_expiry" "high"   "warn" "$msg"
    elif (( days < 45 ));  then emit "health.plesk.license_expiry" "medium" "warn" "$msg"
    else                         emit "health.plesk.license_expiry" "info"  "pass" "$msg"
    fi
fi
