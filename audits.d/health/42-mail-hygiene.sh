# audits.d/health/42-mail-hygiene.sh - per-domain SPF/DKIM/DMARC
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "health: mail DNS hygiene"

: "${MAIL_HYGIENE_MAX_DOMAINS:=50}"
: "${DKIM_SELECTOR:=}"
: "${MAIL_HYGIENE_NULL_MX_INFO:=1}"

if ! _plesk_available; then
    emit "health.mail.hygiene" "medium" "skip" "plesk CLI not available"
    return 0
fi

if ! command -v dig >/dev/null 2>&1; then
    emit "health.mail.hygiene" "medium" "skip" "dig(1) not available"
    return 0
fi

if ! _plesk_mail_in_use; then
    emit "health.mail.hygiene" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
(( ${#domains[@]} > 0 )) || { emit "health.mail.hygiene" "info" "skip" "no mail-enabled domains"; return 0; }

# Determine DKIM selector: config override → plesk bin dkim → "default"
_resolve_selector() {
    local d="$1"
    [[ -n "$DKIM_SELECTOR" ]] && { printf '%s' "$DKIM_SELECTOR"; return; }
    local sel
    sel="$(plesk bin dkim --info "$d" 2>/dev/null | awk -F: '/selector/ {sub(/^ /,"",$2); print $2; exit}')"
    printf '%s' "${sel:-default}"
}

# Detect Null-MX (RFC 7505): a single "0 ." record means the domain refuses mail
_is_null_mx() {
    local d="$1"
    local mx
    mx="$(dig +short MX "$d" 2>/dev/null | awk '{print $1, $2}' | tr -d '"')"
    [[ "$mx" == "0 ." ]]
}

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_HYGIENE_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    # Null-MX short-circuit: domain says "don't send me mail"
    if _is_null_mx "$d"; then
        if (( MAIL_HYGIENE_NULL_MX_INFO == 1 )); then
            emit "health.mail.null_mx.${d}" "info" "pass" "${d}: Null-MX (RFC 7505)"
            continue
        fi
    fi

    # SPF
    if dig +short TXT "$d" 2>/dev/null | grep -q 'v=spf1'; then
        emit "health.mail.spf.${d}" "low" "pass" "${d}: SPF present"
    else
        emit "health.mail.spf.${d}" "medium" "warn" "${d}: no SPF record" \
            "add: v=spf1 +a +mx +a:${d} -all"
    fi

    # DMARC
    if dig +short TXT "_dmarc.${d}" 2>/dev/null | grep -q 'v=DMARC1'; then
        emit "health.mail.dmarc.${d}" "low" "pass" "${d}: DMARC present"
    else
        emit "health.mail.dmarc.${d}" "medium" "warn" "${d}: no DMARC record" \
            "add _dmarc TXT: v=DMARC1; p=quarantine; rua=mailto:postmaster@${d}"
    fi

    # DKIM (dynamic selector)
    sel="$(_resolve_selector "$d")"
    if dig +short TXT "${sel}._domainkey.${d}" 2>/dev/null | grep -q 'v=DKIM1'; then
        emit "health.mail.dkim.${d}" "low" "pass" "${d}: DKIM present (sel=${sel})"
    else
        emit "health.mail.dkim.${d}" "medium" "warn" "${d}: no DKIM (sel=${sel})" \
            "enable DKIM in Plesk Mail settings"
    fi
done
