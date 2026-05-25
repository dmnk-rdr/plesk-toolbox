# audits.d/sec/50-web-tls.sh — per-domain TLS certificate expiry on :443
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"
# shellcheck source=../../lib/tls.sh
. "${PTBOX_ROOT}/lib/tls.sh"

section "security: web TLS"

: "${WEB_TLS_MAX_DOMAINS:=25}"
: "${WEB_DOMAIN_TRUNCATE:=22}"

if ! _plesk_available; then
    emit "sec.web.tls" "medium" "skip" "plesk CLI not available"
    return 0
fi

mapfile -t domains < <(_plesk_domains 2>/dev/null || true)
if (( ${#domains[@]} == 0 )); then
    emit "sec.web.tls" "medium" "skip" "no hosted domains"
    return 0
fi

table_init "Domain" "Cert" "Days"

checked=0
for d in "${domains[@]}"; do
    (( checked >= WEB_TLS_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    label="$(truncate "$d" "$WEB_DOMAIN_TRUNCATE")"

    if ! timeout 3 bash -c ">/dev/tcp/${d}/443" 2>/dev/null; then
        table_row "$label" "$(status_cell skip 'no-443')" "—"
        emit "sec.web.tls.${d}" "low" "skip" "${d}: no connection on 443"
        continue
    fi

    days="$(_tls_cert_days "$d" 443 2>/dev/null || echo -1)"
    if (( days < 0 )); then
        table_row "$label" "$(status_cell fail 'read-err')" "—"
        emit "sec.web.tls.${d}" "high" "fail" "${d}: cert read failed"
    elif (( days < 7 )); then
        table_row "$label" "$(status_cell fail 'expiring')" "$days"
        emit "sec.web.tls.${d}" "high" "fail" "${d}: cert expires in ${days}d" \
            "renew the certificate (Let's Encrypt or reissue)"
    elif (( days < 21 )); then
        table_row "$label" "$(status_cell warn 'renew')" "$days"
        emit "sec.web.tls.${d}" "medium" "warn" "${d}: cert expires in ${days}d"
    else
        table_row "$label" "$(status_cell pass 'valid')" "$days"
        emit "sec.web.tls.${d}" "info" "pass" "${d}: ${days}d remaining"
    fi
done

table_render

(( checked > 0 )) || emit "sec.web.tls" "info" "skip" "no domains checked"
