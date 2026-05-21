# audits.d/sec/50-web-tls.sh - per-domain TLS certificate check
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"
# shellcheck source=../../lib/tls.sh
. "${PTBOX_ROOT}/lib/tls.sh"

section "security: per-domain TLS"

: "${WEB_TLS_MAX_DOMAINS:=25}"

if ! _plesk_available; then
    emit "sec.web.tls" "medium" "skip" "plesk CLI not available"
    return 0
fi

mapfile -t domains < <(_plesk_domains 2>/dev/null || true)
if [[ "${#domains[@]}" -eq 0 ]]; then
    emit "sec.web.tls" "medium" "skip" "no hosted domains"
    return 0
fi

checked=0
for d in "${domains[@]}"; do
    (( checked >= WEB_TLS_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    # Fast port 443 liveness
    if ! timeout 3 bash -c ">/dev/tcp/${d}/443" 2>/dev/null; then
        emit "sec.web.tls_reach.${d}" "low" "skip" "${d}: no connection on 443"
        continue
    fi

    days="$(_tls_cert_days "$d" 443 2>/dev/null || echo -1)"
    if (( days < 0 )); then
        emit "sec.web.tls_cert.${d}" "high" "fail" "${d}: cert read failed"
    elif (( days < 7 )); then
        emit "sec.web.tls_cert.${d}" "high" "fail" "${d}: cert expires in ${days}d" \
            "renew the certificate (Let's Encrypt or reissue)"
    elif (( days < 21 )); then
        emit "sec.web.tls_cert.${d}" "medium" "warn" "${d}: cert expires in ${days}d"
    else
        emit "sec.web.tls_cert.${d}" "info" "pass" "${d}: ${days}d remaining"
    fi
done

(( checked > 0 )) || emit "sec.web.tls" "info" "skip" "no domains checked"
