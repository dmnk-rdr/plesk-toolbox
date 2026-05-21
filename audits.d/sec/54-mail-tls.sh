# audits.d/sec/54-mail-tls.sh - per-mail-domain TLS for SMTP/IMAP/POP
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"
# shellcheck source=../../lib/tls.sh
. "${PTBOX_ROOT}/lib/tls.sh"

section "security: mail TLS"

: "${MAIL_TLS_MAX_DOMAINS:=25}"
: "${MAIL_TLS_PORTS:=25 465 587 993 995}"

if ! _plesk_available; then
    emit "sec.mail.tls" "medium" "skip" "plesk CLI not available"
    return 0
fi

if ! command -v openssl >/dev/null 2>&1; then
    emit "sec.mail.tls" "medium" "skip" "openssl(1) not available"
    return 0
fi

if ! _plesk_mail_in_use; then
    emit "sec.mail.tls" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
if (( ${#domains[@]} == 0 )); then
    emit "sec.mail.tls" "info" "skip" "no mail-enabled domains"
    return 0
fi

# Map TCP port → STARTTLS protocol identifier expected by `openssl s_client`
_starttls_for_port() {
    case "$1" in
        25|587) printf 'smtp' ;;
        143)    printf 'imap' ;;
        110)    printf 'pop3' ;;
        *)      printf '' ;;
    esac
}

_port_label() {
    case "$1" in
        25)  printf 'smtp' ;;
        465) printf 'smtps' ;;
        587) printf 'submission' ;;
        993) printf 'imaps' ;;
        995) printf 'pop3s' ;;
        143) printf 'imap' ;;
        110) printf 'pop3' ;;
        *)   printf 'port%s' "$1" ;;
    esac
}

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_TLS_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    host="mail.${d}"

    # Resolve once — skip cleanly if mail.<d> doesn't even have a record
    if ! dig +short A "$host" 2>/dev/null | grep -q '.' \
        && ! dig +short AAAA "$host" 2>/dev/null | grep -q '.'; then
        emit "sec.mail.tls_dns.${d}" "low" "skip" "${host}: no A/AAAA record"
        continue
    fi

    for port in $MAIL_TLS_PORTS; do
        label="$(_port_label "$port")"
        id_base="sec.mail.tls.${d}.${label}"

        # Reachability — short TCP probe, no full handshake yet
        if ! timeout 3 bash -c ">/dev/tcp/${host}/${port}" 2>/dev/null; then
            emit "${id_base}" "low" "skip" "${host}:${port}: not reachable"
            continue
        fi

        starttls="$(_starttls_for_port "$port")"
        days="$(_tls_cert_days "$host" "$port" "$starttls" 2>/dev/null || echo -1)"

        if (( days < 0 )); then
            emit "${id_base}" "high" "fail" "${host}:${port}: cert read failed" \
                "verify ${label} TLS is configured and the service responds"
        elif (( days < 7 )); then
            emit "${id_base}" "high" "fail" "${host}:${port}: cert expires in ${days}d" \
                "renew certificate (Plesk → Tools & Settings → SSL/TLS Certificates)"
        elif (( days < 21 )); then
            emit "${id_base}" "medium" "warn" "${host}:${port}: cert expires in ${days}d"
        else
            emit "${id_base}" "info" "pass" "${host}:${port}: ${days}d remaining"
        fi

        # Hostname-match: cert subject/SAN should cover mail.<d>
        # (don't run if cert read already failed)
        if (( days >= 0 )); then
            local_starttls_opt=()
            [[ -n "$starttls" ]] && local_starttls_opt=(-starttls "$starttls")
            subj_san="$(echo | timeout 5 openssl s_client \
                "${local_starttls_opt[@]}" \
                -connect "${host}:${port}" -servername "$host" 2>/dev/null \
                | openssl x509 -noout -ext subjectAltName -subject 2>/dev/null)"
            if [[ -n "$subj_san" ]] \
                && ( grep -qiE "DNS:${host}([^A-Za-z0-9.-]|$)" <<< "$subj_san" \
                  || grep -qiE "DNS:\*\.${d}([^A-Za-z0-9.-]|$)" <<< "$subj_san" \
                  || grep -qiE "CN ?= ?${host}" <<< "$subj_san" ); then
                : # matches, no extra emit
            else
                emit "${id_base}.match" "medium" "warn" \
                    "${host}:${port}: cert does not list ${host}" \
                    "reissue mail cert covering ${host} (or a wildcard *.${d})"
            fi
        fi
    done
done

(( checked > 0 )) || emit "sec.mail.tls" "info" "skip" "no domains checked"
