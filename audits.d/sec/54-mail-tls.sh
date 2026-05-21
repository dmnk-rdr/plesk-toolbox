# audits.d/sec/54-mail-tls.sh - per-mail-domain TLS for SMTP/IMAP/POP
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"
# shellcheck source=../../lib/tls.sh
. "${PTBOX_ROOT}/lib/tls.sh"

section "security: mail TLS"

: "${MAIL_TLS_MAX_DOMAINS:=25}"
: "${MAIL_TLS_PORTS:=25 465 587 993 995}"
: "${MAIL_TLS_CONNECT_TIMEOUT:=5}"

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

# One openssl connection per (host,port). Parses both expiry and SAN/CN
# from the same handshake. Sets globals: CERT_DAYS, CERT_NAMES.
_probe_cert() {
    local host="$1" port="$2" starttls="$3"
    local starttls_opt=()
    [[ -n "$starttls" ]] && starttls_opt=(-starttls "$starttls")
    CERT_DAYS=-1
    CERT_NAMES=""
    local cert_text
    cert_text="$(echo | timeout "$MAIL_TLS_CONNECT_TIMEOUT" openssl s_client \
        "${starttls_opt[@]}" \
        -connect "${host}:${port}" -servername "$host" 2>/dev/null \
        | openssl x509 -noout -enddate -ext subjectAltName -subject 2>/dev/null)" || return 1
    [[ -z "$cert_text" ]] && return 1

    local end_date end_epoch now_epoch
    end_date="$(awk -F= '/^notAfter=/ {print $2; exit}' <<< "$cert_text")"
    [[ -z "$end_date" ]] && return 1
    end_epoch="$(date -d "$end_date" +%s 2>/dev/null)" || return 1
    now_epoch="$(date +%s)"
    CERT_DAYS=$(( (end_epoch - now_epoch) / 86400 ))

    # SAN line (if present) + subject CN — both reduced to lowercase tokens.
    local san_line subj_cn
    san_line="$(grep -A1 'X509v3 Subject Alternative Name' <<< "$cert_text" \
                | tail -n1 | tr ',' '\n' | sed 's/^[[:space:]]*DNS://I' \
                | tr '[:upper:]' '[:lower:]' | tr -d ' ')"
    subj_cn="$(awk -F'CN ?= ?' '/^subject=/ {print $2; exit}' <<< "$cert_text" \
                | awk -F, '{print $1}' | tr '[:upper:]' '[:lower:]' \
                | tr -d ' ')"
    CERT_NAMES="$(printf '%s\n%s\n' "$san_line" "$subj_cn" | sort -u)"
    return 0
}

# Match a hostname against the names extracted from the cert (incl. wildcards).
_cert_matches() {
    local host="${1,,}" names="$2" n
    while IFS= read -r n; do
        [[ -z "$n" ]] && continue
        if [[ "$n" == "$host" ]]; then return 0; fi
        if [[ "$n" == "*."* ]]; then
            # wildcard *.example.com matches one label deep
            local suffix="${n#\*.}"
            # shellcheck disable=SC2295  # suffix is a domain; glob/literal equivalent
            [[ "$host" == *."$suffix" && "${host%.${suffix}}" != *.* ]] && return 0
        fi
    done <<< "$names"
    return 1
}

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_TLS_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    host="mail.${d}"

    # Resolve once — skip cleanly if mail.<d> has no record at all
    if ! dig +short A "$host" 2>/dev/null | grep -q '.' \
        && ! dig +short AAAA "$host" 2>/dev/null | grep -q '.'; then
        emit "sec.mail.tls_dns.${d}" "low" "skip" "${host}: no A/AAAA record"
        continue
    fi

    for port in $MAIL_TLS_PORTS; do
        label="$(_port_label "$port")"
        id_base="sec.mail.tls.${d}.${label}"

        # Reachability — short TCP probe before the handshake
        if ! timeout 3 bash -c ">/dev/tcp/${host}/${port}" 2>/dev/null; then
            emit "${id_base}" "low" "skip" "${host}:${port}: not reachable"
            continue
        fi

        starttls="$(_starttls_for_port "$port")"
        if ! _probe_cert "$host" "$port" "$starttls"; then
            emit "${id_base}" "high" "fail" "${host}:${port}: cert read failed" \
                "verify ${label} TLS is configured and the service responds"
            continue
        fi

        if (( CERT_DAYS < 7 )); then
            emit "${id_base}" "high" "fail" "${host}:${port}: cert expires in ${CERT_DAYS}d" \
                "renew certificate (Plesk → Tools & Settings → SSL/TLS Certificates)"
        elif (( CERT_DAYS < 21 )); then
            emit "${id_base}" "medium" "warn" "${host}:${port}: cert expires in ${CERT_DAYS}d"
        else
            emit "${id_base}" "info" "pass" "${host}:${port}: ${CERT_DAYS}d remaining"
        fi

        if ! _cert_matches "$host" "$CERT_NAMES"; then
            emit "${id_base}.match" "medium" "warn" \
                "${host}:${port}: cert does not list ${host}" \
                "reissue mail cert covering ${host} (or a wildcard *.${d})"
        fi
    done
done

(( checked > 0 )) || emit "sec.mail.tls" "info" "skip" "no domains checked"
