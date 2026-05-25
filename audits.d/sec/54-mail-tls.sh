# audits.d/sec/54-mail-tls.sh — per-mail-domain TLS on SMTP/IMAP/POP ports
#
# Table columns:
#   25 / 465 / 587 / 993 / 995  reachability + cert + name-match per port
#   Days                        smallest cert remaining days across all ports,
#                               with port label appended e.g. "12 (587)"
#
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"
# shellcheck source=../../lib/tls.sh
. "${PTBOX_ROOT}/lib/tls.sh"

section "security: mail TLS"

: "${MAIL_TLS_MAX_DOMAINS:=25}"
: "${MAIL_TLS_PORTS:=25 465 587 993 995}"
: "${MAIL_TLS_CONNECT_TIMEOUT:=5}"
: "${MAIL_DOMAIN_TRUNCATE:=22}"

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

_starttls_for_port() {
    case "$1" in
        25|587) printf 'smtp' ;;
        143)    printf 'imap' ;;
        110)    printf 'pop3' ;;
        *)      printf '' ;;
    esac
}

# Single openssl handshake — sets CERT_DAYS, CERT_NAMES.
_probe_cert() {
    local host="$1" port="$2" starttls="$3"
    local starttls_opt=()
    [[ -n "$starttls" ]] && starttls_opt=(-starttls "$starttls")
    CERT_DAYS=-1; CERT_NAMES=""
    local cert_text
    # -ext is OpenSSL 1.1.1+; -text dumps the same SAN extension and works on
    # OpenSSL 1.0.2 (CentOS 7 / RHEL 7). The SAN parser below scans for the
    # "X509v3 Subject Alternative Name" block which both formats emit.
    cert_text="$(echo | timeout "$MAIL_TLS_CONNECT_TIMEOUT" openssl s_client \
        ${starttls_opt[@]+"${starttls_opt[@]}"} \
        -connect "${host}:${port}" -servername "$host" 2>/dev/null \
        | openssl x509 -noout -enddate -subject -text 2>/dev/null)" || return 1
    [[ -z "$cert_text" ]] && return 1
    local end_date end_epoch now_epoch
    end_date="$(awk -F= '/^notAfter=/ {print $2; exit}' <<< "$cert_text")"
    [[ -z "$end_date" ]] && return 1
    end_epoch="$(date -d "$end_date" +%s 2>/dev/null)" || return 1
    now_epoch="$(date +%s)"
    CERT_DAYS=$(( (end_epoch - now_epoch) / 86400 ))
    local san_line subj_cn
    san_line="$(grep -A1 'X509v3 Subject Alternative Name' <<< "$cert_text" \
                | tail -n1 | tr ',' '\n' | sed 's/^[[:space:]]*DNS://I' \
                | tr '[:upper:]' '[:lower:]' | tr -d ' ')"
    subj_cn="$(awk -F'CN ?= ?' '/^subject=/ {print $2; exit}' <<< "$cert_text" \
                | awk -F, '{print $1}' | tr '[:upper:]' '[:lower:]' | tr -d ' ')"
    CERT_NAMES="$(printf '%s\n%s\n' "$san_line" "$subj_cn" | sort -u)"
    return 0
}

_cert_matches() {
    local host="${1,,}" names="$2" n
    while IFS= read -r n; do
        [[ -z "$n" ]] && continue
        [[ "$n" == "$host" ]] && return 0
        if [[ "$n" == "*."* ]]; then
            local suffix="${n#\*.}"
            # shellcheck disable=SC2295
            [[ "$host" == *."$suffix" && "${host%.${suffix}}" != *.* ]] && return 0
        fi
    done <<< "$names"
    return 1
}

# Header columns: one per port (extracted from MAIL_TLS_PORTS)
read -ra PORTS_ARR <<< "$MAIL_TLS_PORTS"
table_init "Domain" "${PORTS_ARR[@]}" "Days"

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_TLS_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    host="mail.${d}"
    label="$(truncate "$d" "$MAIL_DOMAIN_TRUNCATE")"

    # mail.<d> must resolve at all — otherwise skip whole row.
    if ! dig +short A "$host" 2>/dev/null | grep -q '.' \
        && ! dig +short AAAA "$host" 2>/dev/null | grep -q '.'; then
        skipped_cells=()
        for _p in "${PORTS_ARR[@]}"; do skipped_cells+=("$(status_cell skip)"); done
        table_row "$label" "${skipped_cells[@]}" "—"
        emit "sec.mail.tls.${d}" "low" "skip" "${host}: no A/AAAA record"
        continue
    fi

    port_cells=()
    port_statuses=()
    port_sevs=()
    fixes=()
    min_days=-1
    min_port=""

    for port in "${PORTS_ARR[@]}"; do
        if ! timeout 3 bash -c ">/dev/tcp/${host}/${port}" 2>/dev/null; then
            port_cells+=("$(status_cell skip)")
            port_statuses+=("skip")
            port_sevs+=("low")
            continue
        fi

        starttls="$(_starttls_for_port "$port")"
        if ! _probe_cert "$host" "$port" "$starttls"; then
            port_cells+=("$(status_cell fail)")
            port_statuses+=("fail"); port_sevs+=("high")
            fixes+=("${host}:${port}: cert read failed — verify TLS configured")
            continue
        fi

        # Track minimum cert lifetime across reachable ports.
        if (( min_days < 0 )) || (( CERT_DAYS < min_days )); then
            min_days=$CERT_DAYS
            min_port=$port
        fi

        port_status="pass"; port_sev="info"; cell_status="pass"

        if (( CERT_DAYS < 7 )); then
            port_status="fail"; port_sev="high"; cell_status="fail"
            fixes+=("${host}:${port}: cert expires in ${CERT_DAYS}d — renew")
        elif (( CERT_DAYS < 21 )); then
            port_status="warn"; port_sev="medium"; cell_status="warn"
        fi

        if ! _cert_matches "$host" "$CERT_NAMES"; then
            if [[ "$port_status" == "pass" ]]; then
                port_status="warn"; port_sev="medium"; cell_status="warn"
            fi
            fixes+=("${host}:${port}: cert does not list ${host}")
        fi

        port_cells+=("$(status_cell "$cell_status")")
        port_statuses+=("$port_status")
        port_sevs+=("$port_sev")
    done

    if (( min_days < 0 )); then
        days_cell="—"
    else
        days_cell="${min_days} (${min_port})"
    fi
    table_row "$label" "${port_cells[@]}" "$days_cell"

    row_status="$(worst_status "${port_statuses[@]}")"
    row_sev="$(worst_severity "${port_sevs[@]}")"
    fix=""
    if (( ${#fixes[@]} > 0 )); then
        fix="$(IFS=' | '; printf '%s' "${fixes[*]}")"
    fi
    emit "sec.mail.tls.${d}" "$row_sev" "$row_status" \
        "${host}: min ${min_days}d on :${min_port:-?}" "$fix"
done

table_render

(( checked > 0 )) || emit "sec.mail.tls" "info" "skip" "no domains checked"
