# lib/tls.sh - TLS scanning helper
[[ -n "${__PTBOX_TLS_LOADED:-}" ]] && return 0
__PTBOX_TLS_LOADED=1

: "${TESTSSL_BIN:=}"

# _tls_scan <host> <port> [starttls_proto]
# Emits lines: "proto\tTLSv1.0|TLSv1.2|...\tcipher_flags"  (tab-separated)
# Uses testssl.sh --json if available (TESTSSL_BIN), else falls back to openssl s_client.
_tls_scan() {
    local host="$1" port="$2" starttls="${3:-}"
    if [[ -x "${TESTSSL_BIN:-}" ]]; then
        local args=(--json -p -S --quiet --color 0 --sneaky)
        [[ -n "$starttls" ]] && args+=(--starttls "$starttls")
        "$TESTSSL_BIN" "${args[@]}" "${host}:${port}" 2>/dev/null
        return
    fi
    # Minimal fallback: probe each protocol with openssl
    local proto
    for proto in ssl3 tls1 tls1_1 tls1_2 tls1_3; do
        local opt="-${proto}" starttls_opt=()
        [[ -n "$starttls" ]] && starttls_opt=(-starttls "$starttls")
        local result
        if echo | timeout 5 openssl s_client "$opt" "${starttls_opt[@]}" \
                   -connect "${host}:${port}" -servername "$host" \
                   2>/dev/null | grep -q "BEGIN CERTIFICATE"; then
            printf '%s\tsupported\n' "$proto"
        else
            printf '%s\tnot_supported\n' "$proto"
        fi
    done
}

# Cert expiry in days for host:port (or -1 on failure)
_tls_cert_days() {
    local host="$1" port="$2" starttls="${3:-}"
    local starttls_opt=()
    [[ -n "$starttls" ]] && starttls_opt=(-starttls "$starttls")
    local end_date
    end_date="$(echo | timeout 5 openssl s_client "${starttls_opt[@]}" \
                -connect "${host}:${port}" -servername "$host" 2>/dev/null \
                | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)"
    [[ -z "$end_date" ]] && { echo "-1"; return 1; }
    local end_epoch now_epoch
    end_epoch="$(date -d "$end_date" +%s 2>/dev/null)" || { echo "-1"; return 1; }
    now_epoch="$(date +%s)"
    echo $(( (end_epoch - now_epoch) / 86400 ))
}
