# shellcheck shell=bash
# audits.d/sec/57-mail-dane.sh — DANE / TLSA records for mail ports
#
# DANE (RFC 6698/7672) lets sending MTAs verify the receiving server's
# certificate via DNSSEC-signed TLSA records, defeating MitM downgrade
# attacks that plain STARTTLS cannot. Plesk emits TLSA records when
# enabling Let's Encrypt with DANE; this check verifies they match the
# certificate the server actually serves.
#
# Per port we publish:  _<port>._tcp.mail.<domain>   IN TLSA
# Convention used by Plesk: "3 0 1 <sha256-of-DER-cert>"
#   usage    = 3  (DANE-EE — match the end-entity cert directly)
#   selector = 0  (Full Cert, not SPKI)
#   matching = 1  (SHA-256)
#
# Table columns:
#   TLSA    how many of the expected per-port records are published (N/M)
#   Match   how many of the published records match the live cert
#
# A mismatch FAILS hard because broken DANE makes DANE-aware senders
# (e.g. major German providers) refuse to deliver mail.
#
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "security: mail DANE / TLSA"

: "${MAIL_DANE_MAX_DOMAINS:=50}"
: "${MAIL_DANE_PORTS:=25 110 465 587 993 995}"
: "${MAIL_DANE_REQUIRED:=0}"
: "${MAIL_DANE_CONNECT_TIMEOUT:=5}"
: "${MAIL_DOMAIN_TRUNCATE:=22}"

if ! _plesk_available; then
    emit "sec.mail.dane" "medium" "skip" "plesk CLI not available"
    return 0
fi
if ! command -v dig >/dev/null 2>&1 || ! command -v openssl >/dev/null 2>&1; then
    emit "sec.mail.dane" "medium" "skip" "dig(1) or openssl(1) not available"
    return 0
fi
if ! _plesk_mail_in_use; then
    emit "sec.mail.dane" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
(( ${#domains[@]} > 0 )) || { emit "sec.mail.dane" "info" "skip" "no mail-enabled domains"; return 0; }

# STARTTLS protocol per port (matches openssl s_client -starttls).
_dane_starttls_for_port() {
    case "$1" in
        25|587) printf 'smtp' ;;
        110)    printf 'pop3' ;;
        143)    printf 'imap' ;;
        *)      printf '' ;;
    esac
}

# SHA-256 of the live server certificate in DER form (matches "3 0 1").
# Sets DANE_CERT_HASH (lowercase hex) on success.
_dane_cert_sha256() {
    local host="$1" port="$2" starttls="$3"
    local starttls_opt=()
    [[ -n "$starttls" ]] && starttls_opt=(-starttls "$starttls")
    DANE_CERT_HASH=""
    local digest
    digest="$(echo | timeout "$MAIL_DANE_CONNECT_TIMEOUT" openssl s_client \
        ${starttls_opt[@]+"${starttls_opt[@]}"} \
        -connect "${host}:${port}" -servername "$host" 2>/dev/null \
        | openssl x509 -outform DER 2>/dev/null \
        | openssl dgst -sha256 -hex 2>/dev/null \
        | awk '{print $NF}')" || return 1
    [[ -z "$digest" || ${#digest} -ne 64 ]] && return 1
    DANE_CERT_HASH="${digest,,}"
    return 0
}

# Parse TLSA rdata into "usage selector match hex". Tolerates extra
# whitespace and uppercase. Echoes nothing if not 3-0-1.
_dane_parse_301() {
    local line="$1"
    # Collapse whitespace, strip optional trailing ".
    line="$(tr -s ' \t' ' ' <<< "$line" | sed 's/^ //;s/ $//')"
    [[ "$line" =~ ^3[[:space:]]+0[[:space:]]+1[[:space:]]+(.+)$ ]] || return 1
    # dig wraps long digests into space-separated chunks
    # ("46DC…498F 0879ED55") — join before validating.
    local hex="${BASH_REMATCH[1]//[\" ]/}"
    [[ "$hex" =~ ^[0-9a-fA-F]{64}$ ]] || return 1
    printf '%s' "${hex,,}"
}

read -ra DANE_PORTS_ARR <<< "$MAIL_DANE_PORTS"
expected=${#DANE_PORTS_ARR[@]}
table_init "Domain" "TLSA" "Match"

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_DANE_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    host="mail.${d}"
    label="$(truncate "$d" "$MAIL_DOMAIN_TRUNCATE")"

    # If mail.<d> has no address record, DANE check is moot.
    if ! dig +short A "$host" 2>/dev/null | grep -q '.' \
        && ! dig +short AAAA "$host" 2>/dev/null | grep -q '.'; then
        table_row "$label" "$(status_cell skip)" "—"
        emit "sec.mail.dane.${d}" "low" "skip" "${host}: no A/AAAA record"
        continue
    fi

    published=0
    matched=0
    mismatched=()
    unverifiable=()

    for port in "${DANE_PORTS_ARR[@]}"; do
        raw="$(dig +short TLSA "_${port}._tcp.${host}" 2>/dev/null | head -n1)"
        [[ -z "$raw" ]] && continue

        published=$((published + 1))
        expected_hash="$(_dane_parse_301 "$raw")" || {
            unverifiable+=("${port}:unsupported-tlsa")
            continue
        }

        starttls="$(_dane_starttls_for_port "$port")"
        if ! _dane_cert_sha256 "$host" "$port" "$starttls"; then
            unverifiable+=("${port}:cert-unreachable")
            continue
        fi

        if [[ "$expected_hash" == "$DANE_CERT_HASH" ]]; then
            matched=$((matched + 1))
        else
            mismatched+=("${port}")
        fi
    done

    # ── Cell + emit logic ────────────────────────────────────────────────
    if (( published == 0 )); then
        if (( MAIL_DANE_REQUIRED == 1 )); then
            tlsa_cell="$(status_cell warn 'miss')"
            match_cell="—"
            status="warn"; sev="medium"
            fix="publish TLSA \"3 0 1 <sha256>\" at _<port>._tcp.${host} for ports: ${MAIL_DANE_PORTS}"
        else
            tlsa_cell="$(status_cell skip 'opt')"
            match_cell="—"
            status="skip"; sev="info"
            fix=""
        fi
        table_row "$label" "$tlsa_cell" "$match_cell"
        emit "sec.mail.dane.${d}" "$sev" "$status" \
            "${d}: no TLSA records" "$fix"
        continue
    fi

    tlsa_cell="$(status_cell pass "${published}/${expected}")"
    if (( published < expected )); then
        # Partial publish — DANE-aware senders to missing ports get no
        # protection; senders to published ports do. Warn, not fail.
        tlsa_cell="$(status_cell warn "${published}/${expected}")"
    fi

    if (( ${#mismatched[@]} > 0 )); then
        match_cell="$(status_cell fail "${matched}/${published}")"
        status="fail"; sev="high"
        fix="TLSA record mismatch on port(s) $(IFS=,; printf '%s' "${mismatched[*]}") — regenerate after cert renewal"
    elif (( ${#unverifiable[@]} > 0 )); then
        # Could not reach server to verify — surface as warn.
        match_cell="$(status_cell warn "${matched}/${published}")"
        status="warn"; sev="low"
        fix="could not verify TLSA on $(IFS=,; printf '%s' "${unverifiable[*]}")"
    elif (( published < expected )); then
        match_cell="$(status_cell pass "${matched}/${published}")"
        status="warn"; sev="low"
        # List missing ports (set difference, ordered as configured).
        missing=()
        for port in "${DANE_PORTS_ARR[@]}"; do
            dig +short TLSA "_${port}._tcp.${host}" 2>/dev/null | grep -q '.' \
                || missing+=("${port}")
        done
        fix="add TLSA on missing port(s): $(IFS=,; printf '%s' "${missing[*]}")"
    else
        match_cell="$(status_cell pass "all")"
        status="pass"; sev="info"
        fix=""
    fi

    table_row "$label" "$tlsa_cell" "$match_cell"
    emit "sec.mail.dane.${d}" "$sev" "$status" \
        "${d}: ${published}/${expected} TLSA published, ${matched} match" "$fix"
done

table_render
