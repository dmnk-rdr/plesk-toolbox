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
# Handles ALL common forms, not just the Plesk default:
#   usage    3 (DANE-EE, leaf certificate) · 2 (DANE-TA, a CA from the chain)
#   selector 0 (full certificate)          · 1 (SPKI, public key only)
#   matching 1 (SHA-256)                   · 2 (SHA-512)
#
# DANE semantics: ONE published record matching is enough (RFC 7671). So each port
# is judged on "at least one matches", not "all match". The dangerous state is a
# port that publishes records of which NONE match — DANE-validating senders then
# refuse delivery.
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

# Fetch the full certificate chain and write it as PEM files into $DANE_CHAIN_DIR.
# cert-00 = leaf, cert-01.. = CA levels.
_dane_fetch_chain() {
    local host="$1" port="$2" starttls="$3"
    local starttls_opt=()
    [[ -n "$starttls" ]] && starttls_opt=(-starttls "$starttls")
    DANE_CHAIN_DIR="$(mktemp -d)" || return 1
    echo | timeout "$MAIL_DANE_CONNECT_TIMEOUT" openssl s_client \
        ${starttls_opt[@]+"${starttls_opt[@]}"} \
        -connect "${host}:${port}" -servername "$host" -showcerts 2>/dev/null \
        | sed -n '/BEGIN CERTIFICATE/,/END CERTIFICATE/p' > "$DANE_CHAIN_DIR/all.pem"
    [[ -s "$DANE_CHAIN_DIR/all.pem" ]] || { rm -rf "$DANE_CHAIN_DIR"; DANE_CHAIN_DIR=""; return 1; }
    ( cd "$DANE_CHAIN_DIR" && csplit -z -s -f cert- -b '%02d.pem' all.pem '/BEGIN CERTIFICATE/' '{*}' ) 2>/dev/null
    [[ -s "$DANE_CHAIN_DIR/cert-00.pem" ]] || { rm -rf "$DANE_CHAIN_DIR"; DANE_CHAIN_DIR=""; return 1; }
    return 0
}

# Hash one certificate per selector/matching. Echoes lowercase hex.
_dane_hash_of() {
    local pem="$1" selector="$2" matching="$3" alg
    case "$matching" in 1) alg="-sha256" ;; 2) alg="-sha512" ;; *) return 1 ;; esac
    if [[ "$selector" == "0" ]]; then
        openssl x509 -in "$pem" -outform DER 2>/dev/null | openssl dgst $alg -hex 2>/dev/null | awk '{print tolower($NF)}'
    elif [[ "$selector" == "1" ]]; then
        openssl x509 -in "$pem" -noout -pubkey 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null \
            | openssl dgst $alg -hex 2>/dev/null | awk '{print tolower($NF)}'
    else
        return 1
    fi
}

# Split TLSA rdata into the globals DANE_U/DANE_S/DANE_M/DANE_HEX.
_dane_parse() {
    local line
    line="$(tr -s ' \t' ' ' <<< "$1" | sed 's/^ //;s/ $//')"
    [[ "$line" =~ ^([0-3])[[:space:]]+([0-1])[[:space:]]+([0-2])[[:space:]]+(.+)$ ]] || return 1
    DANE_U="${BASH_REMATCH[1]}"; DANE_S="${BASH_REMATCH[2]}"; DANE_M="${BASH_REMATCH[3]}"
    # dig wraps long digests into chunks — strip whitespace and quotes.
    DANE_HEX="${BASH_REMATCH[4]//[\" ]/}"
    DANE_HEX="${DANE_HEX,,}"
    [[ "$DANE_HEX" =~ ^[0-9a-f]+$ ]] || return 1
    return 0
}

# Check whether ONE record matches the fetched chain.
#   usage 3/1 -> leaf only (cert-00)   ·   usage 2/0 -> any CA level of the chain
_dane_record_matches() {
    local pem
    if [[ "$DANE_U" == "3" || "$DANE_U" == "1" ]]; then
        [[ -s "$DANE_CHAIN_DIR/cert-00.pem" ]] || return 1
        [[ "$(_dane_hash_of "$DANE_CHAIN_DIR/cert-00.pem" "$DANE_S" "$DANE_M")" == "$DANE_HEX" ]] && return 0
        return 1
    fi
    for pem in "$DANE_CHAIN_DIR"/cert-*.pem; do
        [[ -s "$pem" ]] || continue
        [[ "$pem" == *cert-00.pem ]] && continue
        [[ "$(_dane_hash_of "$pem" "$DANE_S" "$DANE_M")" == "$DANE_HEX" ]] && return 0
    done
    return 1
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
        mapfile -t rrs < <(dig +short TLSA "_${port}._tcp.${host}" 2>/dev/null | grep .)
        (( ${#rrs[@]} > 0 )) || continue

        published=$((published + 1))

        starttls="$(_dane_starttls_for_port "$port")"
        if ! _dane_fetch_chain "$host" "$port" "$starttls"; then
            unverifiable+=("${port}:cert-unreachable")
            continue
        fi

        # RFC 7671: the port is fine as soon as ONE record matches.
        port_ok=0; parsed_any=0
        for rr in "${rrs[@]}"; do
            [[ -n "$rr" ]] || continue
            _dane_parse "$rr" || continue
            parsed_any=1
            if _dane_record_matches; then port_ok=1; break; fi
        done
        rm -rf "$DANE_CHAIN_DIR"; DANE_CHAIN_DIR=""

        if (( parsed_any == 0 )); then
            unverifiable+=("${port}:unparsable-tlsa")
        elif (( port_ok == 1 )); then
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
            fix="publish TLSA at _<port>._tcp.${host} for ports: ${MAIL_DANE_PORTS}"
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
        fix="NO published TLSA record matches the served certificate on port $(IFS=,; printf '%s' "${mismatched[*]}") — DANE-validating senders cannot deliver. Recompute the digests after every certificate renewal."
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
