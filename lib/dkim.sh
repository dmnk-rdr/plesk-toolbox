# lib/dkim.sh - shared DKIM helpers (used by audits + tools)
#
# Plesk stores DKIM private keys under /etc/domainkeys/<domain>/<selector>
# (selector defaults to "default"). The public key is published as a TXT
# record at <selector>._domainkey.<domain>:
#
#     v=DKIM1; k=rsa; p=<base64>
#
# These helpers normalise "look at the local key" and "fetch the published
# value" so audit grading and rotation tools share the same primitives.
[[ -n "${__PTBOX_DKIM_LOADED:-}" ]] && return 0
__PTBOX_DKIM_LOADED=1

: "${DKIM_SELECTOR_DEFAULT:=default}"
: "${DKIM_KEY_DIR:=/etc/domainkeys}"

# dkim_keyfile <domain> [selector]
# Echoes the canonical key path even if it doesn't exist yet (callers should
# check readability separately). With selector empty: tries 'default' first,
# then the first regular file in the domain dir.
dkim_keyfile() {
    local d="$1" sel="${2:-}"
    local base="${DKIM_KEY_DIR}/${d}"
    if [[ -n "$sel" ]]; then
        printf '%s/%s' "$base" "$sel"
        return 0
    fi
    if [[ -r "${base}/${DKIM_SELECTOR_DEFAULT}" ]]; then
        printf '%s/%s' "$base" "$DKIM_SELECTOR_DEFAULT"
        return 0
    fi
    local alt
    alt="$(find "$base" -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | head -n1)"
    if [[ -n "$alt" ]]; then
        printf '%s/%s' "$base" "$alt"
        return 0
    fi
    printf '%s/%s' "$base" "$DKIM_SELECTOR_DEFAULT"
    return 1
}

# dkim_selector_for_keyfile <keyfile>
# Inverse: extract the selector name (basename) from a keyfile path.
dkim_selector_for_keyfile() {
    basename "$1"
}

# dkim_rsa_bits <keyfile>
# Echoes the modulus bit length (e.g. 1024, 2048). Empty on failure.
dkim_rsa_bits() {
    openssl rsa -in "$1" -text -noout 2>/dev/null \
        | awk '/Private-Key:.*bit/ {gsub(/[^0-9]/,"",$2); print $2; exit}'
}

# dkim_local_pubkey_b64 <keyfile>
# Echoes the base64 public-key body (one long line, no PEM headers).
dkim_local_pubkey_b64() {
    openssl rsa -in "$1" -pubout 2>/dev/null \
        | awk '/-----BEGIN /{flag=1; next} /-----END /{flag=0} flag' \
        | tr -d '\n'
}

# dkim_record_value <keyfile>
# Echoes the full TXT record value: "v=DKIM1; k=rsa; p=<base64>"
dkim_record_value() {
    local p
    p="$(dkim_local_pubkey_b64 "$1")"
    [[ -z "$p" ]] && return 1
    printf 'v=DKIM1; k=rsa; p=%s' "$p"
}

# dkim_record_name <selector> <domain>
# Standard "<sel>._domainkey.<d>" with no trailing dot — callers can add one.
dkim_record_name() {
    printf '%s._domainkey.%s' "$1" "$2"
}

# dkim_dns_raw <selector> <domain>
# Fetches the raw TXT record (concatenates split chunks, strips quotes).
dkim_dns_raw() {
    dig +short TXT "$(dkim_record_name "$1" "$2")" 2>/dev/null \
        | sed 's/" "//g' | tr -d '"\n'
}

# dkim_dns_p <selector> <domain>
# Echoes just the p= base64 from the published TXT record, or empty.
dkim_dns_p() {
    local raw
    raw="$(dkim_dns_raw "$1" "$2")"
    [[ -z "$raw" ]] && return 1
    sed -E -n 's/.*[[:space:]]*p=([A-Za-z0-9+/=]+).*/\1/p' <<< "$raw"
}

# dkim_chunks <value> [width]
# Splits a long TXT value into <width>-char (default 255) substrings — most
# zone editors paste this as multiple quoted strings on one record.
dkim_chunks() {
    local value="$1" width="${2:-255}"
    local i len="${#value}"
    for (( i=0; i<len; i+=width )); do
        printf '"%s"\n' "${value:i:width}"
    done
}

# dkim_status <local-keyfile> <selector> <domain>
# Classifies the DKIM state for one (domain, selector) pair. Echoes one of:
#   missing-key | no-dns | revoked | stale | weak | testing | ok
# Sets DKIM_BITS to the local key length as a side effect.
dkim_status() {
    local keyfile="$1" sel="$2" d="$3"
    DKIM_BITS=""
    [[ -r "$keyfile" ]] || { printf 'missing-key'; return 0; }

    DKIM_BITS="$(dkim_rsa_bits "$keyfile")"

    local dns_raw dns_p local_p
    dns_raw="$(dkim_dns_raw "$sel" "$d")"
    if [[ -z "$dns_raw" ]]; then
        printf 'no-dns'; return 0
    fi
    dns_p="$(sed -E -n 's/.*[[:space:]]*p=([A-Za-z0-9+/=]+).*/\1/p' <<< "$dns_raw")"
    if [[ -z "$dns_p" ]]; then
        printf 'revoked'; return 0
    fi
    local_p="$(dkim_local_pubkey_b64 "$keyfile")"
    if [[ -n "$local_p" && "$dns_p" != "$local_p" ]]; then
        printf 'stale'; return 0
    fi
    if grep -qE '(^|[[:space:]])t=[^;]*y' <<< "$dns_raw"; then
        printf 'testing'; return 0
    fi
    : "${DKIM_MIN_BITS:=2048}"
    if [[ -n "$DKIM_BITS" && "$DKIM_BITS" -lt "$DKIM_MIN_BITS" ]]; then
        printf 'weak'; return 0
    fi
    printf 'ok'
}
