# audits.d/health/43-mail-dkim.sh - DKIM record validation, not just presence
#
# Checks per mail-enabled domain:
#   * a local private key exists at /etc/domainkeys/<domain>/<selector>
#   * the key is at least 2048 bits (1024-bit keys flagged)
#   * a DNS TXT record exists at <selector>._domainkey.<domain>
#   * the DNS record has a non-empty p= (empty = revoked)
#   * the DNS public key matches the local private key's public part
#     (catches the classic "Plesk rotated, DNS not updated" failure mode)
#   * the t=y testing flag is not set in production
#
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "health: mail DKIM"

: "${MAIL_DKIM_MAX_DOMAINS:=50}"
: "${MAIL_DKIM_MIN_BITS:=2048}"
: "${DKIM_SELECTOR:=default}"

if ! _plesk_available; then
    emit "health.mail.dkim" "medium" "skip" "plesk CLI not available"
    return 0
fi

if ! command -v dig >/dev/null 2>&1; then
    emit "health.mail.dkim" "medium" "skip" "dig(1) not available"
    return 0
fi

if ! command -v openssl >/dev/null 2>&1; then
    emit "health.mail.dkim" "medium" "skip" "openssl(1) not available"
    return 0
fi

if ! _plesk_mail_in_use; then
    emit "health.mail.dkim" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
(( ${#domains[@]} > 0 )) || { emit "health.mail.dkim" "info" "skip" "no mail-enabled domains"; return 0; }

# Return the p= base64 value from a (joined) DKIM TXT record, or empty.
_dkim_dns_p() {
    sed -E -n 's/.*[[:space:]]*p=([A-Za-z0-9+/=]+).*/\1/p' <<< "$1"
}

# Base64 body of a PEM blob piped on stdin (BEGIN/END lines + newlines stripped).
_pem_body() {
    awk '/-----BEGIN /{flag=1; next} /-----END /{flag=0} flag' | tr -d '\n'
}

# Bit count of a private RSA key file. Falls back to 0 on parse error.
_rsa_bits() {
    openssl rsa -in "$1" -text -noout 2>/dev/null \
        | awk '/Private-Key:.*bit/ {gsub(/[^0-9]/,"",$2); print $2; exit}'
}

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_DKIM_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    sel="$DKIM_SELECTOR"
    keyfile="$(_plesk_dkim_key_path "$d" "$sel")"

    # 1. Local key present?
    if [[ ! -r "$keyfile" ]]; then
        # Maybe a different selector — try the directory.
        alt="$(find "/etc/domainkeys/${d}" -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | head -n1)"
        if [[ -n "$alt" && -r "/etc/domainkeys/${d}/${alt}" ]]; then
            sel="$alt"
            keyfile="/etc/domainkeys/${d}/${sel}"
        else
            emit "health.mail.dkim.${d}.local" "medium" "warn" \
                "${d}: no local DKIM key (Plesk DKIM not enabled?)" \
                "enable DKIM in Plesk → ${d} → Mail Settings"
            continue
        fi
    fi

    # 2. Key length
    bits="$(_rsa_bits "$keyfile")"
    if [[ -z "$bits" || "$bits" -eq 0 ]]; then
        emit "health.mail.dkim.${d}.keyparse" "medium" "warn" \
            "${d}: cannot parse local DKIM key"
    elif (( bits < MAIL_DKIM_MIN_BITS )); then
        emit "health.mail.dkim.${d}.keybits" "medium" "warn" \
            "${d}: DKIM key is ${bits}-bit (< ${MAIL_DKIM_MIN_BITS})" \
            "rotate to a 2048-bit key in Plesk Mail Settings"
    else
        emit "health.mail.dkim.${d}.keybits" "info" "pass" \
            "${d}: DKIM key ${bits}-bit (sel=${sel})"
    fi

    # 3. DNS record. Long records come back from dig as multiple "..." chunks
    # joined by a space — that space lands inside the base64 of p=, breaking
    # the match. Strip the chunk-separators first, then the quotes/newlines.
    dns_raw="$(dig +short TXT "${sel}._domainkey.${d}" 2>/dev/null | sed 's/" "//g' | tr -d '"\n')"
    if [[ -z "$dns_raw" ]]; then
        emit "health.mail.dkim.${d}.dns" "high" "fail" \
            "${d}: no DKIM TXT at ${sel}._domainkey.${d}" \
            "publish the TXT record Plesk generated for this domain"
        continue
    fi

    # 4. p= empty → revoked
    dns_p="$(_dkim_dns_p "$dns_raw")"
    if [[ -z "$dns_p" ]]; then
        emit "health.mail.dkim.${d}.revoked" "high" "fail" \
            "${d}: DKIM record present but p= is empty (key revoked)" \
            "republish DKIM record with current public key"
        continue
    fi

    # 5. DNS pubkey ↔ local key match
    local_p="$(openssl rsa -in "$keyfile" -pubout 2>/dev/null | _pem_body)"
    # Both forms are base64 of the SubjectPublicKeyInfo DER for RSA — byte
    # equality is the right comparison.
    if [[ -n "$local_p" && "$dns_p" == "$local_p" ]]; then
        emit "health.mail.dkim.${d}.match" "info" "pass" \
            "${d}: DNS public key matches local key"
    elif [[ -n "$local_p" ]]; then
        emit "health.mail.dkim.${d}.match" "high" "fail" \
            "${d}: DNS public key does NOT match local key (stale rotation?)" \
            "republish ${sel}._domainkey.${d} TXT with current key (see Plesk Mail Settings → Server-wide Mail Settings → DKIM)"
    fi

    # 6. t=y testing flag
    if grep -qE '(^|[[:space:]])t=[^;]*y' <<< "$dns_raw"; then
        emit "health.mail.dkim.${d}.testing" "medium" "warn" \
            "${d}: DKIM record has t=y (testing mode)" \
            "remove t=y once DKIM is verified to work"
    fi
done
