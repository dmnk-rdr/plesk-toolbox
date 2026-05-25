# tools.d/mail/dkim-show.sh — print the correct DKIM TXT record for a domain
#
# Reads the local Plesk DKIM private key, builds the canonical
# v=DKIM1; k=rsa; p=<base64> record value, fetches what's actually published
# in DNS, and reports whether they match. Output is meant to be copy-pasted
# into an external DNS UI (AutoDNS, Cloudflare, …) when Plesk doesn't own
# the zone.
#
# Usage:
#   plesk-tool mail/dkim-show <domain> [selector]
#
# Read-only.

# shellcheck source=../../lib/dkim.sh
. "${PTBOX_ROOT}/lib/dkim.sh"

_dkim_show_one() {
    local d="$1" sel="${2:-}" keyfile
    keyfile="$(dkim_keyfile "$d" "$sel")"
    if [[ ! -r "$keyfile" ]]; then
        printf '  %s%s%s — no local DKIM key (%s)\n' \
            "${C_RED:-}" "$d" "${C_RST:-}" "$keyfile"
        printf '  %senable DKIM in Plesk → %s → Mail Settings to create it%s\n' \
            "${C_DIM:-}" "$d" "${C_RST:-}"
        return 1
    fi

    sel="$(dkim_selector_for_keyfile "$keyfile")"
    local bits value name status local_p dns_p
    bits="$(dkim_rsa_bits "$keyfile")"
    value="$(dkim_record_value "$keyfile")" || {
        printf '  %scould not derive public key from %s%s\n' \
            "${C_RED:-}" "$keyfile" "${C_RST:-}"
        return 1
    }
    name="$(dkim_record_name "$sel" "$d")"
    status="$(dkim_status "$keyfile" "$sel" "$d")"
    local_p="$(dkim_local_pubkey_b64 "$keyfile")"
    dns_p="$(dkim_dns_p "$sel" "$d" || true)"

    local status_color status_text
    case "$status" in
        ok)      status_color="${C_GRN:-}"; status_text="match" ;;
        stale)   status_color="${C_RED:-}"; status_text="STALE — DNS pubkey differs from local key" ;;
        no-dns)  status_color="${C_RED:-}"; status_text="missing — no TXT record published" ;;
        revoked) status_color="${C_RED:-}"; status_text="REVOKED — published TXT has empty p=" ;;
        weak)    status_color="${C_YEL:-}"; status_text="weak — local key is ${bits}-bit (need 2048+)" ;;
        testing) status_color="${C_YEL:-}"; status_text="testing — DNS TXT has t=y flag" ;;
        *)       status_color=""; status_text="$status" ;;
    esac

    printf '\n  %s%s%s  (%s-bit, selector=%s)\n' \
        "${C_BOLD:-}" "$d" "${C_RST:-}" "${bits:-?}" "$sel"
    printf '  %sstatus%s  %s%s%s\n' \
        "${C_DIM:-}" "${C_RST:-}" "$status_color" "$status_text" "${C_RST:-}"

    printf '  %srecord%s  %s\n' "${C_DIM:-}" "${C_RST:-}" "$name"
    printf '  %stype%s    TXT\n' "${C_DIM:-}" "${C_RST:-}"

    printf '  %svalue%s   %s\n' "${C_DIM:-}" "${C_RST:-}" "$value"

    # Most DNS UIs accept the whole string. BIND-style zone files want it
    # split into 255-char quoted chunks; show that form as well when it's
    # actually needed.
    if (( ${#value} > 255 )); then
        printf '  %schunked (BIND-style):%s\n' "${C_DIM:-}" "${C_RST:-}"
        local chunk
        while IFS= read -r chunk; do
            printf '            %s\n' "$chunk"
        done < <(dkim_chunks "$value")
    fi

    # If DNS is published, show the diff so it's obvious *what* is stale.
    if [[ -n "$dns_p" && "$dns_p" != "$local_p" ]]; then
        printf '\n  %sDNS currently publishes a different key:%s\n' "${C_DIM:-}" "${C_RST:-}"
        printf '  %sDNS  p=%s%s%.40s…\n' "${C_DIM:-}" "${C_RST:-}" "${C_YEL:-}" "$dns_p"
        printf '  %slocal p=%s%s%.40s…  %s← publish this%s\n' \
            "${C_DIM:-}" "${C_RST:-}" "${C_GRN:-}" "$local_p" "${C_DIM:-}" "${C_RST:-}"
    fi
    return 0
}

main() {
    local d="${1:-}" sel="${2:-}"
    if [[ -z "$d" ]]; then
        printf 'usage: plesk-tool mail/dkim-show <domain> [selector]\n' >&2
        return 2
    fi
    section "DKIM record for ${d}"
    _dkim_show_one "$d" "$sel"
}
