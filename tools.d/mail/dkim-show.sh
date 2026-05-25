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

usage() {
    cat <<'EOF'
plesk-tool mail/dkim-show <domain> [selector] [--bind]

Read /etc/domainkeys/<domain>/<selector> (selector defaults to "default"),
build the canonical "v=DKIM1; k=rsa; p=<base64>" TXT record, compare it to
what's currently published in DNS, and print a copy-paste-ready block.

Status meanings:
  match    DNS already publishes this exact key — nothing to do.
  STALE    DNS publishes a *different* key. Either republish the local
           key (shown), or rotate locally first with mail/dkim-rotate.
  missing  No TXT record at <sel>._domainkey.<domain> yet. Publish it.
  REVOKED  Published TXT has empty p= (RFC-defined "revoke this key").
  weak     Local key is below the configured MAIL_DKIM_MIN_BITS (2048).
           Run mail/dkim-rotate before publishing — don't downgrade DNS.

Flags:
  --bind   also print the 255-char-chunked BIND zone-file form (only
           needed if you're editing a raw zone file, not a DNS UI).

Read-only — never touches the key file or DNS.
EOF
}

_dkim_show_one() {
    local d="$1" sel="${2:-}" bind_mode="${3:-}"
    local keyfile
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
        ok)      status_color="${C_GRN:-}"; status_text="match — DNS already publishes this key" ;;
        stale)   status_color="${C_RED:-}"; status_text="STALE — DNS publishes a different key" ;;
        no-dns)  status_color="${C_RED:-}"; status_text="missing — no TXT record published yet" ;;
        revoked) status_color="${C_RED:-}"; status_text="REVOKED — published TXT has empty p=" ;;
        weak)    status_color="${C_YEL:-}"; status_text="weak — local key is ${bits}-bit (rotate to 2048+ recommended)" ;;
        testing) status_color="${C_YEL:-}"; status_text="testing — DNS TXT carries t=y" ;;
        *)       status_color=""; status_text="$status" ;;
    esac

    printf '\n  %s%s%s  (local key: %s-bit, selector=%s)\n' \
        "${C_BOLD:-}" "$d" "${C_RST:-}" "${bits:-?}" "$sel"
    printf '  %sstatus%s  %s%s%s\n' \
        "${C_DIM:-}" "${C_RST:-}" "$status_color" "$status_text" "${C_RST:-}"

    # Always print the publish block — even on match, so the operator can
    # quickly verify the live value byte-for-byte against their DNS UI.
    dkim_print_publish_block "$name" "$value" "$bind_mode"

    # Diff context for stale: show truncated prefixes so the operator can
    # see *why* it doesn't match without scrolling the full base64.
    if [[ -n "$dns_p" && "$dns_p" != "$local_p" ]]; then
        printf '\n  %swhy stale (first 40 chars of each pubkey):%s\n' "${C_DIM:-}" "${C_RST:-}"
        printf '    currently in DNS:   %s%.40s…%s\n' "${C_YEL:-}" "$dns_p" "${C_RST:-}"
        printf '    on this server:     %s%.40s…%s  (this one is in the value above)\n' \
            "${C_GRN:-}" "$local_p" "${C_RST:-}"
    fi

    if [[ "$status" != "ok" ]]; then
        printf '\n  After publishing:\n'
        printf '    plesk-tool mail/dkim-verify %s\n' "$d"
    fi
    return 0
}

main() {
    local d="" sel="" bind_mode=""
    while (( $# )); do
        case "$1" in
            --bind) bind_mode="--bind" ;;
            -*)     printf 'unknown flag: %s\n' "$1" >&2; return 2 ;;
            *)
                if   [[ -z "$d" ]];   then d="$1"
                elif [[ -z "$sel" ]]; then sel="$1"
                else printf 'extra arg: %s\n' "$1" >&2; return 2
                fi ;;
        esac
        shift
    done
    if [[ -z "$d" ]]; then
        printf 'usage: plesk-tool mail/dkim-show <domain> [selector] [--bind]\n' >&2
        return 2
    fi
    section "DKIM record for ${d}"
    _dkim_show_one "$d" "$sel" "$bind_mode"
}
