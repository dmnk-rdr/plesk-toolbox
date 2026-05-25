# tools.d/mail/dkim-verify.sh — verify DKIM end-to-end
#
# Two modes:
#
#   default          Local check — read /etc/domainkeys/<d>/<sel>, fetch the
#                    published TXT, and report whether the public keys match,
#                    bit length, and any flags (t=y testing, empty p= revoked).
#                    Does not send mail. Fast, no external dependencies
#                    beyond dig + openssl.
#
#   --send <addr>    Live test — sends a signed message via the local Postfix
#                    from <addr>@<domain> to a recipient, so the recipient
#                    side can see whether DKIM validates. Requires swaks.
#
#   --verifier       Sends the live test to check-auth@verifier.port25.com,
#                    which replies to the From: address with a full SPF/DKIM
#                    /DMARC report. Requires swaks + a real mailbox to read
#                    the response.
#
# Usage:
#   plesk-tool mail/dkim-verify <domain> [selector]
#   plesk-tool mail/dkim-verify <domain> --send postmaster@example.com
#   plesk-tool mail/dkim-verify <domain> --verifier --from postmaster@<d>

# shellcheck source=../../lib/dkim.sh
. "${PTBOX_ROOT}/lib/dkim.sh"

usage() {
    cat <<'EOF'
plesk-tool mail/dkim-verify <domain> [selector]
plesk-tool mail/dkim-verify <domain> --send <addr> [--from <addr>]
plesk-tool mail/dkim-verify <domain> --verifier [--from <addr>]

Default (local validation):
  Reads /etc/domainkeys/<d>/<selector>, fetches the published TXT, and
  reports match / stale / missing / revoked / weak / testing. Exits non-
  zero on anything but a clean match — wire into CI or a healthcheck.

--send <addr>:
  Submit a signed test mail through the local Postfix to <addr>. The
  recipient mailbox can then show whether the signature validated and
  with which selector. Requires swaks.

--verifier:
  Shortcut for --send check-auth@verifier.port25.com — the port25
  verifier service emails a full SPF/DKIM/DMARC report back to the
  From: address. Use --from to override the default (postmaster@<d>).

Read-only unless --send / --verifier is given.
EOF
}

_verify_local() {
    local d="$1" sel="$2" keyfile
    keyfile="$(dkim_keyfile "$d" "$sel")"
    if [[ ! -r "$keyfile" ]]; then
        printf '  %sno local DKIM key at %s%s\n' "${C_RED:-}" "$keyfile" "${C_RST:-}" >&2
        return 1
    fi
    sel="$(dkim_selector_for_keyfile "$keyfile")"

    local bits raw dns_p local_p status
    bits="$(dkim_rsa_bits "$keyfile")"
    raw="$(dkim_dns_raw "$sel" "$d")"
    dns_p="$(dkim_dns_p "$sel" "$d" || true)"
    local_p="$(dkim_local_pubkey_b64 "$keyfile")"
    status="$(dkim_status "$keyfile" "$sel" "$d")"

    printf '  %sdomain%s    %s (selector=%s, %s-bit)\n' \
        "${C_DIM:-}" "${C_RST:-}" "$d" "$sel" "${bits:-?}"
    printf '  %skeyfile%s   %s\n' "${C_DIM:-}" "${C_RST:-}" "$keyfile"
    printf '  %sdns name%s  %s\n' "${C_DIM:-}" "${C_RST:-}" "$(dkim_record_name "$sel" "$d")"
    if [[ -n "$raw" ]]; then
        printf '  %sdns value%s %.80s%s\n' "${C_DIM:-}" "${C_RST:-}" "$raw" \
            "$( (( ${#raw} > 80 )) && echo '…' )"
    else
        printf '  %sdns value%s %s(none)%s\n' "${C_DIM:-}" "${C_RST:-}" "${C_RED:-}" "${C_RST:-}"
    fi

    case "$status" in
        ok)
            printf '\n  %s✓ DKIM verification OK%s — DNS matches local key, %s-bit\n' \
                "${C_GRN:-}" "${C_RST:-}" "$bits"
            return 0 ;;
        stale)
            printf '\n  %s✗ STALE%s — DNS pubkey differs from local key\n' \
                "${C_RED:-}" "${C_RST:-}"
            printf '  %sdns    p=%s%s%.40s…\n' "${C_DIM:-}" "${C_RST:-}" "${C_YEL:-}" "$dns_p"
            printf '  %slocal  p=%s%s%.40s…  %s← publish this%s\n' \
                "${C_DIM:-}" "${C_RST:-}" "${C_GRN:-}" "$local_p" "${C_DIM:-}" "${C_RST:-}"
            printf '  fix: plesk-tool mail/dkim-show %s\n' "$d" ;;
        no-dns)
            printf '\n  %s✗ NO DNS%s — no TXT record at %s\n' \
                "${C_RED:-}" "${C_RST:-}" "$(dkim_record_name "$sel" "$d")"
            printf '  fix: plesk-tool mail/dkim-show %s\n' "$d" ;;
        revoked)
            printf '\n  %s✗ REVOKED%s — published TXT has empty p=\n' \
                "${C_RED:-}" "${C_RST:-}"
            printf '  fix: plesk-tool mail/dkim-show %s\n' "$d" ;;
        testing)
            printf '\n  %s⚠ TESTING%s — DNS record carries t=y (treated as test mode by receivers)\n' \
                "${C_YEL:-}" "${C_RST:-}"
            printf '  fix: drop t=y from the published TXT once verified\n' ;;
        weak)
            printf '\n  %s⚠ WEAK%s — key is %s-bit (want %s+)\n' \
                "${C_YEL:-}" "${C_RST:-}" "$bits" "${DKIM_MIN_BITS:-2048}"
            printf '  fix: plesk-tool mail/dkim-rotate %s\n' "$d" ;;
        missing-key)
            printf '\n  %s✗ NO LOCAL KEY%s — enable DKIM in Plesk → %s → Mail Settings\n' \
                "${C_RED:-}" "${C_RST:-}" "$d" ;;
    esac
    return 1
}

_verify_send() {
    local d="$1" recipient="$2" from="$3"
    if ! command -v swaks >/dev/null 2>&1; then
        printf '  swaks not installed — install via: yum install swaks || apt install swaks\n' >&2
        return 1
    fi
    [[ -z "$from" ]] && from="postmaster@${d}"
    local subj
    subj="DKIM verify test for ${d} ($(date -u +%FT%TZ))"
    printf '  from:    %s\n' "$from"
    printf '  to:      %s\n' "$recipient"
    printf '  subject: %s\n' "$subj"
    tool_confirm "Send DKIM test mail via local Postfix?" || return 1
    tool_run swaks \
        --server 127.0.0.1 --port 25 \
        --from "$from" \
        --to "$recipient" \
        --h-Subject "$subj" \
        --body "Automated DKIM verification probe from plesk-toolbox on $(hostname -f)." \
        --suppress-data
    [[ "$DRY_RUN" -eq 1 ]] && return 0
    if [[ "$recipient" == *"verifier.port25.com"* ]]; then
        printf '\n  %sport25 verifier will email a full DKIM/SPF/DMARC report to %s%s\n' \
            "${C_DIM:-}" "$from" "${C_RST:-}"
    fi
}

main() {
    local d="" sel="" mode="local" recipient="" from=""
    while (( $# )); do
        case "$1" in
            --send)       mode="send"; recipient="$2"; shift ;;
            --send=*)     mode="send"; recipient="${1#--send=}" ;;
            --verifier)   mode="send"; recipient="check-auth@verifier.port25.com" ;;
            --from)       from="$2"; shift ;;
            --from=*)     from="${1#--from=}" ;;
            -*)           printf 'unknown flag: %s\n' "$1" >&2; return 2 ;;
            *)
                if   [[ -z "$d" ]];    then d="$1"
                elif [[ -z "$sel" ]];  then sel="$1"
                else printf 'extra arg: %s\n' "$1" >&2; return 2
                fi ;;
        esac
        shift
    done
    if [[ -z "$d" ]]; then
        printf 'usage: plesk-tool mail/dkim-verify <domain> [selector] [--send addr | --verifier] [--from addr]\n' >&2
        return 2
    fi

    section "DKIM verify: ${d}"
    case "$mode" in
        local) _verify_local "$d" "$sel" ;;
        send)
            if [[ -z "$recipient" ]]; then
                printf '  --send needs a recipient address\n' >&2; return 2
            fi
            _verify_local "$d" "$sel" || true
            printf '\n  %s── live test ──%s\n' "${C_BOLD:-}" "${C_RST:-}"
            _verify_send "$d" "$recipient" "$from" ;;
    esac
}
