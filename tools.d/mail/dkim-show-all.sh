# tools.d/mail/dkim-show-all.sh — bulk fix-record dump for problematic DKIM
#
# Iterates every Plesk mail-enabled domain and prints the canonical TXT
# record for any domain whose DKIM is stale, revoked, missing in DNS, or
# below the configured bit length. Use --all to also show OK domains.
#
# Usage:
#   plesk-tool mail/dkim-show-all
#   plesk-tool mail/dkim-show-all --all
#
# Read-only.

# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"
# shellcheck source=../../lib/dkim.sh
. "${PTBOX_ROOT}/lib/dkim.sh"
# shellcheck source=./dkim-show.sh
. "${PTBOX_ROOT}/tools.d/mail/dkim-show.sh"

main() {
    local show_all=0 bind_mode=""
    local a
    for a in "$@"; do
        case "$a" in
            --all|-a) show_all=1 ;;
            --bind)   bind_mode="--bind" ;;
            *) printf 'unknown arg: %s\n' "$a" >&2; return 2 ;;
        esac
    done

    if ! _plesk_available; then
        printf 'plesk CLI not available\n' >&2; return 1
    fi

    mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
    if (( ${#domains[@]} == 0 )); then
        printf 'no mail-enabled domains\n'; return 0
    fi

    section "DKIM records (problem domains)"
    local d sel keyfile status problems=0 skipped=0
    for d in "${domains[@]}"; do
        keyfile="$(dkim_keyfile "$d")"
        sel="$(dkim_selector_for_keyfile "$keyfile")"
        if [[ ! -r "$keyfile" ]]; then
            (( show_all == 0 )) && { (( ++skipped )); continue; }
        fi
        status="$(dkim_status "$keyfile" "$sel" "$d")"
        if [[ "$status" == "ok" && "$show_all" -eq 0 ]]; then
            (( ++skipped ))
            continue
        fi
        _dkim_show_one "$d" "$sel" "$bind_mode" || true
        (( ++problems ))
    done

    printf '\n  %s%d domains shown%s — %d ok/hidden (%s)\n' \
        "${C_BOLD:-}" "$problems" "${C_RST:-}" "$skipped" \
        "$( (( show_all )) && echo 'all mode' || echo 'pass --all to also show OK' )"
}
