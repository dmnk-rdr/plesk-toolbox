# tools.d/mail/dkim-rotate.sh — rotate Plesk's DKIM private key safely
#
# Rotation always breaks mail signing for the time between key swap and DNS
# publication. To avoid that gap on external DNS providers (AutoDNS,
# Cloudflare, …) we split rotation into two explicit steps:
#
#   1. stage    (default)
#        - Generate a fresh 2048-bit key next to the live one (default.new).
#        - Print the TXT record the new key would need.
#        - Do NOT touch the live key — signing keeps working.
#
#   2. activate (--activate)
#        - Confirm the new public key is already published in DNS.
#        - Atomically swap default.new → default (backup of old key kept).
#        - Restart pc-remote + postfix so signers pick up the new key.
#
# Discard a staged key with --discard. Force-overwrite a stale stage with
# --force.
#
# Usage:
#   plesk-tool mail/dkim-rotate <domain>             # stage new key
#   plesk-tool mail/dkim-rotate <domain> --bits 4096 # custom key size
#   plesk-tool mail/dkim-rotate <domain> --activate  # swap once DNS is live
#   plesk-tool mail/dkim-rotate <domain> --discard   # remove staged key
#
# Honors --dry-run and --yes from the dispatcher.

# shellcheck source=../../lib/dkim.sh
. "${PTBOX_ROOT}/lib/dkim.sh"

: "${DKIM_ROTATE_SERVICES:=pc-remote postfix}"
: "${DKIM_KEY_OWNER:=root:popuser}"
: "${DKIM_KEY_MODE:=640}"

_rotate_print_record() {
    local keyfile="$1" sel="$2" d="$3" bind_mode="${4:-}"
    local value name
    value="$(dkim_record_value "$keyfile")"
    name="$(dkim_record_name "$sel" "$d")"
    dkim_print_publish_block "$name" "$value" "$bind_mode"
}

_rotate_stage() {
    local d="$1" bits="$2" force="$3" bind_mode="$4" sel keyfile staged
    keyfile="$(dkim_keyfile "$d")"
    sel="$(dkim_selector_for_keyfile "$keyfile")"
    staged="${keyfile}.new"

    if [[ ! -r "$keyfile" ]]; then
        printf '  no existing DKIM key at %s\n' "$keyfile" >&2
        printf '  enable DKIM in Plesk first so the key directory exists\n' >&2
        return 1
    fi
    if [[ -e "$staged" && "$force" -ne 1 ]]; then
        printf '  staged key already exists: %s\n' "$staged"
        printf '  re-use it with --activate, or pass --force to regenerate\n'
        _rotate_print_record "$staged" "$sel" "$d" "$bind_mode"
        printf '\n  Once the record is live in DNS, finish with:\n'
        printf '    plesk-tool mail/dkim-rotate %s --activate\n' "$d"
        return 0
    fi

    printf '  current: %s (%s-bit)\n' "$keyfile" "$(dkim_rsa_bits "$keyfile")"
    printf '  staging: %s (%s-bit)\n' "$staged" "$bits"
    tool_confirm "Generate new ${bits}-bit DKIM key for ${d}?" || return 1

    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '  would run: openssl genrsa -out %s %s\n' "$staged" "$bits"
    else
        if ! openssl genrsa -out "$staged" "$bits" >/dev/null 2>&1; then
            printf '  openssl key generation failed\n' >&2; return 1
        fi
        printf '  run: openssl genrsa -out %s %s\n' "$staged" "$bits"
    fi
    tool_run chown "$DKIM_KEY_OWNER" "$staged"
    tool_run chmod "$DKIM_KEY_MODE" "$staged"

    [[ "$DRY_RUN" -eq 1 ]] && return 0

    _rotate_print_record "$staged" "$sel" "$d" "$bind_mode"
    printf '\n  Once the record is live in DNS, finish with:\n'
    printf '    plesk-tool mail/dkim-rotate %s --activate\n' "$d"
}

_rotate_activate() {
    local d="$1" sel keyfile staged backup
    keyfile="$(dkim_keyfile "$d")"
    sel="$(dkim_selector_for_keyfile "$keyfile")"
    staged="${keyfile}.new"

    if [[ ! -r "$staged" ]]; then
        printf '  no staged key at %s — run without --activate first\n' "$staged" >&2
        return 1
    fi

    # Verify DNS publishes the new public key before we swap.
    local staged_p dns_p
    staged_p="$(dkim_local_pubkey_b64 "$staged")"
    dns_p="$(dkim_dns_p "$sel" "$d" || true)"
    if [[ -z "$dns_p" ]]; then
        printf '  %sDNS has no TXT record at %s%s\n' \
            "${C_RED:-}" "$(dkim_record_name "$sel" "$d")" "${C_RST:-}" >&2
        printf '  publish the staged record first, then re-run --activate\n' >&2
        return 1
    fi
    if [[ "$dns_p" != "$staged_p" ]]; then
        printf '  %sDNS pubkey does not match staged key — swap would break signing%s\n' \
            "${C_RED:-}" "${C_RST:-}"
        printf '  %sDNS    p=%s%.40s…\n' "${C_DIM:-}" "${C_RST:-}" "$dns_p"
        printf '  %sstaged p=%s%.40s…\n' "${C_DIM:-}" "${C_RST:-}" "$staged_p"
        printf '  wait for DNS propagation, or re-stage with --force\n'
        return 1
    fi

    backup="${keyfile}.bak.$(date +%s)"
    printf '  DNS matches staged key — safe to swap.\n'
    printf '  backup:  %s\n' "$backup"
    printf '  restart: %s\n' "$DKIM_ROTATE_SERVICES"
    tool_confirm "Swap key and restart mail signing for ${d}?" || return 1

    tool_run cp -p "$keyfile" "$backup"
    tool_run mv "$staged" "$keyfile"
    tool_run chown "$DKIM_KEY_OWNER" "$keyfile"
    tool_run chmod "$DKIM_KEY_MODE" "$keyfile"

    local svc
    for svc in $DKIM_ROTATE_SERVICES; do
        if systemctl list-unit-files --type=service 2>/dev/null \
            | awk '{print $1}' | grep -qx "${svc}.service"; then
            tool_run systemctl restart "$svc"
        fi
    done

    [[ "$DRY_RUN" -eq 1 ]] || printf '\n  %sactivated — mail signing now uses the new key%s\n' \
        "${C_GRN:-}" "${C_RST:-}"
}

_rotate_discard() {
    local d="$1" keyfile staged
    keyfile="$(dkim_keyfile "$d")"
    staged="${keyfile}.new"
    if [[ ! -e "$staged" ]]; then
        printf '  no staged key to discard\n'; return 0
    fi
    tool_confirm "Discard staged DKIM key ${staged}?" || return 1
    tool_run rm -f "$staged"
}

main() {
    local d="" mode="stage" bits=2048 force=0 bind_mode=""
    while (( $# )); do
        case "$1" in
            --activate) mode="activate" ;;
            --discard)  mode="discard" ;;
            --force)    force=1 ;;
            --bind)     bind_mode="--bind" ;;
            --bits)     bits="$2"; shift ;;
            --bits=*)   bits="${1#--bits=}" ;;
            -*)         printf 'unknown flag: %s\n' "$1" >&2; return 2 ;;
            *)
                if [[ -z "$d" ]]; then d="$1"
                else printf 'extra arg: %s\n' "$1" >&2; return 2
                fi ;;
        esac
        shift
    done
    if [[ -z "$d" ]]; then
        printf 'usage: plesk-tool mail/dkim-rotate <domain> [--activate|--discard] [--bits N] [--force] [--bind]\n' >&2
        return 2
    fi

    tool_begin "dkim-rotate:${d}:${mode}" "DKIM rotation (${mode}) for ${d}" || return 1
    case "$mode" in
        stage)    _rotate_stage    "$d" "$bits" "$force" "$bind_mode" ;;
        activate) _rotate_activate "$d" ;;
        discard)  _rotate_discard  "$d" ;;
    esac
    local rc=$?
    tool_end "$( (( rc == 0 )) && echo ok || echo fail )"
    return "$rc"
}
