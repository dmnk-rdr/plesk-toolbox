# audits.d/health/42-mail-spf.sh - SPF record validation, not just presence
#
# Checks per mail-enabled domain:
#   * exactly one v=spf1 record (RFC 7208 §3.2)
#   * server's own IPs are authorised by the record
#   * sane all-qualifier (-all / ~all preferred over ?all / +all)
#   * total DNS-lookup count under the RFC limit (10)
#   * absence of the deprecated `ptr` mechanism
#
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "health: mail SPF"

: "${MAIL_SPF_MAX_DOMAINS:=50}"

if ! _plesk_available; then
    emit "health.mail.spf" "medium" "skip" "plesk CLI not available"
    return 0
fi

if ! command -v dig >/dev/null 2>&1; then
    emit "health.mail.spf" "medium" "skip" "dig(1) not available"
    return 0
fi

if ! _plesk_mail_in_use; then
    emit "health.mail.spf" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
(( ${#domains[@]} > 0 )) || { emit "health.mail.spf" "info" "skip" "no mail-enabled domains"; return 0; }

# Server IPs (authoritative source: Plesk DB).
mapfile -t SERVER_IPS < <(_plesk_server_ips 2>/dev/null || true)
SERVER_V4=()
SERVER_V6=()
for ip in "${SERVER_IPS[@]}"; do
    [[ "$ip" == *:* ]] && SERVER_V6+=("$ip") || SERVER_V4+=("$ip")
done

# Concatenate split TXT strings, strip the surrounding quotes dig returns.
_txt_join() { tr -d '"' | tr -d '\n'; }

# Fetch the SPF record(s) for $1. One per line (multiple = RFC violation).
_spf_records() {
    dig +short TXT "$1" 2>/dev/null \
        | awk '/v=spf1/ { gsub(/"/,""); gsub(/[[:space:]]+/," "); print }'
}

# Token count of mechanisms that cause a DNS lookup (a, mx, ptr, exists,
# include, redirect). RFC 7208 §4.6.4 caps this at 10 across the whole
# evaluation; we count only the top level here.
_spf_lookup_count() {
    awk '
        BEGIN { c=0 }
        { for (i=1; i<=NF; i++) {
            t=$i; sub(/^[+\-~?]/, "", t)
            if (t ~ /^(a|mx|ptr|exists|include|redirect=)/) c++
        } }
        END { print c }
    ' <<< "$1"
}

_spf_has_ptr() {
    # Hyphen must be at the start/end of a bracket expression to be literal;
    # `[+\-~?]` is interpreted as a literal backslash on some grep builds.
    grep -qE '(^| )[-+~?]?ptr( |:|$)' <<< "$1"
}

# All-qualifier: the qualifier on the `all` mechanism.
# Returns "+", "-", "~", "?", or "" if no `all` is present.
_spf_all_qual() {
    grep -oE '[-+~?]?all( |$)' <<< "$1" | head -n1 | sed -E 's/all.*//; s/^$/+/'
}

# Does $record authorise any of the server IPs?
# Returns 0 if yes. Implements a pragmatic subset of RFC 7208:
#   ip4:/ip6: literal match (with CIDR support via bash arithmetic on /32 and /128)
#   a/+a       resolves the domain itself, matches server IP
#   mx/+mx     resolves MX, then A/AAAA of each MX, matches server IP
# include: is not followed (skip), but its presence is noted.
_spf_authorizes() {
    local record="$1" domain="$2"
    local token bare
    local mech mech_arg

    for token in $record; do
        # Strip qualifier (default +) for evaluation; we only care about
        # positive matches here, leading `-` would still authorise nothing.
        bare="${token#[-+~?]}"
        [[ "$token" == -* || "$token" == "~all" || "$token" == "?all" || "$token" == "all" || "$token" == "-all" ]] && continue

        mech="${bare%%:*}"
        mech_arg="${bare#*:}"
        [[ "$mech" == "$mech_arg" ]] && mech_arg=""

        case "$mech" in
            ip4)
                local target="${mech_arg%/*}"
                for ip in "${SERVER_V4[@]}"; do
                    [[ "$ip" == "$target" ]] && return 0
                done
                ;;
            ip6)
                local target="${mech_arg%/*}"
                for ip in "${SERVER_V6[@]}"; do
                    [[ "$ip" == "$target" ]] && return 0
                done
                ;;
            a)
                local host="${mech_arg:-$domain}"
                local a aaaa
                a="$(dig +short A "$host" 2>/dev/null)"
                aaaa="$(dig +short AAAA "$host" 2>/dev/null)"
                for ip in "${SERVER_V4[@]}"; do
                    grep -qxF "$ip" <<< "$a" && return 0
                done
                for ip in "${SERVER_V6[@]}"; do
                    grep -qxF "$ip" <<< "$aaaa" && return 0
                done
                ;;
            mx)
                local host="${mech_arg:-$domain}"
                local mx_list mxh
                mx_list="$(dig +short MX "$host" 2>/dev/null | awk '{print $2}' | sed 's/\.$//')"
                while IFS= read -r mxh; do
                    [[ -z "$mxh" ]] && continue
                    local a aaaa
                    a="$(dig +short A "$mxh" 2>/dev/null)"
                    aaaa="$(dig +short AAAA "$mxh" 2>/dev/null)"
                    for ip in "${SERVER_V4[@]}"; do
                        grep -qxF "$ip" <<< "$a" && return 0
                    done
                    for ip in "${SERVER_V6[@]}"; do
                        grep -qxF "$ip" <<< "$aaaa" && return 0
                    done
                done <<< "$mx_list"
                ;;
        esac
    done
    return 1
}

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_SPF_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    mapfile -t recs < <(_spf_records "$d")

    # 1. Presence + uniqueness
    if (( ${#recs[@]} == 0 )); then
        emit "health.mail.spf.${d}" "medium" "warn" "${d}: no SPF record" \
            "publish TXT: v=spf1 +a +mx -all"
        continue
    fi
    if (( ${#recs[@]} > 1 )); then
        emit "health.mail.spf.${d}.multi" "high" "fail" \
            "${d}: ${#recs[@]} SPF records (RFC 7208 forbids more than one)" \
            "merge into a single TXT record"
        # Keep going with the first one so we still report on its content.
    fi

    rec="${recs[0]}"

    # 2. Server-IP authorisation
    if (( ${#SERVER_IPS[@]} == 0 )); then
        emit "health.mail.spf.${d}.coverage" "low" "skip" \
            "${d}: cannot determine this server's IPs, coverage check skipped"
    elif _spf_authorizes "$rec" "$d"; then
        emit "health.mail.spf.${d}.coverage" "info" "pass" \
            "${d}: server IP authorised by SPF"
    else
        emit "health.mail.spf.${d}.coverage" "high" "fail" \
            "${d}: SPF does not authorise this server's IPs" \
            "add: ip4:${SERVER_V4[0]:-X.X.X.X}${SERVER_V6[0]:+ ip6:${SERVER_V6[0]}}"
    fi

    # 3. All-qualifier strength
    qual="$(_spf_all_qual "$rec")"
    case "$qual" in
        -)  emit "health.mail.spf.${d}.policy" "info" "pass" "${d}: hard fail (-all)" ;;
        \~) emit "health.mail.spf.${d}.policy" "low"  "pass" "${d}: soft fail (~all)" ;;
        \?) emit "health.mail.spf.${d}.policy" "medium" "warn" \
                "${d}: neutral (?all) — receivers will not act on SPF failures" \
                "tighten to ~all or -all" ;;
        +)  emit "health.mail.spf.${d}.policy" "high" "warn" \
                "${d}: pass-all (+all) — anyone can send as you" \
                "tighten to -all" ;;
        "") emit "health.mail.spf.${d}.policy" "medium" "warn" \
                "${d}: no all mechanism (defaults to neutral)" \
                "append -all (or ~all during rollout)" ;;
    esac

    # 4. DNS-lookup budget
    lookups="$(_spf_lookup_count "$rec")"
    if (( lookups > 10 )); then
        emit "health.mail.spf.${d}.lookups" "high" "fail" \
            "${d}: ${lookups} DNS lookups (RFC 7208 limit is 10)" \
            "flatten include: chains or drop unused includes"
    elif (( lookups > 8 )); then
        emit "health.mail.spf.${d}.lookups" "medium" "warn" \
            "${d}: ${lookups} DNS lookups (limit 10, close)"
    fi

    # 5. ptr mechanism (deprecated, RFC 7208 §5.5)
    if _spf_has_ptr "$rec"; then
        emit "health.mail.spf.${d}.ptr" "medium" "warn" \
            "${d}: uses 'ptr' (deprecated, slow, error-prone)" \
            "replace ptr with explicit ip4:/ip6: or +a/+mx"
    fi
done
