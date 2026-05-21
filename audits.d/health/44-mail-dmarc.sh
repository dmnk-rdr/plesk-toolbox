# audits.d/health/44-mail-dmarc.sh - DMARC record validation, not just presence
#
# Checks per mail-enabled domain:
#   * exactly one v=DMARC1 record
#   * policy strength (p=none < quarantine < reject)
#   * rua= present (aggregate reports go somewhere)
#   * pct= sensible (info if <100, the rollout phase)
#   * adkim/aspf alignment flag (relaxed by default; strict reported)
#   * sp= subdomain policy informational
#
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "health: mail DMARC"

: "${MAIL_DMARC_MAX_DOMAINS:=50}"

if ! _plesk_available; then
    emit "health.mail.dmarc" "medium" "skip" "plesk CLI not available"
    return 0
fi

if ! command -v dig >/dev/null 2>&1; then
    emit "health.mail.dmarc" "medium" "skip" "dig(1) not available"
    return 0
fi

if ! _plesk_mail_in_use; then
    emit "health.mail.dmarc" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
(( ${#domains[@]} > 0 )) || { emit "health.mail.dmarc" "info" "skip" "no mail-enabled domains"; return 0; }

# Fetch DMARC TXT records (joined, one per line).
_dmarc_records() {
    dig +short TXT "_dmarc.$1" 2>/dev/null \
        | awk '/v=DMARC1/ { gsub(/"/,""); gsub(/[[:space:]]+/," "); print }'
}

# Extract a tag's value from a DMARC record. _dmarc_tag <tag> <record>
_dmarc_tag() {
    sed -E -n "s/.*(^|[[:space:];])$1=([^;[:space:]]+).*/\\2/p" <<< "$2"
}

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_DMARC_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    mapfile -t recs < <(_dmarc_records "$d")

    # 1. Presence + uniqueness
    if (( ${#recs[@]} == 0 )); then
        emit "health.mail.dmarc.${d}" "medium" "warn" "${d}: no DMARC record" \
            "publish _dmarc.${d} TXT: v=DMARC1; p=quarantine; rua=mailto:postmaster@${d}"
        continue
    fi
    if (( ${#recs[@]} > 1 )); then
        emit "health.mail.dmarc.${d}.multi" "high" "fail" \
            "${d}: ${#recs[@]} DMARC records (only one allowed)" \
            "consolidate into a single _dmarc TXT record"
    fi
    rec="${recs[0]}"

    # 2. Policy
    policy="$(_dmarc_tag p "$rec")"
    case "$policy" in
        reject)
            emit "health.mail.dmarc.${d}.policy" "info" "pass" "${d}: p=reject (enforced)" ;;
        quarantine)
            emit "health.mail.dmarc.${d}.policy" "info" "pass" "${d}: p=quarantine" ;;
        none)
            emit "health.mail.dmarc.${d}.policy" "medium" "warn" \
                "${d}: p=none — monitoring only, no enforcement" \
                "after monitoring rua reports, move to p=quarantine then p=reject" ;;
        "")
            emit "health.mail.dmarc.${d}.policy" "high" "fail" \
                "${d}: DMARC record has no p= tag (required)" \
                "set p=quarantine or p=reject" ;;
        *)
            emit "health.mail.dmarc.${d}.policy" "medium" "warn" \
                "${d}: unknown DMARC policy p=${policy}" ;;
    esac

    # 3. Aggregate reporting target
    rua="$(_dmarc_tag rua "$rec")"
    if [[ -z "$rua" ]]; then
        emit "health.mail.dmarc.${d}.rua" "low" "warn" \
            "${d}: no rua= aggregate-report destination" \
            "add rua=mailto:postmaster@${d} (or an inbox you actually read)"
    else
        emit "health.mail.dmarc.${d}.rua" "info" "pass" "${d}: reports → ${rua}"
    fi

    # 4. pct
    pct="$(_dmarc_tag pct "$rec")"
    if [[ -n "$pct" && "$pct" =~ ^[0-9]+$ ]]; then
        if (( pct < 100 )); then
            emit "health.mail.dmarc.${d}.pct" "info" "pass" \
                "${d}: pct=${pct} (phased rollout)"
        fi
        if (( pct < 25 && policy != "none" )); then
            emit "health.mail.dmarc.${d}.pct_low" "low" "warn" \
                "${d}: pct=${pct} is very low — enforcement barely applies"
        fi
    fi

    # 5. Alignment flags (defaults are relaxed)
    aspf="$(_dmarc_tag aspf "$rec")"
    adkim="$(_dmarc_tag adkim "$rec")"
    [[ "$aspf"  == "s" ]] && emit "health.mail.dmarc.${d}.aspf"  "info" "pass" "${d}: SPF alignment strict"
    [[ "$adkim" == "s" ]] && emit "health.mail.dmarc.${d}.adkim" "info" "pass" "${d}: DKIM alignment strict"

    # 6. Subdomain policy
    sp="$(_dmarc_tag sp "$rec")"
    if [[ -n "$sp" && "$sp" != "$policy" ]]; then
        emit "health.mail.dmarc.${d}.sp" "info" "pass" "${d}: sp=${sp} (overrides p for subdomains)"
    fi
done
