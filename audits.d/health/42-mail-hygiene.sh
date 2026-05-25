# audits.d/health/42-mail-hygiene.sh — consolidated per-domain mail health
#
# One table row per mail-enabled domain with columns:
#   SPF        coverage + all-qualifier strength
#   DKIM       local key bit-length, DNS ↔ local match
#   DMARC      policy strength (reject > quarantine > none)
#   Mailboxes  count + sieve sanity (Plesk fileinto "INBOX" bug detector)
#
# Per-row emit() lines carry the detailed fix hints for the worst finding.
#
# Replaces the previous four files (42-mail-spf, 43-mail-dkim,
# 44-mail-dmarc, 46-mail-mailboxes).
#
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "health: mail hygiene"

: "${MAIL_HYGIENE_MAX_DOMAINS:=50}"
: "${MAIL_DKIM_MIN_BITS:=2048}"
: "${DKIM_SELECTOR:=default}"
: "${MAIL_SIEVE_CHECK:=1}"
: "${MAIL_DOMAIN_TRUNCATE:=22}"

if ! _plesk_available; then
    emit "health.mail.hygiene" "medium" "skip" "plesk CLI not available"
    return 0
fi
if ! command -v dig >/dev/null 2>&1; then
    emit "health.mail.hygiene" "medium" "skip" "dig(1) not available"
    return 0
fi
if ! command -v openssl >/dev/null 2>&1; then
    emit "health.mail.hygiene" "medium" "skip" "openssl(1) not available"
    return 0
fi
if ! _plesk_mail_in_use; then
    emit "health.mail.hygiene" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
(( ${#domains[@]} > 0 )) || { emit "health.mail.hygiene" "info" "skip" "no mail-enabled domains"; return 0; }

# Server IPs (authoritative source: Plesk DB) — used for SPF coverage check.
mapfile -t SERVER_IPS < <(_plesk_server_ips 2>/dev/null || true)
SERVER_V4=()
SERVER_V6=()
# Bash 4.2 (CentOS 7) + set -u: ${arr[@]} on an empty array is "unbound".
# Use ${arr[@]+"${arr[@]}"} to expand safely.
for ip in ${SERVER_IPS[@]+"${SERVER_IPS[@]}"}; do
    [[ "$ip" == *:* ]] && SERVER_V6+=("$ip") || SERVER_V4+=("$ip")
done

# ─── SPF helpers (lifted from old 42-mail-spf.sh) ────────────────────────────

_spf_records() {
    dig +short TXT "$1" 2>/dev/null \
        | awk '/v=spf1/ { gsub(/"/,""); gsub(/[[:space:]]+/," "); print }'
}

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

_spf_has_ptr() { grep -qE '(^| )[-+~?]?ptr( |:|$)' <<< "$1"; }

_spf_all_qual() {
    grep -oE '[-+~?]?all( |$)' <<< "$1" | head -n1 | sed -E 's/all.*//; s/^$/+/'
}

_spf_authorizes() {
    local record="$1" domain="$2" token bare mech mech_arg
    for token in $record; do
        bare="${token#[-+~?]}"
        [[ "$token" == -* || "$token" == "~all" || "$token" == "?all" || "$token" == "all" || "$token" == "-all" ]] && continue
        mech="${bare%%:*}"
        mech_arg="${bare#*:}"
        [[ "$mech" == "$mech_arg" ]] && mech_arg=""
        case "$mech" in
            ip4)
                local target="${mech_arg%/*}"
                for ip in ${SERVER_V4[@]+"${SERVER_V4[@]}"}; do [[ "$ip" == "$target" ]] && return 0; done ;;
            ip6)
                local target="${mech_arg%/*}"
                for ip in ${SERVER_V6[@]+"${SERVER_V6[@]}"}; do [[ "$ip" == "$target" ]] && return 0; done ;;
            a)
                local host="${mech_arg:-$domain}" a aaaa
                a="$(dig +short A "$host" 2>/dev/null)"
                aaaa="$(dig +short AAAA "$host" 2>/dev/null)"
                for ip in ${SERVER_V4[@]+"${SERVER_V4[@]}"}; do grep -qxF "$ip" <<< "$a" && return 0; done
                for ip in ${SERVER_V6[@]+"${SERVER_V6[@]}"}; do grep -qxF "$ip" <<< "$aaaa" && return 0; done ;;
            mx)
                local host="${mech_arg:-$domain}" mx_list mxh
                mx_list="$(dig +short MX "$host" 2>/dev/null | awk '{print $2}' | sed 's/\.$//')"
                while IFS= read -r mxh; do
                    [[ -z "$mxh" ]] && continue
                    local a aaaa
                    a="$(dig +short A "$mxh" 2>/dev/null)"
                    aaaa="$(dig +short AAAA "$mxh" 2>/dev/null)"
                    for ip in ${SERVER_V4[@]+"${SERVER_V4[@]}"}; do grep -qxF "$ip" <<< "$a" && return 0; done
                    for ip in ${SERVER_V6[@]+"${SERVER_V6[@]}"}; do grep -qxF "$ip" <<< "$aaaa" && return 0; done
                done <<< "$mx_list" ;;
        esac
    done
    return 1
}

# Grades SPF for one domain. Sets SPF_STATUS, SPF_CELL, SPF_FIX, SPF_SEV.
_grade_spf() {
    local d="$1"
    SPF_FIX="" SPF_SEV="info"
    mapfile -t recs < <(_spf_records "$d")

    if (( ${#recs[@]} == 0 )); then
        SPF_STATUS="fail"; SPF_CELL="$(status_cell fail 'miss')"; SPF_SEV="medium"
        SPF_FIX="publish TXT: v=spf1 +a +mx -all"
        return
    fi
    if (( ${#recs[@]} > 1 )); then
        SPF_STATUS="fail"; SPF_CELL="$(status_cell fail 'multi')"; SPF_SEV="high"
        SPF_FIX="merge ${#recs[@]} SPF records into one (RFC 7208 forbids multiple)"
        return
    fi

    local rec="${recs[0]}"
    if (( ${#SERVER_IPS[@]} > 0 )) && ! _spf_authorizes "$rec" "$d"; then
        SPF_STATUS="fail"; SPF_CELL="$(status_cell fail 'no-ip')"; SPF_SEV="high"
        SPF_FIX="add: ip4:${SERVER_V4[0]:-X.X.X.X}${SERVER_V6[0]:+ ip6:${SERVER_V6[0]}}"
        return
    fi

    local qual short status sev
    qual="$(_spf_all_qual "$rec")"
    case "$qual" in
        -)  status="pass"; sev="info";  short="-all" ;;
        \~) status="pass"; sev="low";   short="~all" ;;
        \?) status="warn"; sev="medium"; short="?all"; SPF_FIX="tighten ?all to ~all or -all" ;;
        +)  status="warn"; sev="high";  short="+all"; SPF_FIX="+all lets anyone send as ${d} — tighten to -all" ;;
        "") status="warn"; sev="medium"; short="all?"; SPF_FIX="append -all (or ~all during rollout)" ;;
    esac

    local lookups; lookups="$(_spf_lookup_count "$rec")"
    if (( lookups > 10 )); then
        status="fail"; sev="high"; short="${lookups}lk"
        SPF_FIX="${lookups} DNS lookups exceeds RFC limit of 10 — flatten includes"
    elif (( lookups > 8 )) && [[ "$status" == "pass" ]]; then
        status="warn"; sev="medium"; short="${lookups}lk"
        SPF_FIX="${lookups} DNS lookups, RFC limit 10 — flatten includes"
    fi

    if _spf_has_ptr "$rec" && [[ "$status" == "pass" ]]; then
        status="warn"; sev="medium"; short="ptr"
        SPF_FIX="replace deprecated ptr mechanism with ip4:/ip6: or +a/+mx"
    fi

    SPF_STATUS="$status"; SPF_SEV="$sev"
    SPF_CELL="$(status_cell "$status" "$short")"
}

# ─── DKIM helpers (lifted from old 43-mail-dkim.sh) ──────────────────────────

_dkim_dns_p() {
    sed -E -n 's/.*[[:space:]]*p=([A-Za-z0-9+/=]+).*/\1/p' <<< "$1"
}
_pem_body() {
    awk '/-----BEGIN /{flag=1; next} /-----END /{flag=0} flag' | tr -d '\n'
}
_rsa_bits() {
    openssl rsa -in "$1" -text -noout 2>/dev/null \
        | awk '/Private-Key:.*bit/ {gsub(/[^0-9]/,"",$2); print $2; exit}'
}

# Grades DKIM for one domain. Sets DKIM_STATUS, DKIM_CELL, DKIM_FIX, DKIM_SEV.
_grade_dkim() {
    local d="$1" sel="$DKIM_SELECTOR" keyfile alt
    DKIM_FIX="" DKIM_SEV="info"
    keyfile="$(_plesk_dkim_key_path "$d" "$sel")"

    if [[ ! -r "$keyfile" ]]; then
        alt="$(find "/etc/domainkeys/${d}" -maxdepth 1 -type f -printf '%f\n' 2>/dev/null | head -n1)"
        if [[ -n "$alt" && -r "/etc/domainkeys/${d}/${alt}" ]]; then
            sel="$alt"; keyfile="/etc/domainkeys/${d}/${sel}"
        else
            DKIM_STATUS="warn"; DKIM_SEV="medium"
            DKIM_CELL="$(status_cell warn 'off')"
            DKIM_FIX="enable DKIM in Plesk → ${d} → Mail Settings"
            return
        fi
    fi

    local bits dns_raw dns_p local_p
    bits="$(_rsa_bits "$keyfile")"

    dns_raw="$(dig +short TXT "${sel}._domainkey.${d}" 2>/dev/null | sed 's/" "//g' | tr -d '"\n')"
    if [[ -z "$dns_raw" ]]; then
        DKIM_STATUS="fail"; DKIM_SEV="high"
        DKIM_CELL="$(status_cell fail 'no-dns')"
        DKIM_FIX="publish ${sel}._domainkey.${d} TXT from Plesk Mail Settings"
        return
    fi

    dns_p="$(_dkim_dns_p "$dns_raw")"
    if [[ -z "$dns_p" ]]; then
        DKIM_STATUS="fail"; DKIM_SEV="high"
        DKIM_CELL="$(status_cell fail 'rev')"
        DKIM_FIX="DKIM TXT has empty p= (revoked) — republish current public key"
        return
    fi

    local_p="$(openssl rsa -in "$keyfile" -pubout 2>/dev/null | _pem_body)"
    if [[ -n "$local_p" && "$dns_p" != "$local_p" ]]; then
        DKIM_STATUS="fail"; DKIM_SEV="high"
        DKIM_CELL="$(status_cell fail 'stale')"
        DKIM_FIX="DNS pubkey doesn't match local key — republish ${sel}._domainkey.${d} TXT"
        return
    fi

    # t=y testing flag → warn
    if grep -qE '(^|[[:space:]])t=[^;]*y' <<< "$dns_raw"; then
        DKIM_STATUS="warn"; DKIM_SEV="medium"
        DKIM_CELL="$(status_cell warn 't=y')"
        DKIM_FIX="DKIM TXT has t=y (testing) — remove once verified"
        return
    fi

    if [[ -n "$bits" && "$bits" -lt "$MAIL_DKIM_MIN_BITS" ]]; then
        DKIM_STATUS="warn"; DKIM_SEV="medium"
        DKIM_CELL="$(status_cell warn "${bits}b")"
        DKIM_FIX="DKIM key is ${bits}-bit — rotate to ${MAIL_DKIM_MIN_BITS}-bit in Plesk"
        return
    fi

    DKIM_STATUS="pass"; DKIM_CELL="$(status_cell pass "${bits:-?}b")"
}

# ─── DMARC helpers (lifted from old 44-mail-dmarc.sh) ────────────────────────

_dmarc_records() {
    dig +short TXT "_dmarc.$1" 2>/dev/null \
        | awk '/v=DMARC1/ { gsub(/"/,""); gsub(/[[:space:]]+/," "); print }'
}
_dmarc_tag() {
    sed -E -n "s/.*(^|[[:space:];])$1=([^;[:space:]]+).*/\\2/p" <<< "$2"
}

# Grades DMARC for one domain. Sets DMARC_STATUS, DMARC_CELL, DMARC_FIX, DMARC_SEV.
_grade_dmarc() {
    local d="$1"
    DMARC_FIX="" DMARC_SEV="info"
    mapfile -t recs < <(_dmarc_records "$d")

    if (( ${#recs[@]} == 0 )); then
        DMARC_STATUS="warn"; DMARC_SEV="medium"
        DMARC_CELL="$(status_cell warn 'miss')"
        DMARC_FIX="publish _dmarc.${d} TXT: v=DMARC1; p=quarantine; rua=mailto:postmaster@${d}"
        return
    fi
    if (( ${#recs[@]} > 1 )); then
        DMARC_STATUS="fail"; DMARC_SEV="high"
        DMARC_CELL="$(status_cell fail 'multi')"
        DMARC_FIX="consolidate ${#recs[@]} _dmarc records into one"
        return
    fi

    local rec="${recs[0]}" policy rua
    policy="$(_dmarc_tag p "$rec")"
    rua="$(_dmarc_tag rua "$rec")"

    case "$policy" in
        reject)
            DMARC_STATUS="pass"; DMARC_CELL="$(status_cell pass 'reject')" ;;
        quarantine)
            DMARC_STATUS="pass"; DMARC_CELL="$(status_cell pass 'quar')" ;;
        none)
            DMARC_STATUS="warn"; DMARC_SEV="medium"
            DMARC_CELL="$(status_cell warn 'p=none')"
            DMARC_FIX="DMARC p=none — monitor rua reports, then move to quarantine/reject" ;;
        "")
            DMARC_STATUS="fail"; DMARC_SEV="high"
            DMARC_CELL="$(status_cell fail 'no-p')"
            DMARC_FIX="DMARC record missing p= tag" ;;
        *)
            DMARC_STATUS="warn"; DMARC_SEV="medium"
            DMARC_CELL="$(status_cell warn "p=${policy:0:3}")"
            DMARC_FIX="unknown DMARC policy p=${policy}" ;;
    esac

    if [[ -z "$rua" && "$DMARC_STATUS" == "pass" ]]; then
        DMARC_STATUS="warn"; DMARC_SEV="low"
        DMARC_FIX="${DMARC_FIX:+$DMARC_FIX; }add rua=mailto:postmaster@${d}"
    fi
}

# ─── Mailboxes + sieve helpers (lifted from old 46-mail-mailboxes.sh) ────────

# Sets MBX_STATUS, MBX_CELL, MBX_FIX, MBX_SEV, MBX_COUNT.
_grade_mailboxes() {
    local d="$1"
    MBX_FIX="" MBX_SEV="info"
    mapfile -t boxes < <(_plesk_mailboxes "$d" 2>/dev/null || true)
    MBX_COUNT=${#boxes[@]}

    if (( MBX_COUNT == 0 )); then
        MBX_STATUS="skip"; MBX_CELL="$(status_cell skip '0')"
        return
    fi

    if (( MAIL_SIEVE_CHECK != 1 )); then
        MBX_STATUS="pass"; MBX_CELL="$(status_cell pass "${MBX_COUNT}")"
        return
    fi

    local u sieve owner bad_inbox=() bad_owner=()
    for u in "${boxes[@]}"; do
        sieve="$(_plesk_sieve_path "$d" "$u")"
        [[ -r "$sieve" ]] || continue
        if grep -qE 'fileinto[[:space:]]+"INBOX"' "$sieve" 2>/dev/null; then
            bad_inbox+=("$u")
        fi
        owner="$(stat -c '%U:%G' "$sieve" 2>/dev/null || echo "")"
        if [[ -n "$owner" && "$owner" != "popuser:popuser" ]]; then
            bad_owner+=("${u}(${owner})")
        fi
    done

    if (( ${#bad_inbox[@]} > 0 )); then
        MBX_STATUS="warn"; MBX_SEV="medium"
        MBX_CELL="$(status_cell warn "${MBX_COUNT}")"
        MBX_FIX="sieve fileinto \"INBOX\" bug in ${#bad_inbox[@]} mailbox(es): ${bad_inbox[*]} — change to \"INBOX.Spam\""
    elif (( ${#bad_owner[@]} > 0 )); then
        MBX_STATUS="warn"; MBX_SEV="low"
        MBX_CELL="$(status_cell warn "${MBX_COUNT}")"
        MBX_FIX="${#bad_owner[@]} sieve file(s) with wrong owner: ${bad_owner[*]} — chown popuser:popuser"
    else
        MBX_STATUS="pass"; MBX_CELL="$(status_cell pass "${MBX_COUNT}")"
    fi
}

# ─── Main loop ───────────────────────────────────────────────────────────────

table_init "Domain" "SPF" "DKIM" "DMARC" "Mailboxes"

checked=0
total_boxes=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_HYGIENE_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    _grade_spf       "$d"
    _grade_dkim      "$d"
    _grade_dmarc     "$d"
    _grade_mailboxes "$d"
    total_boxes=$(( total_boxes + MBX_COUNT ))

    label="$(truncate "$d" "$MAIL_DOMAIN_TRUNCATE")"
    table_row "$label" "$SPF_CELL" "$DKIM_CELL" "$DMARC_CELL" "$MBX_CELL"

    row_status="$(worst_status "$SPF_STATUS" "$DKIM_STATUS" "$DMARC_STATUS" "$MBX_STATUS")"
    row_sev="$(worst_severity "$SPF_SEV" "$DKIM_SEV" "$DMARC_SEV" "$MBX_SEV")"

    fixes=""
    for f in "$SPF_FIX" "$DKIM_FIX" "$DMARC_FIX" "$MBX_FIX"; do
        [[ -n "$f" ]] || continue
        [[ -n "$fixes" ]] && fixes+=" | "
        fixes+="$f"
    done

    emit "health.mail.${d}" "$row_sev" "$row_status" \
        "${d}: spf=${SPF_STATUS} dkim=${DKIM_STATUS} dmarc=${DMARC_STATUS} mbx=${MBX_STATUS}/${MBX_COUNT}" \
        "$fixes"
done

table_render

# Summary line: total mailboxes across checked domains.
emit "health.mail.mailbox_total" "info" "pass" \
    "${total_boxes} mailboxes across ${checked} domain(s)"
