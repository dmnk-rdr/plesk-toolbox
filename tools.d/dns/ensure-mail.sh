# shellcheck shell=bash
# tools.d/dns/ensure-mail.sh - reconcile mail DNS records via AutoDNS / SchlundTech
#
# Derives the desired mail-related DNS records for hosted domains from this
# server (Plesk DKIM keys, hosted-domain list) — the same truth the audits
# check — then diffs against live DNS and pushes missing records through the
# AutoDNS / SchlundTech JSON API (lib/autodns.sh).
#
# Covered: SPF, DKIM, DMARC, TLSRPT, MTA-STS TXT, autoconfig CNAME,
# autodiscover SRV. Records are only ever ADDED — or, with --replace,
# replaced in a single add+remove stream. This tool never deletes records,
# and never touches records that already pass the audit's grading.
#
# Usage: plesk-tool dns/ensure-mail [<domain> ...] [--all] [--replace]
#                                   [--ttl=N] [--dry-run] [--yes]

# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"
# shellcheck source=../../lib/dkim.sh
. "${PTBOX_ROOT}/lib/dkim.sh"
# shellcheck source=../../lib/autodns.sh
. "${PTBOX_ROOT}/lib/autodns.sh"

: "${DNS_ENSURE_TTL:=3600}"
: "${DNS_ENSURE_SPF:=v=spf1 +a +mx -all}"
# Not `: "${VAR:=…}"` — the {domain} placeholder's closing brace would
# terminate the parameter expansion early and eat the trailing "}".
if [[ -z "${DNS_ENSURE_DMARC:-}" ]]; then
    DNS_ENSURE_DMARC='v=DMARC1; p=quarantine; rua=mailto:postmaster@{domain}'
fi
: "${DNS_ENSURE_TLSRPT:=1}"
: "${DNS_ENSURE_MTA_STS:=1}"
: "${DNS_ENSURE_AUTOCONFIG:=1}"

usage() {
    cat <<EOF
plesk-tool dns/ensure-mail [<domain> ...] [--all] [flags]

Reconciles mail-related DNS records (SPF, DKIM, DMARC, TLSRPT, MTA-STS,
autoconfig/autodiscover) against the AutoDNS / SchlundTech JSON API.

arguments:
  <domain> ...    one or more hosted domains
  --all           every mail-enabled Plesk domain (honors IGNORE_DOMAINS)

flags:
  --replace       also replace records that exist but grade badly
                  (default: existing-but-different records are only reported)
  --ttl=N         TTL for new records (default: ${DNS_ENSURE_TTL})
  --dry-run       show the plan, change nothing (works without credentials)
  --yes           skip the confirmation prompt

credentials (root-only file, see plesk-toolbox.conf.example):
  ${AUTODNS_SECRETS}
      AUTODNS_USER="account"  AUTODNS_PASSWORD="..."  AUTODNS_CONTEXT=10

config overrides: DNS_ENSURE_TTL, DNS_ENSURE_SPF, DNS_ENSURE_DMARC,
  DNS_ENSURE_TLSRPT, DNS_ENSURE_MTA_STS, DNS_ENSURE_AUTOCONFIG,
  DKIM_SELECTOR, AUTODNS_URL, AUTODNS_CONTEXT, AUTODNS_SECRETS
EOF
}

HAVE_CREDS=0

# ─── plan (parallel arrays; states: ok add differs manual skip) ─────────────
P_FQDN=(); P_ZONE=(); P_VNS=(); P_TYPE=(); P_VALUE=(); P_PREF=()
P_STATE=(); P_NOTE=()

# _plan <fqdn> <zone> <vns> <type> <value> <pref> <state> <note>
_plan() {
    P_FQDN+=("$1"); P_ZONE+=("$2"); P_VNS+=("$3"); P_TYPE+=("$4")
    P_VALUE+=("$5"); P_PREF+=("$6"); P_STATE+=("$7"); P_NOTE+=("$8")
}

# ─── live DNS helpers (system resolver — same view the audits grade) ────────

# TXT values for a name: quotes stripped, 255-byte chunks joined, one per line.
_txt_live() {
    dig +short TXT "$1" 2>/dev/null | sed 's/" "//g' | tr -d '"' | tr -s ' '
}

_resolves() {
    local t
    for t in A AAAA CNAME; do
        [[ -n "$(dig +short "$t" "$1" 2>/dev/null)" ]] && return 0
    done
    return 1
}

# _rel_name <fqdn> <zone> — record name relative to zone ("" = apex)
_rel_name() {
    local fqdn="$1" zone="$2"
    if [[ "$fqdn" == "$zone" ]]; then
        printf ''
    else
        printf '%s' "${fqdn%."$zone"}"
    fi
}

# First authoritative NS of a zone (for post-apply verification), cached.
declare -A _ZNS_CACHE
_zone_ns() {
    local zone="$1"
    if [[ -z "${_ZNS_CACHE[$zone]:-}" ]]; then
        _ZNS_CACHE[$zone]="$(dig +short NS "$zone" 2>/dev/null | head -n1)"
        _ZNS_CACHE[$zone]="${_ZNS_CACHE[$zone]:--}"
    fi
    [[ "${_ZNS_CACHE[$zone]}" == "-" ]] && return 1
    printf '%s' "${_ZNS_CACHE[$zone]}"
}

# ─── per-domain desired-state computation ───────────────────────────────────

_plan_domain() {
    local d="$1" zone="" vns="" zinfo rc=0

    # Which zone does this domain live in — and is it ours to write?
    if (( HAVE_CREDS )); then
        zinfo="$(autodns_zone_find "$d")" || rc=$?
        case "$rc" in
            1) _plan "$d" "-" "-" "-" "" "" skip "zone not in this AutoDNS/SchlundTech account"; return 0 ;;
            2) _plan "$d" "-" "-" "-" "" "" skip "zone lookup failed (API error, see above)"; return 0 ;;
        esac
        zone="${zinfo%% *}"
        vns="${zinfo#* }"
    else
        # No credentials (dry-run): find the zone apex via SOA walk; whether
        # the account actually manages it is verified at apply time.
        local cand="$d"
        while [[ "$cand" == *.* ]]; do
            if [[ -n "$(dig +short SOA "$cand" 2>/dev/null)" ]]; then
                zone="$cand"
                break
            fi
            cand="${cand#*.}"
        done
        vns="?"
        if [[ -z "$zone" ]]; then
            _plan "$d" "-" "-" "-" "" "" skip "no zone apex found (domain not delegated?)"
            return 0
        fi
    fi

    # ── SPF ──────────────────────────────────────────────────────────────
    local -a spf=()
    mapfile -t spf < <(_txt_live "$d" | grep '^v=spf1' || true)
    if (( ${#spf[@]} == 0 )); then
        _plan "$d" "$zone" "$vns" TXT "$DNS_ENSURE_SPF" "" add "SPF missing"
    elif (( ${#spf[@]} > 1 )); then
        _plan "$d" "$zone" "$vns" TXT "$DNS_ENSURE_SPF" "" manual \
            "${#spf[@]} SPF records (RFC 7208 forbids multiple) — merge by hand"
    else
        local rec="${spf[0]% }"
        case " $rec " in
            *" -all "*|*" ~all "*)
                _plan "$d" "$zone" "$vns" TXT "$rec" "" ok "" ;;
            *)
                _plan "$d" "$zone" "$vns" TXT "$DNS_ENSURE_SPF" "" differs \
                    "weak qualifier, live: $rec" ;;
        esac
    fi

    # ── DKIM (from the local Plesk key — the only source of truth) ───────
    local keyfile="" sel="" dkim_name="" dkim_value="" dstatus=""
    keyfile="$(dkim_keyfile "$d" "" 2>/dev/null)" || true
    if [[ -z "$keyfile" || ! -r "$keyfile" ]]; then
        _plan "_domainkey.$d" "$zone" "$vns" TXT "" "" skip \
            "no local DKIM key — enable DKIM in Plesk first"
    else
        sel="$(dkim_selector_for_keyfile "$keyfile")"
        dkim_name="$(dkim_record_name "$sel" "$d")"
        dkim_value="$(dkim_record_value "$keyfile")" || dkim_value=""
        if [[ -z "$dkim_value" ]]; then
            _plan "$dkim_name" "$zone" "$vns" TXT "" "" skip "cannot derive public key from $keyfile"
        else
            # dkim_status sets DKIM_BITS, but the command substitution runs
            # in a subshell — read the key length ourselves.
            local bits
            bits="$(dkim_rsa_bits "$keyfile")"
            dstatus="$(dkim_status "$keyfile" "$sel" "$d")"
            case "$dstatus" in
                no-dns)
                    _plan "$dkim_name" "$zone" "$vns" TXT "$dkim_value" "" add "DKIM TXT missing" ;;
                stale|revoked)
                    _plan "$dkim_name" "$zone" "$vns" TXT "$dkim_value" "" differs \
                        "published key is $dstatus vs local key" ;;
                testing)
                    _plan "$dkim_name" "$zone" "$vns" TXT "$dkim_value" "" ok \
                        "t=y testing flag set — remove once verified" ;;
                weak)
                    _plan "$dkim_name" "$zone" "$vns" TXT "$dkim_value" "" ok \
                        "${bits:-?}-bit key — rotate via tool mail/dkim-rotate" ;;
                *)
                    _plan "$dkim_name" "$zone" "$vns" TXT "$dkim_value" "" ok "" ;;
            esac
        fi
    fi

    # ── DMARC ─────────────────────────────────────────────────────────────
    local dmarc_desired="${DNS_ENSURE_DMARC//\{domain\}/$d}"
    local -a dm=()
    mapfile -t dm < <(_txt_live "_dmarc.$d" | grep -i '^v=DMARC1' || true)
    if (( ${#dm[@]} == 0 )); then
        _plan "_dmarc.$d" "$zone" "$vns" TXT "$dmarc_desired" "" add "DMARC missing"
    elif (( ${#dm[@]} > 1 )); then
        _plan "_dmarc.$d" "$zone" "$vns" TXT "$dmarc_desired" "" manual \
            "${#dm[@]} DMARC records — consolidate by hand"
    else
        local pol
        pol="$(sed -E -n 's/.*[; ] *p=([^; ]+).*/\1/p' <<< "${dm[0]}")"
        case "$pol" in
            quarantine|reject)
                _plan "_dmarc.$d" "$zone" "$vns" TXT "${dm[0]}" "" ok "p=$pol" ;;
            *)
                _plan "_dmarc.$d" "$zone" "$vns" TXT "$dmarc_desired" "" differs \
                    "live: ${dm[0]}" ;;
        esac
    fi

    # ── TLSRPT ────────────────────────────────────────────────────────────
    if (( DNS_ENSURE_TLSRPT == 1 )); then
        if _txt_live "_smtp._tls.$d" | grep -qi '^v=TLSRPTv1'; then
            _plan "_smtp._tls.$d" "$zone" "$vns" TXT "" "" ok ""
        else
            _plan "_smtp._tls.$d" "$zone" "$vns" TXT \
                "v=TLSRPTv1; rua=mailto:postmaster@${d}" "" add "TLSRPT missing"
        fi
    fi

    # ── MTA-STS (TXT only published once the policy file is actually
    #    served — a dangling _mta-sts record helps nobody) ─────────────────
    if (( DNS_ENSURE_MTA_STS == 1 )); then
        if _txt_live "_mta-sts.$d" | grep -qi '^v=STSv1'; then
            _plan "_mta-sts.$d" "$zone" "$vns" TXT "" "" ok ""
        else
            local policy
            policy="$(curl -s --max-time 6 \
                "https://mta-sts.${d}/.well-known/mta-sts.txt" 2>/dev/null || true)"
            if grep -q 'STSv1' <<< "$policy"; then
                _plan "_mta-sts.$d" "$zone" "$vns" TXT \
                    "v=STSv1; id=$(date -u +%Y%m%d%H%M%S)" "" add "MTA-STS TXT missing"
            else
                _plan "_mta-sts.$d" "$zone" "$vns" TXT "" "" skip \
                    "publish https://mta-sts.${d}/.well-known/mta-sts.txt first"
            fi
        fi
    fi

    # ── autoconfig / autodiscover ─────────────────────────────────────────
    if (( DNS_ENSURE_AUTOCONFIG == 1 )); then
        if _resolves "autoconfig.$d"; then
            _plan "autoconfig.$d" "$zone" "$vns" CNAME "" "" ok ""
        else
            _plan "autoconfig.$d" "$zone" "$vns" CNAME "${d}." "" add "autoconfig host missing"
        fi
        if _resolves "autodiscover.$d" \
            || [[ -n "$(dig +short SRV "_autodiscover._tcp.$d" 2>/dev/null)" ]]; then
            _plan "_autodiscover._tcp.$d" "$zone" "$vns" SRV "" "" ok ""
        else
            # SRV value = "<weight> <port> <target>", priority via pref.
            _plan "_autodiscover._tcp.$d" "$zone" "$vns" SRV "0 443 ${d}." "0" add \
                "autodiscover SRV missing"
        fi
    fi
}

# ─── plan rendering ──────────────────────────────────────────────────────────

_state_cell() {
    case "$1" in
        ok)      printf '%sOK     %s' "$C_GRN" "$C_RST" ;;
        add)     printf '%sADD    %s' "$C_YEL" "$C_RST" ;;
        differs) printf '%sDIFFERS%s' "$C_RED" "$C_RST" ;;
        manual)  printf '%sMANUAL %s' "$C_RED" "$C_RST" ;;
        skip)    printf '%sSKIP   %s' "$C_DIM" "$C_RST" ;;
    esac
}

_print_plan() {
    printf '\n  %-7s %-34s %-5s %-40s %s\n' "STATE" "RECORD" "TYPE" "VALUE" "NOTE"
    local i
    for i in "${!P_FQDN[@]}"; do
        printf '  %s %-34s %-5s %-40s %s%s%s\n' \
            "$(_state_cell "${P_STATE[$i]}")" \
            "$(truncate "${P_FQDN[$i]}" 34)" \
            "${P_TYPE[$i]}" \
            "$(truncate "${P_VALUE[$i]}" 40)" \
            "$C_DIM" "${P_NOTE[$i]}" "$C_RST"
    done
}

# ─── apply ───────────────────────────────────────────────────────────────────

# _apply_zone <zone> <vns> <replace> <idx...>
# Batches all planned changes of one zone into a single _stream call.
_apply_zone() {
    local zone="$1" vns="$2" replace="$3"
    shift 3
    local adds='[]' rems='[]' zrecs="" i rel rr prefix matched n_add=0 n_rem=0

    for i in "$@"; do
        rel="$(_rel_name "${P_FQDN[$i]}" "$zone")"
        rr="$(autodns_rr_json "$rel" "${P_TYPE[$i]}" "${P_VALUE[$i]}" \
            "$DNS_ENSURE_TTL" "${P_PREF[$i]}")"

        if [[ "${P_STATE[$i]}" == "differs" ]]; then
            (( replace == 1 )) || continue
            # Remove exactly what the API has under this name/type. For TXT
            # the value prefix (v=spf1 / v=DMARC1 / v=DKIM1) keeps unrelated
            # TXT records at the same name untouched.
            if [[ -z "$zrecs" ]]; then
                zrecs="$(autodns_zone_records "$zone" "$vns")" || zrecs="[]"
            fi
            prefix=""
            [[ "${P_TYPE[$i]}" == "TXT" ]] && prefix="${P_VALUE[$i]%% *}"
            matched="$(jq -c --arg n "$rel" --arg t "${P_TYPE[$i]}" --arg p "$prefix" \
                'map(select(.name == $n and .type == $t
                    and (($p == "") or (.value | startswith($p)))))' <<< "$zrecs")"
            if [[ "$matched" == "[]" ]]; then
                printf '  %swarning:%s %s %s: no live record matched via API — not replacing\n' \
                    "$C_YEL" "$C_RST" "${P_FQDN[$i]}" "${P_TYPE[$i]}"
                continue
            fi
            rems="$(jq -c --argjson m "$matched" '. + $m' <<< "$rems")"
            n_rem=$(( n_rem + $(jq 'length' <<< "$matched") ))
        fi

        adds="$(jq -c --argjson rr "$rr" '. + [$rr]' <<< "$adds")"
        n_add=$(( n_add + 1 ))
        P_STATE[i]="applied"
    done

    (( n_add == 0 )) && return 0
    printf '  zone %s: streaming %d add(s), %d remove(s)\n' "$zone" "$n_add" "$n_rem"
    if ! autodns_zone_stream "$zone" "$adds" "$rems"; then
        printf '  %serror:%s zone %s update failed\n' "$C_RED" "$C_RST" "$zone"
        return 1
    fi
    return 0
}

# _verify_applied — re-resolve every applied record against the zone's
# authoritative NS. PENDING is not an error (NS push can lag a little).
_verify_applied() {
    local i ns got want
    for i in "${!P_FQDN[@]}"; do
        [[ "${P_STATE[$i]}" == "applied" ]] || continue
        ns="$(_zone_ns "${P_ZONE[$i]}")" || ns=""
        case "${P_TYPE[$i]}" in
            TXT)
                got="$(dig +short TXT "${P_FQDN[$i]}" ${ns:+@"$ns"} 2>/dev/null \
                    | sed 's/" "//g' | tr -d '"' | tr -s ' ')"
                want="$(tr -s ' ' <<< "${P_VALUE[$i]}")"
                ;;
            CNAME)
                got="$(dig +short CNAME "${P_FQDN[$i]}" ${ns:+@"$ns"} 2>/dev/null)"
                want="${P_VALUE[$i]%.}"
                got="${got%.}"
                ;;
            SRV)
                got="$(dig +short SRV "${P_FQDN[$i]}" ${ns:+@"$ns"} 2>/dev/null)"
                want=""   # any answer counts
                ;;
        esac
        if { [[ -z "$want" ]] && [[ -n "$got" ]]; } || grep -qxF "$want" <<< "$got"; then
            printf '  %sverified%s %s %s\n' "$C_GRN" "$C_RST" "${P_FQDN[$i]}" "${P_TYPE[$i]}"
        else
            printf '  %spending %s %s %s (not yet on %s — re-run audit later)\n' \
                "$C_YEL" "$C_RST" "${P_FQDN[$i]}" "${P_TYPE[$i]}" "${ns:-resolver}"
        fi
    done
}

main() {
    local -a domains=()
    local all=0 replace=0 a
    for a in "$@"; do
        case "$a" in
            --all)     all=1 ;;
            --replace) replace=1 ;;
            --ttl=*)   DNS_ENSURE_TTL="${a#*=}" ;;
            -*)        printf 'unknown flag: %s\n\n' "$a" >&2; usage; return 2 ;;
            *)         domains+=("$a") ;;
        esac
    done

    tool_begin "dns.ensure_mail" "reconcile mail DNS records via AutoDNS/SchlundTech" || return 1

    local dep
    for dep in dig jq curl; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            printf '  error: %s(1) not available\n' "$dep" >&2
            tool_end "skip"
            return 1
        fi
    done

    if (( all == 1 )); then
        mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
        if (( ${#domains[@]} == 0 )); then
            printf '  no mail-enabled Plesk domains found\n'
            tool_end "skip"
            return 1
        fi
    elif (( ${#domains[@]} == 0 )); then
        usage >&2
        tool_end "skip"
        return 2
    fi

    if autodns_load_credentials 2>/dev/null; then
        HAVE_CREDS=1
        label_line "api" "${AUTODNS_URL} (context ${AUTODNS_CONTEXT})"
    elif (( DRY_RUN == 1 )); then
        printf '  note: no API credentials — planning from public DNS only\n'
        printf '        (zone ownership is verified once credentials exist)\n'
    else
        printf '  error: no API credentials — create %s (see --help)\n' "$AUTODNS_SECRETS" >&2
        tool_end "fail"
        return 1
    fi
    label_line "domains" "${#domains[@]}"

    local d
    for d in "${domains[@]}"; do
        _plan_domain "$d"
    done

    _print_plan

    # Tally what the plan wants to do.
    local i n_add=0 n_diff=0 n_manual=0
    for i in "${!P_STATE[@]}"; do
        case "${P_STATE[$i]}" in
            add)     n_add=$(( n_add + 1 )) ;;
            differs) n_diff=$(( n_diff + 1 )) ;;
            manual)  n_manual=$(( n_manual + 1 )) ;;
        esac
    done

    printf '\n'
    (( n_manual > 0 )) && printf '  %d record(s) need manual cleanup (MANUAL) — not auto-fixable\n' "$n_manual"
    if (( n_diff > 0 && replace == 0 )); then
        printf '  %d record(s) exist but grade badly (DIFFERS) — re-run with --replace to fix\n' "$n_diff"
    fi

    local n_changes=$(( n_add + (replace == 1 ? n_diff : 0) ))
    if (( n_changes == 0 )); then
        printf '  nothing to change — DNS is in sync\n'
        tool_end "ok"
        return 0
    fi

    if (( DRY_RUN == 1 )); then
        printf '  dry-run: would apply %d record change(s)\n' "$n_changes"
        tool_end "ok"
        return 0
    fi

    if ! tool_confirm "apply ${n_changes} DNS record change(s) via ${AUTODNS_URL}?"; then
        printf '  aborted\n'
        tool_end "aborted"
        return 1
    fi

    # Group actionable plan rows per zone, one _stream call per zone.
    printf '\n'
    local failed=0 zone
    local -a zones=()
    mapfile -t zones < <(
        for i in "${!P_STATE[@]}"; do
            case "${P_STATE[$i]}" in add|differs) printf '%s\n' "${P_ZONE[$i]}" ;; esac
        done | sort -u
    )
    for zone in ${zones[@]+"${zones[@]}"}; do
        local vns=""
        local -a idxs=()
        for i in "${!P_STATE[@]}"; do
            [[ "${P_ZONE[$i]}" == "$zone" ]] || continue
            case "${P_STATE[$i]}" in
                add|differs) idxs+=("$i"); vns="${P_VNS[$i]}" ;;
            esac
        done
        if [[ "$vns" == "?" || -z "$vns" ]]; then
            printf '  %serror:%s zone %s: no virtual nameserver known — skipping\n' \
                "$C_RED" "$C_RST" "$zone"
            failed=1
            continue
        fi
        _apply_zone "$zone" "$vns" "$replace" ${idxs[@]+"${idxs[@]}"} || failed=1
    done

    printf '\n'
    sleep 2
    _verify_applied

    if (( failed == 1 )); then
        tool_end "fail"
        return 1
    fi
    tool_end "ok"
}
