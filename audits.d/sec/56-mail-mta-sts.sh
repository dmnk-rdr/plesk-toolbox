# audits.d/sec/56-mail-mta-sts.sh - MTA-STS (RFC 8461) + TLSRPT (RFC 8460)
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "security: MTA-STS / TLSRPT"

: "${MAIL_MTA_STS_MAX_DOMAINS:=50}"
: "${MAIL_MTA_STS_REQUIRED:=0}"   # 1 = absent records become warn; 0 = info
: "${MAIL_TLSRPT_REQUIRED:=0}"

# Severity for "absent" cases — depends on whether ops considers STS mandatory.
_absent_sev() { (( MAIL_MTA_STS_REQUIRED == 1 )) && printf 'medium' || printf 'info'; }
_absent_st()  { (( MAIL_MTA_STS_REQUIRED == 1 )) && printf 'warn'   || printf 'pass'; }
_tlsrpt_sev() { (( MAIL_TLSRPT_REQUIRED  == 1 )) && printf 'medium' || printf 'info'; }
_tlsrpt_st()  { (( MAIL_TLSRPT_REQUIRED  == 1 )) && printf 'warn'   || printf 'pass'; }

if ! _plesk_available; then
    emit "sec.mail.mta_sts" "medium" "skip" "plesk CLI not available"
    return 0
fi

if ! command -v dig >/dev/null 2>&1; then
    emit "sec.mail.mta_sts" "medium" "skip" "dig(1) not available"
    return 0
fi

if ! command -v curl >/dev/null 2>&1; then
    emit "sec.mail.mta_sts" "medium" "skip" "curl(1) not available"
    return 0
fi

if ! _plesk_mail_in_use; then
    emit "sec.mail.mta_sts" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
(( ${#domains[@]} > 0 )) || { emit "sec.mail.mta_sts" "info" "skip" "no mail-enabled domains"; return 0; }

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_MTA_STS_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    # ── MTA-STS TXT record ────────────────────────────────────────────────
    sts_txt="$(dig +short TXT "_mta-sts.${d}" 2>/dev/null | tr -d '"' | tr -s ' ')"
    if grep -q 'v=STSv1' <<< "$sts_txt"; then
        emit "sec.mail.mta_sts.${d}.txt" "info" "pass" "${d}: _mta-sts TXT present"

        # ── Policy file fetch ──
        policy="$(curl -fsSL --max-time 6 \
            "https://mta-sts.${d}/.well-known/mta-sts.txt" 2>/dev/null)"
        if [[ -z "$policy" ]]; then
            emit "sec.mail.mta_sts.${d}.policy" "medium" "fail" \
                "${d}: TXT advertises STS but policy file unreachable" \
                "publish https://mta-sts.${d}/.well-known/mta-sts.txt"
        else
            ok=1
            grep -qE '^[[:space:]]*version:[[:space:]]*STSv1[[:space:]]*$' \
                <<< "$policy" || ok=0
            grep -qE '^[[:space:]]*mode:[[:space:]]*(enforce|testing|none)[[:space:]]*$' \
                <<< "$policy" || ok=0
            grep -qE '^[[:space:]]*mx:[[:space:]]*[^[:space:]]' <<< "$policy" || ok=0
            grep -qE '^[[:space:]]*max_age:[[:space:]]*[0-9]+' <<< "$policy" || ok=0

            mode="$(grep -E '^[[:space:]]*mode:' <<< "$policy" \
                    | awk -F: '{gsub(/[ \t]/,"",$2); print $2; exit}')"
            if (( ok == 1 )); then
                if [[ "$mode" == "enforce" ]]; then
                    emit "sec.mail.mta_sts.${d}.policy" "info" "pass" \
                        "${d}: STS policy valid (mode=enforce)"
                else
                    emit "sec.mail.mta_sts.${d}.policy" "low" "pass" \
                        "${d}: STS policy valid (mode=${mode:-?})"
                fi
            else
                emit "sec.mail.mta_sts.${d}.policy" "medium" "warn" \
                    "${d}: STS policy malformed" \
                    "fix mta-sts.txt: need version/mode/mx/max_age"
            fi
        fi
    else
        emit "sec.mail.mta_sts.${d}.txt" "$(_absent_sev)" "$(_absent_st)" \
            "${d}: no MTA-STS record" \
            "publish _mta-sts.${d} TXT 'v=STSv1; id=$(date +%Y%m%d)01' + policy file"
    fi

    # ── TLSRPT TXT record ────────────────────────────────────────────────
    tls_rpt="$(dig +short TXT "_smtp._tls.${d}" 2>/dev/null | tr -d '"' | tr -s ' ')"
    if grep -q 'v=TLSRPTv1' <<< "$tls_rpt"; then
        emit "sec.mail.tlsrpt.${d}" "info" "pass" "${d}: TLSRPT present"
    else
        emit "sec.mail.tlsrpt.${d}" "$(_tlsrpt_sev)" "$(_tlsrpt_st)" \
            "${d}: no TLSRPT record" \
            "publish _smtp._tls.${d} TXT 'v=TLSRPTv1; rua=mailto:postmaster@${d}'"
    fi
done
