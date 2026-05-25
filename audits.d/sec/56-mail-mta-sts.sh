# audits.d/sec/56-mail-mta-sts.sh — MTA-STS (RFC 8461) + TLSRPT (RFC 8460)
#
# Table columns:
#   MTA-STS   _mta-sts TXT record + .well-known policy file
#   Policy    parsed policy mode (enforce / testing / none)
#   TLSRPT    _smtp._tls TXT record
#
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "security: MTA-STS / TLSRPT"

: "${MAIL_MTA_STS_MAX_DOMAINS:=50}"
: "${MAIL_MTA_STS_REQUIRED:=0}"
: "${MAIL_TLSRPT_REQUIRED:=0}"
: "${MAIL_DOMAIN_TRUNCATE:=22}"

if ! _plesk_available; then
    emit "sec.mail.mta_sts" "medium" "skip" "plesk CLI not available"
    return 0
fi
if ! command -v dig >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    emit "sec.mail.mta_sts" "medium" "skip" "dig(1) or curl(1) not available"
    return 0
fi
if ! _plesk_mail_in_use; then
    emit "sec.mail.mta_sts" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
(( ${#domains[@]} > 0 )) || { emit "sec.mail.mta_sts" "info" "skip" "no mail-enabled domains"; return 0; }

table_init "Domain" "MTA-STS" "Policy" "TLSRPT"

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_MTA_STS_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    label="$(truncate "$d" "$MAIL_DOMAIN_TRUNCATE")"
    sts_status="info" sts_sev="info" sts_fix=""
    pol_status="info" pol_sev="info" pol_fix=""
    rpt_status="info" rpt_sev="info" rpt_fix=""
    sts_cell="" pol_cell="" rpt_cell=""

    # ── MTA-STS TXT ────────────────────────────────────────────────────────
    sts_txt="$(dig +short TXT "_mta-sts.${d}" 2>/dev/null | tr -d '"' | tr -s ' ')"
    if grep -q 'v=STSv1' <<< "$sts_txt"; then
        sts_status="pass"; sts_cell="$(status_cell pass 'set')"

        # ── Policy file ──
        policy="$(curl -fsSL --max-time 6 \
            "https://mta-sts.${d}/.well-known/mta-sts.txt" 2>/dev/null)"
        if [[ -z "$policy" ]]; then
            pol_status="fail"; pol_sev="medium"
            pol_cell="$(status_cell fail 'no-file')"
            pol_fix="publish https://mta-sts.${d}/.well-known/mta-sts.txt"
        else
            ok=1
            grep -qE '^[[:space:]]*version:[[:space:]]*STSv1[[:space:]]*$' <<< "$policy" || ok=0
            grep -qE '^[[:space:]]*mode:[[:space:]]*(enforce|testing|none)[[:space:]]*$' <<< "$policy" || ok=0
            grep -qE '^[[:space:]]*mx:[[:space:]]*[^[:space:]]' <<< "$policy" || ok=0
            grep -qE '^[[:space:]]*max_age:[[:space:]]*[0-9]+' <<< "$policy" || ok=0
            mode="$(grep -E '^[[:space:]]*mode:' <<< "$policy" \
                    | awk -F: '{gsub(/[ \t]/,"",$2); print $2; exit}')"
            if (( ok == 1 )); then
                case "$mode" in
                    enforce)
                        pol_status="pass"; pol_cell="$(status_cell pass 'enforce')" ;;
                    testing)
                        pol_status="pass"; pol_sev="low"; pol_cell="$(status_cell pass 'testing')" ;;
                    none|*)
                        pol_status="warn"; pol_sev="low"; pol_cell="$(status_cell warn "${mode:-?}")" ;;
                esac
            else
                pol_status="warn"; pol_sev="medium"
                pol_cell="$(status_cell warn 'malformed')"
                pol_fix="mta-sts.txt missing version/mode/mx/max_age"
            fi
        fi
    else
        if (( MAIL_MTA_STS_REQUIRED == 1 )); then
            sts_status="warn"; sts_sev="medium"
            sts_cell="$(status_cell warn 'miss')"
            sts_fix="publish _mta-sts.${d} TXT and policy file"
        else
            sts_status="skip"; sts_cell="$(status_cell skip 'opt')"
        fi
        pol_status="skip"; pol_cell="—"
    fi

    # ── TLSRPT TXT ─────────────────────────────────────────────────────────
    tls_rpt="$(dig +short TXT "_smtp._tls.${d}" 2>/dev/null | tr -d '"' | tr -s ' ')"
    if grep -q 'v=TLSRPTv1' <<< "$tls_rpt"; then
        rpt_status="pass"; rpt_cell="$(status_cell pass 'set')"
    else
        if (( MAIL_TLSRPT_REQUIRED == 1 )); then
            rpt_status="warn"; rpt_sev="medium"
            rpt_cell="$(status_cell warn 'miss')"
            rpt_fix="publish _smtp._tls.${d} TXT: v=TLSRPTv1; rua=mailto:postmaster@${d}"
        else
            rpt_status="skip"; rpt_cell="$(status_cell skip 'opt')"
        fi
    fi

    table_row "$label" "$sts_cell" "$pol_cell" "$rpt_cell"

    row_status="$(worst_status "$sts_status" "$pol_status" "$rpt_status")"
    row_sev="$(worst_severity "$sts_sev" "$pol_sev" "$rpt_sev")"
    fixes=""
    for f in "$sts_fix" "$pol_fix" "$rpt_fix"; do
        [[ -n "$f" ]] || continue
        [[ -n "$fixes" ]] && fixes+=" | "
        fixes+="$f"
    done

    emit "sec.mail.mta_sts.${d}" "$row_sev" "$row_status" \
        "${d}: mta-sts=${sts_status} policy=${pol_status} tlsrpt=${rpt_status}" "$fixes"
done

table_render
