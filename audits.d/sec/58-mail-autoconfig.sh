# audits.d/sec/58-mail-autoconfig.sh — autoconfig (Thunderbird) + autodiscover (Outlook)
#
# Table columns:
#   Autoconfig    Thunderbird/Apple Mail config endpoint
#                 ("autoconfig.<d>" host, or .well-known on the apex)
#   Autodiscover  Outlook/Exchange endpoint
#                 ("autodiscover.<d>" host, or _autodiscover._tcp SRV)
#
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "security: mail client autoconfig"

: "${MAIL_AUTOCONFIG_MAX_DOMAINS:=50}"
: "${MAIL_AUTOCONFIG_REQUIRE_HOST:=0}"
: "${MAIL_AUTOCONFIG_TIMEOUT:=6}"
: "${MAIL_DOMAIN_TRUNCATE:=22}"

if ! _plesk_available; then
    emit "sec.mail.autoconfig" "medium" "skip" "plesk CLI not available"
    return 0
fi
if ! command -v dig >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    emit "sec.mail.autoconfig" "medium" "skip" "dig(1) or curl(1) not available"
    return 0
fi
if ! _plesk_mail_in_use; then
    emit "sec.mail.autoconfig" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
(( ${#domains[@]} > 0 )) || { emit "sec.mail.autoconfig" "info" "skip" "no mail-enabled domains"; return 0; }

_http_status() {
    curl -s -o /dev/null --max-time "$MAIL_AUTOCONFIG_TIMEOUT" \
        -L -w '%{http_code}' "$1" 2>/dev/null
}
_http_ok() {
    case "$1" in 2??|3??|401) return 0 ;; esac
    return 1
}

table_init "Domain" "Autoconfig" "Autodiscover"

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_AUTOCONFIG_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    label="$(truncate "$d" "$MAIL_DOMAIN_TRUNCATE")"
    ac_status="info" ac_sev="info" ac_cell="" ac_fix=""
    ad_status="info" ad_sev="info" ad_cell="" ad_fix=""

    # ── Autoconfig (Thunderbird / Apple Mail) ──────────────────────────────
    ac_host="autoconfig.${d}"
    ac_url="https://${ac_host}/mail/config-v1.1.xml?emailaddress=user%40${d}"
    wk_url="https://${d}/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=user%40${d}"

    ac_dns="$(dig +short A "$ac_host" 2>/dev/null | head -n1)"
    [[ -z "$ac_dns" ]] && ac_dns="$(dig +short AAAA "$ac_host" 2>/dev/null | head -n1)"

    if [[ -n "$ac_dns" ]]; then
        code="$(_http_status "$ac_url")"
        if _http_ok "$code"; then
            ac_status="pass"; ac_cell="$(status_cell pass "host ${code}")"
        else
            ac_status="warn"; ac_sev="low"
            ac_cell="$(status_cell warn "HTTP ${code}")"
            ac_fix="${ac_host} resolves but ${ac_url} returns ${code}"
        fi
    else
        code="$(_http_status "$wk_url")"
        if _http_ok "$code"; then
            if (( MAIL_AUTOCONFIG_REQUIRE_HOST == 1 )); then
                ac_status="warn"; ac_sev="low"
                ac_cell="$(status_cell warn '.well-known')"
                ac_fix="add ${ac_host} CNAME or A record"
            else
                ac_status="pass"; ac_cell="$(status_cell pass '.well-known')"
            fi
        else
            if (( MAIL_AUTOCONFIG_REQUIRE_HOST == 1 )); then
                ac_status="warn"; ac_sev="medium"
                ac_cell="$(status_cell warn 'miss')"
                ac_fix="publish ${ac_host} or .well-known/autoconfig on ${d}"
            else
                ac_status="skip"; ac_cell="$(status_cell skip 'opt')"
            fi
        fi
    fi

    # ── Autodiscover (Outlook / Exchange) ──────────────────────────────────
    ad_host="autodiscover.${d}"
    ad_url="https://${ad_host}/autodiscover/autodiscover.xml"
    srv="$(dig +short SRV "_autodiscover._tcp.${d}" 2>/dev/null | head -n1)"

    ad_dns="$(dig +short A "$ad_host" 2>/dev/null | head -n1)"
    [[ -z "$ad_dns" ]] && ad_dns="$(dig +short AAAA "$ad_host" 2>/dev/null | head -n1)"

    if [[ -n "$ad_dns" ]]; then
        code="$(_http_status "$ad_url")"
        case "$code" in
            2??|3??|401|405)
                ad_status="pass"; ad_cell="$(status_cell pass "host ${code}")" ;;
            *)
                ad_status="warn"; ad_sev="low"
                ad_cell="$(status_cell warn "HTTP ${code}")"
                ad_fix="${ad_host} resolves but ${ad_url} returns ${code}" ;;
        esac
    elif [[ -n "$srv" ]]; then
        ad_status="pass"; ad_cell="$(status_cell pass 'SRV')"
    else
        if (( MAIL_AUTOCONFIG_REQUIRE_HOST == 1 )); then
            ad_status="warn"; ad_sev="low"
            ad_cell="$(status_cell warn 'miss')"
            ad_fix="publish ${ad_host} A/AAAA or _autodiscover._tcp.${d} SRV"
        else
            ad_status="skip"; ad_cell="$(status_cell skip 'opt')"
        fi
    fi

    table_row "$label" "$ac_cell" "$ad_cell"

    row_status="$(worst_status "$ac_status" "$ad_status")"
    row_sev="$(worst_severity "$ac_sev" "$ad_sev")"
    fixes=""
    for f in "$ac_fix" "$ad_fix"; do
        [[ -n "$f" ]] || continue
        [[ -n "$fixes" ]] && fixes+=" | "
        fixes+="$f"
    done

    emit "sec.mail.autoconfig.${d}" "$row_sev" "$row_status" \
        "${d}: autoconfig=${ac_status} autodiscover=${ad_status}" "$fixes"
done

table_render
