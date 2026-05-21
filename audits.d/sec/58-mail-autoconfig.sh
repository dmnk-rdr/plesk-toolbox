# audits.d/sec/58-mail-autoconfig.sh - autoconfig (Thunderbird) + autodiscover (Outlook)
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "security: mail client autoconfig"

: "${MAIL_AUTOCONFIG_MAX_DOMAINS:=50}"
: "${MAIL_AUTOCONFIG_REQUIRE_HOST:=0}"   # 0 = .well-known on the apex domain is acceptable
: "${MAIL_AUTOCONFIG_TIMEOUT:=6}"

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

# Returns the HTTP status code of a HEAD/GET against $1, or "000" on failure.
# Uses GET because some Plesk vhost configs return 405 on HEAD for static XML.
_http_status() {
    curl -s -o /dev/null --max-time "$MAIL_AUTOCONFIG_TIMEOUT" \
        -L -w '%{http_code}' "$1" 2>/dev/null
}

# A 2xx/3xx counts as "endpoint exists"; 401 also counts (Plesk/Exchange-style).
_http_ok() {
    case "$1" in 2??|3??|401) return 0 ;; esac
    return 1
}

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_AUTOCONFIG_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    # ── Autoconfig (Thunderbird/Apple Mail) ──────────────────────────────
    ac_host="autoconfig.${d}"
    ac_url="https://${ac_host}/mail/config-v1.1.xml?emailaddress=user%40${d}"
    wk_url="https://${d}/.well-known/autoconfig/mail/config-v1.1.xml?emailaddress=user%40${d}"

    ac_dns=""
    ac_dns="$(dig +short A "$ac_host" 2>/dev/null | head -n1)"
    [[ -z "$ac_dns" ]] && ac_dns="$(dig +short AAAA "$ac_host" 2>/dev/null | head -n1)"

    if [[ -n "$ac_dns" ]]; then
        code="$(_http_status "$ac_url")"
        if _http_ok "$code"; then
            emit "sec.mail.autoconfig.${d}" "info" "pass" \
                "${d}: autoconfig endpoint OK (HTTP ${code})"
        else
            emit "sec.mail.autoconfig.${d}" "low" "warn" \
                "${d}: autoconfig.${d} resolves but endpoint returns ${code}" \
                "serve ${ac_url}"
        fi
    else
        # Fall back to .well-known on the apex
        code="$(_http_status "$wk_url")"
        if _http_ok "$code"; then
            sev_status="info"; verdict="pass"; fix=""
            if (( MAIL_AUTOCONFIG_REQUIRE_HOST == 1 )); then
                sev_status="low"; verdict="warn"
                fix="add autoconfig.${d} CNAME or A record"
            fi
            emit "sec.mail.autoconfig.${d}" "$sev_status" "$verdict" \
                "${d}: autoconfig via .well-known (HTTP ${code})" "$fix"
        else
            if (( MAIL_AUTOCONFIG_REQUIRE_HOST == 1 )); then
                emit "sec.mail.autoconfig.${d}" "medium" "warn" \
                    "${d}: no autoconfig (no DNS, no .well-known)" \
                    "publish autoconfig.${d} or .well-known/autoconfig on ${d}"
            else
                emit "sec.mail.autoconfig.${d}" "info" "skip" \
                    "${d}: no autoconfig configured (optional)"
            fi
        fi
    fi

    # ── Autodiscover (Outlook/Exchange) ──────────────────────────────────
    ad_host="autodiscover.${d}"
    ad_url="https://${ad_host}/autodiscover/autodiscover.xml"
    srv="$(dig +short SRV "_autodiscover._tcp.${d}" 2>/dev/null | head -n1)"

    ad_dns=""
    ad_dns="$(dig +short A "$ad_host" 2>/dev/null | head -n1)"
    [[ -z "$ad_dns" ]] && ad_dns="$(dig +short AAAA "$ad_host" 2>/dev/null | head -n1)"

    if [[ -n "$ad_dns" ]]; then
        code="$(_http_status "$ad_url")"
        # Autodiscover POST endpoints often return 200/401/405 on GET — accept those.
        case "$code" in
            2??|3??|401|405)
                emit "sec.mail.autodiscover.${d}" "info" "pass" \
                    "${d}: autodiscover endpoint reachable (HTTP ${code})" ;;
            *)
                emit "sec.mail.autodiscover.${d}" "low" "warn" \
                    "${d}: autodiscover.${d} resolves but endpoint returns ${code}" \
                    "serve ${ad_url}" ;;
        esac
    elif [[ -n "$srv" ]]; then
        emit "sec.mail.autodiscover.${d}" "info" "pass" \
            "${d}: autodiscover via SRV (${srv})"
    else
        if (( MAIL_AUTOCONFIG_REQUIRE_HOST == 1 )); then
            emit "sec.mail.autodiscover.${d}" "low" "warn" \
                "${d}: no autodiscover (no host, no SRV)" \
                "publish autodiscover.${d} A/AAAA or _autodiscover._tcp.${d} SRV"
        else
            emit "sec.mail.autodiscover.${d}" "info" "skip" \
                "${d}: no autodiscover configured (optional)"
        fi
    fi
done
