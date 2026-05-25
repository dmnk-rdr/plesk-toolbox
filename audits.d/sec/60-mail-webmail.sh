# audits.d/sec/60-mail-webmail.sh — webmail.<domain> reachability + content
#
# For every Plesk mail-enabled domain, checks the canonical webmail subdomain:
#
#   DNS      A/AAAA for webmail.<d>
#   TLS      cert validates against the system trust store
#   Webmail  recognisable webmail app (Roundcube/Horde) vs. Plesk placeholder
#
# Plesk normally publishes webmail.* as a CNAME to the server during domain
# creation; missing or stale records typically surface after migrations.
#
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "security: mail webmail"

: "${MAIL_WEBMAIL_MAX_DOMAINS:=50}"
: "${MAIL_WEBMAIL_TIMEOUT:=6}"
: "${MAIL_DOMAIN_TRUNCATE:=22}"

if ! _plesk_available; then
    emit "sec.mail.webmail" "medium" "skip" "plesk CLI not available"
    return 0
fi
if ! command -v dig >/dev/null 2>&1 || ! command -v curl >/dev/null 2>&1; then
    emit "sec.mail.webmail" "medium" "skip" "dig(1) or curl(1) not available"
    return 0
fi
if ! _plesk_mail_in_use; then
    emit "sec.mail.webmail" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
(( ${#domains[@]} > 0 )) || { emit "sec.mail.webmail" "info" "skip" "no mail-enabled domains"; return 0; }

# HTTP status with strict TLS — non-zero exit if the cert is rejected.
_http_status_strict() {
    curl -s -o /dev/null --max-time "$MAIL_WEBMAIL_TIMEOUT" \
        -L -w '%{http_code}' "$1" 2>/dev/null
}
# HTTP status with TLS verification disabled — used to tell "no service"
# (connect refused / timeout) apart from "bad cert".
_http_status_insecure() {
    curl -sk -o /dev/null --max-time "$MAIL_WEBMAIL_TIMEOUT" \
        -L -w '%{http_code}' "$1" 2>/dev/null
}
_http_ok() {
    case "$1" in 2??|3??|401) return 0 ;; esac
    return 1
}
# Fetch the first 8 KiB of the rendered page (insecure — content check only).
_fetch_body_snippet() {
    curl -sk -L --max-time "$MAIL_WEBMAIL_TIMEOUT" \
        -A "plesk-toolbox audit (webmail check)" \
        "$1" 2>/dev/null | head -c 8192
}

# Returns: roundcube | horde | sogo | rainloop | snappymail | afterlogic | plesk-default | unknown
_classify_webmail_body() {
    local body="$1"
    if [[ "$body" == *"Roundcube"* || "$body" == *"roundcube"* ]]; then
        printf 'roundcube'; return
    fi
    if [[ "$body" == *"Horde"* || "$body" == *"horde"* ]]; then
        printf 'horde'; return
    fi
    if [[ "$body" == *"SOGo"* || "$body" == *"sg-default"* ]]; then
        printf 'sogo'; return
    fi
    if [[ "$body" == *"RainLoop"* || "$body" == *"rainloop"* ]]; then
        printf 'rainloop'; return
    fi
    if [[ "$body" == *"SnappyMail"* || "$body" == *"snappymail"* ]]; then
        printf 'snappymail'; return
    fi
    if [[ "$body" == *"AfterLogic"* || "$body" == *"afterlogic"* ]]; then
        printf 'afterlogic'; return
    fi
    if [[ "$body" == *"Web Server's Default Page"* \
        || "$body" == *"<title>Domain Default page</title>"* \
        || "$body" == *"default-website-content"* \
        || "$body" == *"default-server-index"* ]]; then
        printf 'plesk-default'; return
    fi
    printf 'unknown'
}

table_init "Domain" "DNS" "TLS" "Webmail"

checked=0
for d in "${domains[@]}"; do
    (( checked >= MAIL_WEBMAIL_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    label="$(truncate "$d" "$MAIL_DOMAIN_TRUNCATE")"
    host="webmail.${d}"
    url="https://${host}/"

    dns_status="info" dns_cell="" dns_sev="info"
    tls_status="info" tls_cell="" tls_sev="info"
    wm_status="info"  wm_cell=""  wm_sev="info"
    fix=""

    # ── DNS ─────────────────────────────────────────────────────────────────
    addr="$(dig +short A "$host" 2>/dev/null | head -n1)"
    [[ -z "$addr" ]] && addr="$(dig +short AAAA "$host" 2>/dev/null | head -n1)"

    if [[ -z "$addr" ]]; then
        dns_status="warn"; dns_sev="medium"
        dns_cell="$(status_cell warn 'miss')"
        tls_cell="$(status_cell skip 'n/a')"
        wm_cell="$(status_cell skip 'n/a')"
        fix="publish ${host} A/AAAA (Plesk → Domains → ${d} → DNS Settings)"
        table_row "$label" "$dns_cell" "$tls_cell" "$wm_cell"
        emit "sec.mail.webmail.${d}" "$dns_sev" "$dns_status" \
            "${d}: webmail not reachable (no DNS)" "$fix"
        continue
    fi
    dns_cell="$(status_cell pass 'A')"

    # ── TLS (strict) ────────────────────────────────────────────────────────
    code_strict="$(_http_status_strict "$url")"
    if _http_ok "$code_strict"; then
        tls_status="pass"; tls_cell="$(status_cell pass 'valid')"
    else
        code_insecure="$(_http_status_insecure "$url")"
        if _http_ok "$code_insecure"; then
            tls_status="warn"; tls_sev="medium"
            tls_cell="$(status_cell warn 'self')"
            fix="${host}: TLS certificate not trusted — reissue (Plesk → SSL/TLS Certificates)"
        else
            tls_status="fail"; tls_sev="high"
            tls_cell="$(status_cell fail 'no-resp')"
            wm_cell="$(status_cell skip 'n/a')"
            fix="${host}: HTTPS not responding (port 443 closed or service down)"
            table_row "$label" "$dns_cell" "$tls_cell" "$wm_cell"
            emit "sec.mail.webmail.${d}" "$tls_sev" "$tls_status" \
                "${d}: webmail HTTPS unreachable" "$fix"
            continue
        fi
    fi

    # ── Webmail content (always via insecure fetch so self-signed still works) ─
    kind="$(_classify_webmail_body "$(_fetch_body_snippet "$url")")"
    case "$kind" in
        roundcube)     wm_status="pass"; wm_cell="$(status_cell pass 'roundcube')" ;;
        horde)         wm_status="pass"; wm_cell="$(status_cell pass 'horde')" ;;
        sogo)          wm_status="pass"; wm_cell="$(status_cell pass 'sogo')" ;;
        rainloop)      wm_status="pass"; wm_cell="$(status_cell pass 'rainloop')" ;;
        snappymail)    wm_status="pass"; wm_cell="$(status_cell pass 'snappymail')" ;;
        afterlogic)    wm_status="pass"; wm_cell="$(status_cell pass 'afterlogic')" ;;
        plesk-default) wm_status="warn"; wm_sev="medium"
                       wm_cell="$(status_cell warn 'default')"
                       fix2="${host}: serves Plesk default page — enable webmail (Plesk → ${d} → Mail Settings → Webmail)"
                       [[ -n "$fix" ]] && fix="${fix} | ${fix2}" || fix="$fix2" ;;
        *)             wm_status="warn"; wm_sev="low"
                       wm_cell="$(status_cell warn '?')"
                       fix2="${host}: unknown content (not Roundcube/Horde) — verify webmail is configured"
                       [[ -n "$fix" ]] && fix="${fix} | ${fix2}" || fix="$fix2" ;;
    esac

    table_row "$label" "$dns_cell" "$tls_cell" "$wm_cell"

    row_status="$(worst_status "$dns_status" "$tls_status" "$wm_status")"
    row_sev="$(worst_severity "$dns_sev" "$tls_sev" "$wm_sev")"
    emit "sec.mail.webmail.${d}" "$row_sev" "$row_status" \
        "${d}: dns=${dns_status} tls=${tls_status} webmail=${wm_status}" "$fix"
done

table_render
