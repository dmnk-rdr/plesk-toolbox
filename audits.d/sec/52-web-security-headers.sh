# audits.d/sec/52-web-security-headers.sh — per-domain HTTP response headers
#
# For every Plesk-hosted domain reachable on 443, fetches the response headers
# and grades the 9 OWASP-relevant security headers:
#
#   HSTS  Strict-Transport-Security        (max-age >= 6mo, includeSubDomains preferred)
#   XFO   X-Frame-Options                  (DENY / SAMEORIGIN; superseded by CSP frame-ancestors but still widely required)
#   XCTO  X-Content-Type-Options           (nosniff)
#   CSP   Content-Security-Policy          (present; we don't grade the policy itself)
#   RP    Referrer-Policy                  (any value that isn't 'unsafe-url' / missing)
#   PP    Permissions-Policy               (present)
#   COOP  Cross-Origin-Opener-Policy       (same-origin / same-origin-allow-popups)
#   COEP  Cross-Origin-Embedder-Policy     (require-corp / credentialless)
#   CORP  Cross-Origin-Resource-Policy     (same-origin / same-site)
#
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "security: web response headers"

: "${WEB_HEADERS_MAX_DOMAINS:=25}"
: "${WEB_HEADERS_TIMEOUT:=6}"
: "${WEB_HEADERS_HSTS_MIN_DAYS:=180}"        # warn under 6 months; the
                                              # RFC 6797 author guidance is ≥1y
: "${WEB_DOMAIN_TRUNCATE:=22}"
: "${WEB_HEADERS_SKIP_DEFAULT_PAGE:=1}"       # skip domains serving the Plesk
                                              # "Domain Default page" placeholder

if ! _plesk_available; then
    emit "sec.web.headers" "medium" "skip" "plesk CLI not available"
    return 0
fi

if ! command -v curl >/dev/null 2>&1; then
    emit "sec.web.headers" "medium" "skip" "curl(1) not available"
    return 0
fi

mapfile -t domains < <(_plesk_domains 2>/dev/null || true)
if (( ${#domains[@]} == 0 )); then
    emit "sec.web.headers" "info" "skip" "no hosted domains"
    return 0
fi

# Fetch headers as a single blob: <header>: <value>\n
_fetch_headers() {
    curl -sI -L --max-time "$WEB_HEADERS_TIMEOUT" \
        --connect-timeout "$WEB_HEADERS_TIMEOUT" \
        -A "plesk-toolbox audit (header check)" \
        "https://$1/" 2>/dev/null \
        | tr -d '\r' \
        | awk 'BEGIN{IGNORECASE=1} /^[A-Za-z-]+:/ { print tolower($0) }'
}

# Fetch the first 8 KiB of the rendered page — enough to spot Plesk's
# placeholder without pulling full pages.
_fetch_body_snippet() {
    curl -s -L --max-time "$WEB_HEADERS_TIMEOUT" \
        --connect-timeout "$WEB_HEADERS_TIMEOUT" \
        -A "plesk-toolbox audit (content check)" \
        "https://$1/" 2>/dev/null | head -c 8192
}

# Plesk's "Domain Default page" placeholder — no real site behind the vhost.
_is_plesk_default_page() {
    local body="$1"
    [[ "$body" == *"<title>Domain Default page</title>"* ]] && return 0
    [[ "$body" == *"default-website-content"* ]] && return 0
    return 1
}

# _hdr <blob> <header-name-lowercase> → value, or empty
_hdr() {
    awk -v k="$2:" 'BEGIN{IGNORECASE=1} index($0, k)==1 { sub(/^[^:]*: */, ""); print; exit }' <<< "$1"
}

# HSTS grade: pass (>=min days), warn (<min), fail (missing).
# Sets H_HSTS_STATUS and H_HSTS_CELL.
_grade_hsts() {
    local v="$1"
    if [[ -z "$v" ]]; then
        H_HSTS_STATUS="fail"
        H_HSTS_CELL="$(status_cell fail 'miss')"
        H_HSTS_FIX="add header: Strict-Transport-Security: max-age=31536000; includeSubDomains"
        return
    fi
    local ma days short
    ma="$(grep -oE 'max-age=[0-9]+' <<< "$v" | head -n1 | cut -d= -f2)"
    days=$(( ${ma:-0} / 86400 ))
    if (( days >= 365 )); then short="1y+"
    elif (( days >= 30 )); then short="${days}d"
    else short="${days}d"
    fi
    if (( days >= WEB_HEADERS_HSTS_MIN_DAYS )); then
        H_HSTS_STATUS="pass"
        H_HSTS_CELL="$(status_cell pass "$short")"
    elif (( days >= 7 )); then
        H_HSTS_STATUS="warn"
        H_HSTS_CELL="$(status_cell warn "$short")"
        H_HSTS_FIX="raise max-age to at least ${WEB_HEADERS_HSTS_MIN_DAYS}d (15552000)"
    else
        H_HSTS_STATUS="warn"
        H_HSTS_CELL="$(status_cell warn 'low')"
        H_HSTS_FIX="HSTS max-age too low (${days}d) — set 31536000"
    fi
}

# X-Frame-Options grade — accepts DENY/SAMEORIGIN. Missing is warn (CSP
# frame-ancestors may cover it; we can't see that from headers cheaply).
_grade_xfo() {
    local v="${1,,}"
    case "$v" in
        deny)        H_XFO_STATUS="pass"; H_XFO_CELL="$(status_cell pass 'DENY')" ;;
        sameorigin)  H_XFO_STATUS="pass"; H_XFO_CELL="$(status_cell pass 'SAME')" ;;
        "")          H_XFO_STATUS="warn"; H_XFO_CELL="$(status_cell warn 'miss')"
                     H_XFO_FIX="add header: X-Frame-Options: SAMEORIGIN" ;;
        *)           H_XFO_STATUS="warn"; H_XFO_CELL="$(status_cell warn '?')"
                     H_XFO_FIX="X-Frame-Options has unexpected value: ${v}" ;;
    esac
}

_grade_xcto() {
    local v="${1,,}"
    if [[ "$v" == "nosniff" ]]; then
        H_XCTO_STATUS="pass"; H_XCTO_CELL="$(status_cell pass 'set')"
    elif [[ -z "$v" ]]; then
        H_XCTO_STATUS="warn"; H_XCTO_CELL="$(status_cell warn 'miss')"
        H_XCTO_FIX="add header: X-Content-Type-Options: nosniff"
    else
        H_XCTO_STATUS="warn"; H_XCTO_CELL="$(status_cell warn '?')"
    fi
}

_grade_csp() {
    local v="$1"
    if [[ -n "$v" ]]; then
        H_CSP_STATUS="pass"; H_CSP_CELL="$(status_cell pass 'set')"
    else
        H_CSP_STATUS="warn"; H_CSP_CELL="$(status_cell warn 'miss')"
        H_CSP_FIX="add a Content-Security-Policy header"
    fi
}

_grade_rp() {
    local v="${1,,}"
    if [[ -z "$v" ]]; then
        H_RP_STATUS="warn"; H_RP_CELL="$(status_cell warn 'miss')"
        H_RP_FIX="add header: Referrer-Policy: strict-origin-when-cross-origin"
    elif [[ "$v" == "unsafe-url" ]]; then
        H_RP_STATUS="warn"; H_RP_CELL="$(status_cell warn 'unsa')"
        H_RP_FIX="Referrer-Policy=unsafe-url leaks the full URL on cross-origin requests"
    else
        H_RP_STATUS="pass"; H_RP_CELL="$(status_cell pass 'set')"
    fi
}

_grade_pp() {
    local v="$1"
    if [[ -n "$v" ]]; then
        H_PP_STATUS="pass"; H_PP_CELL="$(status_cell pass 'set')"
    else
        H_PP_STATUS="warn"; H_PP_CELL="$(status_cell warn 'miss')"
        H_PP_FIX="add a Permissions-Policy header (deny unused features)"
    fi
}

_grade_coop() {
    local v="${1,,}"
    case "$v" in
        same-origin|same-origin-allow-popups)
            H_COOP_STATUS="pass"; H_COOP_CELL="$(status_cell pass 'set')" ;;
        "")
            H_COOP_STATUS="warn"; H_COOP_CELL="$(status_cell warn 'miss')"
            H_COOP_FIX="add header: Cross-Origin-Opener-Policy: same-origin" ;;
        *)
            H_COOP_STATUS="warn"; H_COOP_CELL="$(status_cell warn 'weak')" ;;
    esac
}

_grade_coep() {
    local v="${1,,}"
    case "$v" in
        require-corp|credentialless)
            H_COEP_STATUS="pass"; H_COEP_CELL="$(status_cell pass 'set')" ;;
        "")
            H_COEP_STATUS="warn"; H_COEP_CELL="$(status_cell warn 'miss')"
            H_COEP_FIX="add header: Cross-Origin-Embedder-Policy: require-corp (only if app supports it)" ;;
        *)
            H_COEP_STATUS="warn"; H_COEP_CELL="$(status_cell warn 'weak')" ;;
    esac
}

_grade_corp() {
    local v="${1,,}"
    case "$v" in
        same-origin|same-site)
            H_CORP_STATUS="pass"; H_CORP_CELL="$(status_cell pass 'set')" ;;
        cross-origin)
            H_CORP_STATUS="warn"; H_CORP_CELL="$(status_cell warn 'cross')" ;;
        "")
            H_CORP_STATUS="warn"; H_CORP_CELL="$(status_cell warn 'miss')"
            H_CORP_FIX="add header: Cross-Origin-Resource-Policy: same-origin" ;;
        *)
            H_CORP_STATUS="warn"; H_CORP_CELL="$(status_cell warn '?')" ;;
    esac
}

# Service-subdomain prefixes — these endpoints serve fixed XML/text payloads,
# not user-visible websites, so security-header expectations don't apply.
: "${WEB_HEADERS_SKIP_PREFIXES:=autodiscover. autoconfig. mta-sts. _dmarc.}"

_skip_service_subdomain() {
    local d="$1" prefix
    for prefix in $WEB_HEADERS_SKIP_PREFIXES; do
        [[ "$d" == "$prefix"* ]] && return 0
    done
    return 1
}

table_init "Domain" "HSTS" "XFO" "XCTO" "CSP" "RP" "PP" "COOP" "COEP" "CORP"

checked=0
for d in "${domains[@]}"; do
    (( checked >= WEB_HEADERS_MAX_DOMAINS )) && break

    # Filter out Plesk-generated service subdomains (autodiscover, autoconfig,
    # mta-sts) — those serve fixed payloads, not browser-facing sites.
    _skip_service_subdomain "$d" && continue

    # Skip domains not listening on 443 — these would just clutter the table.
    if ! timeout 3 bash -c ">/dev/tcp/${d}/443" 2>/dev/null; then
        continue
    fi
    checked=$((checked + 1))
    label="$(truncate "$d" "$WEB_DOMAIN_TRUNCATE")"

    blob="$(_fetch_headers "$d")"
    if [[ -z "$blob" ]]; then
        table_row "$label" \
            "$(status_cell skip 'no-resp')" "" "" "" "" "" "" "" ""
        emit "sec.web.headers.${d}" "low" "skip" "${d}: no HTTPS response"
        continue
    fi

    if (( WEB_HEADERS_SKIP_DEFAULT_PAGE == 1 )); then
        if _is_plesk_default_page "$(_fetch_body_snippet "$d")"; then
            table_row "$label" \
                "$(status_cell skip 'default')" "" "" "" "" "" "" "" ""
            emit "sec.web.headers.${d}" "info" "skip" \
                "${d}: Plesk default page (no website published)"
            continue
        fi
    fi

    H_HSTS_FIX="" H_XFO_FIX="" H_XCTO_FIX="" H_CSP_FIX=""
    H_RP_FIX=""   H_PP_FIX=""  H_COOP_FIX="" H_COEP_FIX="" H_CORP_FIX=""

    _grade_hsts "$(_hdr "$blob" 'strict-transport-security')"
    _grade_xfo  "$(_hdr "$blob" 'x-frame-options')"
    _grade_xcto "$(_hdr "$blob" 'x-content-type-options')"
    _grade_csp  "$(_hdr "$blob" 'content-security-policy')"
    _grade_rp   "$(_hdr "$blob" 'referrer-policy')"
    _grade_pp   "$(_hdr "$blob" 'permissions-policy')"
    _grade_coop "$(_hdr "$blob" 'cross-origin-opener-policy')"
    _grade_coep "$(_hdr "$blob" 'cross-origin-embedder-policy')"
    _grade_corp "$(_hdr "$blob" 'cross-origin-resource-policy')"

    table_row "$label" \
        "$H_HSTS_CELL" "$H_XFO_CELL"  "$H_XCTO_CELL" "$H_CSP_CELL" \
        "$H_RP_CELL"   "$H_PP_CELL"   "$H_COOP_CELL" "$H_COEP_CELL" "$H_CORP_CELL"

    row_status="$(worst_status "$H_HSTS_STATUS" "$H_XFO_STATUS" "$H_XCTO_STATUS" \
                               "$H_CSP_STATUS" "$H_RP_STATUS" "$H_PP_STATUS" \
                               "$H_COOP_STATUS" "$H_COEP_STATUS" "$H_CORP_STATUS")"

    # Map status → severity: missing CSP/HSTS = medium, missing XCTO/XFO = low,
    # cross-origin trio (COOP/COEP/CORP) = low (often impractical to enable).
    row_sev="low"
    [[ "$H_HSTS_STATUS" == "fail" || "$H_CSP_STATUS" == "warn" ]] && row_sev="medium"

    # Build a fix-hint blob (only non-empty fixes, comma-separated)
    fixes=""
    for f in "$H_HSTS_FIX" "$H_XFO_FIX" "$H_XCTO_FIX" "$H_CSP_FIX" \
             "$H_RP_FIX" "$H_PP_FIX" "$H_COOP_FIX" "$H_COEP_FIX" "$H_CORP_FIX"; do
        [[ -n "$f" ]] || continue
        [[ -n "$fixes" ]] && fixes+="; "
        fixes+="$f"
    done

    emit "sec.web.headers.${d}" "$row_sev" "$row_status" \
        "${d}: response headers" "$fixes"
done

if (( checked == 0 )); then
    emit "sec.web.headers" "info" "skip" "no domains reachable on 443"
fi

table_render
