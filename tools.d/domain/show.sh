# tools.d/domain/show.sh - dump everything interesting about a hosted domain
# Usage: plesk-tool domain/show example.com
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

main() {
    local d="${1:?usage: plesk-tool domain/show <domain>}"

    if ! _plesk_available; then
        printf 'plesk CLI not available\n' >&2
        return 1
    fi

    section "domain: ${d}"

    # Basic info from plesk
    local info
    info="$(plesk bin domain --info "$d" 2>/dev/null)"
    if [[ -z "$info" ]]; then
        printf '  not a Plesk-managed domain\n' >&2
        return 1
    fi

    # Hosting
    label_line "hosting type" "$(awk -F: '/Hosting type/ {sub(/^ /,"",$2); print $2}' <<< "$info")"
    label_line "doc root"     "$(awk -F: '/Document root/ {sub(/^ /,"",$2); print $2}' <<< "$info")"
    label_line "php handler"  "$(plesk bin site --info "$d" 2>/dev/null | awk -F: '/PHP handler/ {sub(/^ /,"",$2); print $2}')"
    label_line "ssl"          "$(awk -F: '/SSL support/ {sub(/^ /,"",$2); print $2}' <<< "$info")"
    label_line "creation"     "$(awk -F: '/Creation date/ {sub(/^ /,"",$2); print $2}' <<< "$info")"

    # Disk usage
    local root size
    root="$(_plesk_vhost_conf_dir "$d")"
    root="${root%/conf}"
    if [[ -d "$root" ]]; then
        size="$(du -sh "$root" 2>/dev/null | awk '{print $1}')"
        label_line "disk usage" "$size  ($root)"
    fi

    # Cert
    if timeout 3 bash -c ">/dev/tcp/${d}/443" 2>/dev/null; then
        local days
        # shellcheck source=../../lib/tls.sh
        . "${PTBOX_ROOT}/lib/tls.sh"
        days="$(_tls_cert_days "$d" 443 2>/dev/null || echo -1)"
        if (( days >= 0 )); then
            label_line "cert expires" "${days}d"
        fi
    fi

    # DNS snapshot
    if command -v dig >/dev/null 2>&1; then
        section "DNS for ${d}"
        for type in A AAAA MX TXT; do
            local r
            r="$(dig +short "$type" "$d" 2>/dev/null | paste -sd' ' -)"
            label_line "$type" "${r:-<none>}"
        done
        label_line "SPF"   "$(dig +short TXT "$d" 2>/dev/null | grep -o 'v=spf1[^"]*' || echo '<none>')"
        label_line "DMARC" "$(dig +short TXT "_dmarc.$d" 2>/dev/null | grep -o 'v=DMARC1[^"]*' || echo '<none>')"
    fi
}
