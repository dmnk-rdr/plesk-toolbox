# tools.d/domain/reissue-cert.sh - reissue a Let's Encrypt cert for one domain
# Usage: plesk-tool domain/reissue-cert example.com [--with-www]

main() {
    local domain="${1:?usage: plesk-tool domain/reissue-cert <domain> [--with-www]}"
    shift || true

    local with_www=0
    for a in "$@"; do
        case "$a" in --with-www) with_www=1 ;; esac
    done

    tool_begin "domain.reissue_cert:${domain}" "reissue LE cert for ${domain}" || return 1

    if ! command -v plesk >/dev/null 2>&1; then
        printf '  skip: plesk CLI not found\n'
        tool_end "skip"
        return 0
    fi

    if ! tool_confirm "reissue certificate for ${domain}?"; then
        printf '  aborted\n'
        tool_end "aborted"
        return 1
    fi

    if (( with_www )); then
        tool_run plesk ext letsencrypt --exec letsencrypt cli.php \
            --domain "$domain" --domain "www.$domain" -m "admin@${domain}"
    else
        tool_run plesk ext letsencrypt --exec letsencrypt cli.php \
            --domain "$domain" -m "admin@${domain}"
    fi

    tool_end "ok"
}
