# tools.d/fix/letsencrypt-renew-all.sh - trigger LE cert renewal on all domains
# Uses Plesk's extension command; falls back to certbot if present.

main() {
    tool_begin "fix.web.letsencrypt_renew_all" "renew all Let's Encrypt certificates" || return 1

    if command -v plesk >/dev/null 2>&1 && plesk bin extension --list 2>/dev/null | grep -q letsencrypt; then
        if ! tool_confirm "run 'plesk ext letsencrypt --renew-all'?"; then
            printf '  aborted\n'
            tool_end "aborted"
            return 1
        fi
        tool_run plesk ext letsencrypt --renew-all
        tool_end "ok"
        return 0
    fi

    if command -v certbot >/dev/null 2>&1; then
        if ! tool_confirm "run 'certbot renew'?"; then
            printf '  aborted\n'
            tool_end "aborted"
            return 1
        fi
        tool_run certbot renew
        tool_end "ok"
        return 0
    fi

    printf '  skip: neither Plesk LE extension nor certbot found\n'
    tool_end "skip"
}
