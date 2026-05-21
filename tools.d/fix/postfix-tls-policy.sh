# tools.d/fix/postfix-tls-policy.sh - enforce sane Postfix TLS policy
# Sets smtpd_tls_security_level=may, smtp_tls_security_level=may, disables SSLv3/TLSv1/TLSv1.1.

main() {
    tool_begin "fix.mail.postfix_tls_policy" "enforce Postfix TLS baseline" || return 1

    if ! command -v postconf >/dev/null 2>&1; then
        printf '  skip: postfix not installed\n'
        tool_end "skip"
        return 0
    fi

    # Show current
    printf '  current:\n'
    postconf smtpd_tls_security_level smtp_tls_security_level \
        smtpd_tls_protocols smtp_tls_protocols 2>/dev/null | sed 's/^/    /'

    if ! tool_confirm "apply TLS baseline and reload postfix?"; then
        printf '  aborted\n'
        tool_end "aborted"
        return 1
    fi

    tool_run postconf -e smtpd_tls_security_level=may
    tool_run postconf -e smtp_tls_security_level=may
    tool_run postconf -e 'smtpd_tls_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1'
    tool_run postconf -e 'smtp_tls_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1'
    tool_run postconf -e 'smtpd_tls_mandatory_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1'
    tool_run postconf -e 'smtp_tls_mandatory_protocols=!SSLv2,!SSLv3,!TLSv1,!TLSv1.1'
    tool_run systemctl reload postfix

    tool_end "ok"
}
