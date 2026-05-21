# tools.d/mail/tail-maillog.sh - tail mail log, optionally filtered by domain
# Usage: plesk-tool mail/tail-maillog [domain]

main() {
    local domain="${1:-}"
    local log=""
    for f in /var/log/mail.log /var/log/maillog /var/log/messages; do
        [[ -r "$f" ]] && { log="$f"; break; }
    done

    if [[ -z "$log" ]]; then
        printf 'no readable mail log found\n' >&2
        return 1
    fi

    section "tail: ${log}${domain:+ (filter: $domain)}"
    if [[ -n "$domain" ]]; then
        # shellcheck disable=SC2016
        tail -F "$log" | grep --line-buffered -iE "${domain}|@${domain}"
    else
        tail -F "$log"
    fi
}
