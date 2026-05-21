# tools.d/mail/spam-top-senders.sh - top 20 sending addresses from the mail log
# Quick forensic: who is sending the most mail right now.

main() {
    local log=""
    for f in /var/log/mail.log /var/log/maillog; do
        [[ -r "$f" ]] && { log="$f"; break; }
    done
    [[ -z "$log" ]] && { printf 'no readable mail log\n' >&2; return 1; }

    section "top senders (from $(basename "$log"))"
    # Extract from=<...> lines
    grep 'from=<[^>]' "$log" 2>/dev/null \
        | sed -E 's/.*from=<([^>]*)>.*/\1/' \
        | sort | uniq -c | sort -rn | head -20 \
        | awk '{printf "  %6d  %s\n", $1, $2}'
}
