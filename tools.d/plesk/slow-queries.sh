# tools.d/plesk/slow-queries.sh - summarise the Plesk MySQL slow query log
# Usage: plesk-tool plesk/slow-queries [logfile]

main() {
    local log="${1:-}"
    if [[ -z "$log" ]]; then
        for f in /var/lib/mysql/*slow*.log /var/log/mysql/mysql-slow.log /var/log/mariadb/mysql-slow.log; do
            [[ -r "$f" ]] && { log="$f"; break; }
        done
    fi
    [[ -r "$log" ]] || { printf 'no readable slow query log found\n' >&2; return 1; }

    section "slow queries: ${log}"

    if command -v pt-query-digest >/dev/null 2>&1; then
        pt-query-digest --limit 10 "$log"
        return 0
    fi

    if command -v mysqldumpslow >/dev/null 2>&1; then
        mysqldumpslow -t 10 -s c "$log"
        return 0
    fi

    # Fallback: crude grep
    printf '  queries longer than 1s (raw count by fingerprint):\n'
    awk '/^# Query_time/ {t=$3} /^[[:space:]]*SELECT|^[[:space:]]*UPDATE|^[[:space:]]*DELETE|^[[:space:]]*INSERT/ {if (t>1) print}' "$log" \
        | sort | uniq -c | sort -rn | head -10
}
