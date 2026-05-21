# tools.d/system/top-open-files.sh - processes with the most open file descriptors
# Useful when hitting nofile limits (common on busy Plesk + Apache + PHP-FPM).

main() {
    if ! command -v lsof >/dev/null 2>&1; then
        printf 'lsof not installed\n' >&2
        return 1
    fi

    section "processes by open file descriptors"
    printf '  %6s %-20s %6s\n' "PID" "COMMAND" "COUNT"
    lsof -n 2>/dev/null \
        | awk 'NR>1 {print $2, $1}' \
        | sort | uniq -c | sort -rn | head -15 \
        | awk '{printf "  %6d %-20s %6d\n", $2, $3, $1}'
}
