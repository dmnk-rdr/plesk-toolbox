# tools.d/plesk/sw-engine-rss.sh - show sw-engine workers sorted by RSS
# Plesk's PHP-FPM/FastCGI process manager is a frequent source of memory pressure.

main() {
    if ! pgrep -x sw-engine >/dev/null 2>&1; then
        printf 'sw-engine not running\n' >&2
        return 1
    fi

    section "sw-engine workers (top RSS)"
    ps -C sw-engine -o pid,ppid,user,rss,%cpu,etime,cmd --sort=-rss 2>/dev/null \
        | awk 'NR==1 {print "  " $0; next}
               NR<=16 {printf "  %6d %6d %-8s %6dK %5s %-12s %s\n", $1,$2,$3,$4,$5,$6,$7}'

    local total_kb
    total_kb="$(ps -C sw-engine -o rss= 2>/dev/null | awk '{s+=$1} END{print s+0}')"
    printf '\n  total sw-engine RSS: %s\n' "$(hr_bytes $(( total_kb * 1024 )))"
}
