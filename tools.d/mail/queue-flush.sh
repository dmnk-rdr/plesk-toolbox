# tools.d/mail/queue-flush.sh - flush the Postfix mail queue
# Optional: --older-than=<spec> to delete deferred messages older than N days.

main() {
    tool_begin "mail.queue_flush" "flush / clean postfix queue" || return 1

    if ! command -v postqueue >/dev/null 2>&1; then
        printf '  skip: postfix not installed\n'
        tool_end "skip"
        return 0
    fi

    local older=""
    for arg in "$@"; do
        case "$arg" in
            --older-than=*) older="${arg#*=}" ;;
        esac
    done

    printf '  queue size before:\n'
    postqueue -p 2>/dev/null | tail -1 | sed 's/^/    /'

    if [[ -n "$older" ]]; then
        local days="${older%d}"
        [[ "$days" =~ ^[0-9]+$ ]] || { printf '  invalid --older-than=%s\n' "$older" >&2; tool_end "error"; return 2; }
        if tool_confirm "delete deferred messages older than ${days} days?"; then
            tool_run bash -c "find /var/spool/postfix/deferred -type f -mtime +${days} -print0 | xargs -0 -r postsuper -d"
        fi
    fi

    if tool_confirm "flush queue now (postqueue -f)?"; then
        tool_run postqueue -f
    fi

    printf '  queue size after:\n'
    postqueue -p 2>/dev/null | tail -1 | sed 's/^/    /'
    tool_end "ok"
}
