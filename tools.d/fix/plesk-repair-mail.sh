# tools.d/fix/plesk-repair-mail.sh - run `plesk repair mail -y`
# Wraps the Plesk built-in repair with dry-run + logging discipline.

main() {
    tool_begin "fix.plesk.repair_mail" "run plesk repair mail -y" || return 1

    if ! command -v plesk >/dev/null 2>&1; then
        printf '  skip: plesk CLI not found\n'
        tool_end "skip"
        return 0
    fi

    if ! tool_confirm "run 'plesk repair mail -y' (may restart mail services)?"; then
        printf '  aborted\n'
        tool_end "aborted"
        return 1
    fi

    tool_run plesk repair mail -y
    tool_end "ok"
}
