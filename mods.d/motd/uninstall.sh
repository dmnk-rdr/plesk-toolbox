#!/usr/bin/env bash
# mods.d/motd/uninstall.sh - disable the server-motd dashboard
set -euo pipefail

: "${PTBOX_ROOT:=/opt/plesk-toolbox}"
: "${PTBOX_MOD_NAME:=motd}"
: "${PTBOX_MOD_STATE:=/var/lib/plesk-toolbox/mods}"

# shellcheck source=../../lib/common.sh
. "${PTBOX_ROOT}/lib/common.sh"
# shellcheck source=../../lib/safety.sh
. "${PTBOX_ROOT}/lib/safety.sh"

manifest="${PTBOX_MOD_STATE}/${PTBOX_MOD_NAME}.manifest"
section "mod: motd - uninstall"

if [[ ! -f "$manifest" ]]; then
    printf '  nothing to do (no manifest)\n'
    exit 0
fi

# Reverse the manifest in reverse order
tac "$manifest" | while IFS= read -r line; do
    kind="${line%%:*}"
    path="${line#*:}"
    case "$kind" in
        linked)
            [[ -L "$path" ]] && rm -f "$path"
            ;;
        hidden)
            restore_file "$path"
            ;;
        created)
            rm -f "$path"
            ;;
        enabled)
            if command -v systemctl >/dev/null 2>&1; then
                systemctl disable --now "$path" 2>/dev/null || true
            fi
            ;;
    esac
done

if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload 2>/dev/null || true
fi

rm -f "$manifest"
printf '  motd mod disabled\n'
