#!/usr/bin/env bash
# mods.d/motd/install.sh - enable the server-motd dashboard
set -euo pipefail

: "${PTBOX_ROOT:=/opt/plesk-toolbox}"
: "${PTBOX_MOD_NAME:=motd}"
: "${PTBOX_MOD_STATE:=/var/lib/plesk-toolbox/mods}"
MOTD_DIR="/etc/update-motd.d"
SYSTEMD_DIR="/etc/systemd/system"
CACHE_DIR="/var/cache/server-motd"

# shellcheck source=../../lib/common.sh
. "${PTBOX_ROOT}/lib/common.sh"
# shellcheck source=../../lib/safety.sh
. "${PTBOX_ROOT}/lib/safety.sh"

mkdir -p "$PTBOX_MOD_STATE" "$CACHE_DIR"
manifest="${PTBOX_MOD_STATE}/${PTBOX_MOD_NAME}.manifest"
: > "$manifest"

_record() { printf '%s\n' "$1" >> "$manifest"; }

section "mod: motd - install"

# Disable noisy default motd scripts (reversible)
DEFAULT_MOTD_DISABLE=(10-uname 50-motd-news 90-updates-available 91-release-upgrade 97-overlayroot)
for d in "${DEFAULT_MOTD_DISABLE[@]}"; do
    if [[ -f "${MOTD_DIR}/${d}" ]]; then
        hide_file "${MOTD_DIR}/${d}"
        _record "hidden:${MOTD_DIR}/${d}"
    fi
done

# Link our sections into /etc/update-motd.d/
mkdir -p "$MOTD_DIR"
for src in "${PTBOX_ROOT}/mods.d/motd/sections"/*.sh; do
    [[ -f "$src" ]] || continue
    base="$(basename "$src")"
    target="${MOTD_DIR}/${base}"
    chmod +x "$src"
    ln -sfn "$src" "$target"
    _record "linked:${target}"
done

# systemd timer for the refresh worker
if [[ -d "$SYSTEMD_DIR" ]] && command -v systemctl >/dev/null 2>&1; then
    install -m 0644 "${PTBOX_ROOT}/share/systemd/server-motd-refresh.service" \
        "${SYSTEMD_DIR}/server-motd-refresh.service"
    _record "created:${SYSTEMD_DIR}/server-motd-refresh.service"
    install -m 0644 "${PTBOX_ROOT}/share/systemd/server-motd-refresh.timer" \
        "${SYSTEMD_DIR}/server-motd-refresh.timer"
    _record "created:${SYSTEMD_DIR}/server-motd-refresh.timer"
    systemctl daemon-reload
    systemctl enable --now server-motd-refresh.timer
    _record "enabled:server-motd-refresh.timer"
fi

# Prime the cache once so the first login shows something fresh
"${PTBOX_ROOT}/bin/server-motd-refresh" 2>/dev/null || true

printf '  motd mod enabled. try: run-parts %s/\n' "$MOTD_DIR"
