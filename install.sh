#!/usr/bin/env bash
# install.sh - plesk-toolbox installer
# Installs the source tree to /opt/plesk-toolbox, links shims into /usr/local/bin,
# creates runtime dirs, and enables the 'motd' mod by default.
set -euo pipefail

PREFIX="${PREFIX:-/opt/plesk-toolbox}"
BIN_DIR="${BIN_DIR:-/usr/local/bin}"
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/var/log/plesk-toolbox"
STATE_DIR="/var/lib/plesk-toolbox"

SHIMS=(plesk-toolbox plesk-audit plesk-sec-audit plesk-tool plesk-mod)

uninstall() {
    echo "→ disabling enabled mods"
    if [[ -x "${BIN_DIR}/plesk-toolbox" ]]; then
        for m in "${STATE_DIR}/mods"/*.manifest; do
            [[ -f "$m" ]] || continue
            name="$(basename "$m" .manifest)"
            "${BIN_DIR}/plesk-toolbox" mod disable "$name" || true
        done
    fi

    echo "→ removing shims"
    for s in "${SHIMS[@]}"; do rm -f "${BIN_DIR}/${s}"; done
    rm -f "${BIN_DIR}/server-motd-refresh"

    echo "→ removing source tree"
    rm -rf "$PREFIX"

    echo "done. /etc/plesk-toolbox.conf and ${LOG_DIR} kept — remove manually if desired."
}

if [[ "${1:-}" == "--uninstall" ]]; then
    uninstall
    exit 0
fi

if [[ $EUID -ne 0 ]]; then
    echo "must run as root (try: sudo $0)" >&2
    exit 1
fi

echo "→ installing plesk-toolbox to ${PREFIX}"
mkdir -p "$PREFIX"
# Copy all tree components that exist
for d in bin lib audits.d tools.d mods.d share; do
    [[ -d "${SRC_DIR}/${d}" ]] || continue
    cp -a "${SRC_DIR}/${d}" "$PREFIX/"
done
[[ -f "${SRC_DIR}/plesk-toolbox.conf.example" ]] && \
    cp "${SRC_DIR}/plesk-toolbox.conf.example" "$PREFIX/"
[[ -f "${SRC_DIR}/README.md" ]] && cp "${SRC_DIR}/README.md" "$PREFIX/"
[[ -f "${SRC_DIR}/LICENSE" ]] && cp "${SRC_DIR}/LICENSE" "$PREFIX/"

find "${PREFIX}/bin" -type f -exec chmod +x {} \;
find "${PREFIX}/mods.d" -name '*.sh' -exec chmod +x {} \; 2>/dev/null || true

echo "→ creating shims in ${BIN_DIR}"
for s in "${SHIMS[@]}"; do
    ln -sfn "${PREFIX}/bin/${s}" "${BIN_DIR}/${s}"
done
ln -sfn "${PREFIX}/bin/server-motd-refresh" "${BIN_DIR}/server-motd-refresh"

echo "→ creating runtime directories"
mkdir -p "$LOG_DIR" "${STATE_DIR}/mods" /var/cache/server-motd

echo "→ installing example config"
if [[ ! -f /etc/plesk-toolbox.conf && -f "${PREFIX}/plesk-toolbox.conf.example" ]]; then
    install -m 0644 "${PREFIX}/plesk-toolbox.conf.example" /etc/plesk-toolbox.conf
    echo "  wrote /etc/plesk-toolbox.conf (review it)"
fi

echo "→ installing bash completion"
if [[ -d /etc/bash_completion.d && -f "${PREFIX}/share/completion/plesk-toolbox.bash" ]]; then
    install -m 0644 "${PREFIX}/share/completion/plesk-toolbox.bash" \
        /etc/bash_completion.d/plesk-toolbox
fi

echo "→ enabling 'motd' mod"
"${BIN_DIR}/plesk-toolbox" mod enable motd || true

cat <<EOF

✓ plesk-toolbox installed.

Try:
  sudo plesk-toolbox audit              # run the full audit
  sudo plesk-sec-audit                  # legacy alias, still works
  sudo plesk-toolbox audit --list       # list available checks
  sudo plesk-tool domain/show <domain>  # inspect a hosted domain
  sudo plesk-mod list                   # mod status

Logs:     ${LOG_DIR}/
Config:   /etc/plesk-toolbox.conf
Source:   ${PREFIX}

Uninstall: sudo ${SRC_DIR}/install.sh --uninstall
EOF
