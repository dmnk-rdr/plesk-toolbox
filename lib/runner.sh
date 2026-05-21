# lib/runner.sh - shared loader for audits.d/ and tools.d/ modules
[[ -n "${__PTBOX_RUNNER_LOADED:-}" ]] && return 0
__PTBOX_RUNNER_LOADED=1

: "${PTBOX_ROOT:=/opt/plesk-toolbox}"

# _runner_reset_counters
_runner_reset_counters() {
    _CNT_PASS=0; _CNT_FAIL=0; _CNT_WARN=0; _CNT_SKIP=0
    _JSON_FIRST=1
}

# run_audit_dir <absolute-dir> [filter-glob]
# Sources every NN-*.sh under the directory (sorted), in the current shell.
run_audit_dir() {
    local dir="$1" filter="${2:-*.sh}"
    local f
    [[ -d "$dir" ]] || { printf '  (no checks in %s)\n' "$dir" >&2; return 0; }
    shopt -s nullglob
    for f in "$dir"/$filter; do
        [[ -f "$f" ]] || continue
        # shellcheck disable=SC1090
        . "$f"
    done
    shopt -u nullglob
}

# run_audit_profile <profile>
# Profile shorthand: sec, health, sec/network, health/mail, etc.
run_audit_profile() {
    local profile="${1:-}"
    local base="${PTBOX_ROOT}/audits.d"
    [[ -z "$profile" ]] && {
        run_audit_dir "${base}/sec"
        run_audit_dir "${base}/health"
        return
    }
    # Pillar with optional group filter: sec, sec/network
    local pillar="${profile%%/*}"
    local group="${profile#*/}"
    [[ "$pillar" == "$group" ]] && group=""
    if [[ -z "$group" ]]; then
        run_audit_dir "${base}/${pillar}"
    else
        # Group filter: NN-<group>-*.sh
        run_audit_dir "${base}/${pillar}" "*-${group}-*.sh"
    fi
}

# list_audits [pillar]
list_audits() {
    local pillar="${1:-}" base="${PTBOX_ROOT}/audits.d"
    local dir files f
    if [[ -n "$pillar" ]]; then
        dir="${base}/${pillar}"
        [[ -d "$dir" ]] || { echo "(no audits in $dir)"; return 1; }
        printf '%s:\n' "$pillar"
        for f in "$dir"/*.sh; do
            [[ -f "$f" ]] && printf '  %s\n' "$(basename "$f" .sh)"
        done
        return 0
    fi
    for p in sec health; do
        dir="${base}/${p}"
        [[ -d "$dir" ]] || continue
        printf '%s:\n' "$p"
        for f in "$dir"/*.sh; do
            [[ -f "$f" ]] && printf '  %s\n' "$(basename "$f" .sh)"
        done
    done
}

# run_tool <group/name> <args...>
run_tool() {
    local spec="$1"; shift || true
    [[ -z "$spec" ]] && { echo "usage: plesk-tool <group>/<name> [args...]" >&2; return 2; }
    # Resolve group/name to a file
    local path="${PTBOX_ROOT}/tools.d/${spec}.sh"
    if [[ ! -f "$path" ]]; then
        # Allow shorthand without extension in either component
        path="${PTBOX_ROOT}/tools.d/${spec}"
        [[ ! -f "$path" ]] && { printf 'tool not found: %s\n' "$spec" >&2; return 2; }
    fi
    _PTBOX_TOOL_ARGS="$*"
    # shellcheck disable=SC1090
    . "$path"
    if declare -F main >/dev/null; then
        main "$@"
    else
        printf 'tool %s missing main() function\n' "$spec" >&2
        return 2
    fi
}

# list_tools
list_tools() {
    local base="${PTBOX_ROOT}/tools.d"
    [[ -d "$base" ]] || { echo "(no tools installed)"; return 0; }
    local group f
    for group in "$base"/*/; do
        [[ -d "$group" ]] || continue
        printf '%s:\n' "$(basename "$group")"
        for f in "$group"*.sh; do
            [[ -f "$f" ]] && printf '  %s/%s\n' "$(basename "$group")" "$(basename "$f" .sh)"
        done
    done
}

# Print summary line after an audit run (counts + colors if TTY)
audit_summary() {
    [[ "${JSON_OUTPUT:-0}" -eq 1 ]] && return 0
    printf '\n%ssummary:%s %s%d pass%s  %s%d warn%s  %s%d fail%s  %s%d skip%s\n' \
        "${C_BOLD:-}" "${C_RST:-}" \
        "${C_GRN:-}" "$_CNT_PASS" "${C_RST:-}" \
        "${C_YEL:-}" "$_CNT_WARN" "${C_RST:-}" \
        "${C_RED:-}" "$_CNT_FAIL" "${C_RST:-}" \
        "${C_DIM:-}" "$_CNT_SKIP" "${C_RST:-}"
}
