# lib/dispatch.sh - top-level subcommand router
[[ -n "${__PTBOX_DISPATCH_LOADED:-}" ]] && return 0
__PTBOX_DISPATCH_LOADED=1

: "${PTBOX_ROOT:=/opt/plesk-toolbox}"
: "${JSON_OUTPUT:=0}"
: "${DRY_RUN:=0}"
: "${ASSUME_YES:=0}"
: "${DISPATCH_LIST:=0}"
export JSON_OUTPUT DRY_RUN ASSUME_YES DISPATCH_LIST

# shellcheck source=common.sh
. "${PTBOX_ROOT}/lib/common.sh"
# shellcheck source=logging.sh
. "${PTBOX_ROOT}/lib/logging.sh"
# shellcheck source=runner.sh
. "${PTBOX_ROOT}/lib/runner.sh"

dispatch_usage() {
    cat <<EOF
plesk-toolbox - Plesk server daily-ops toolbox

usage:
  plesk-toolbox audit  [sec|health|<group>|<pillar>/<group>] [--json] [--list]
  plesk-toolbox tool   <group>/<name> [args...] [--dry-run] [--yes]
  plesk-toolbox mod    list | status <name> | enable <name> | disable <name>
  plesk-toolbox help   [topic]

audit profile examples:
  audit               full audit (sec + health)
  audit sec           security pillar only
  audit mail          all mail-related checks across pillars
  audit sec/mail      mail checks under sec/ only
  audit health/mail   mail checks under health/ only

global flags:
  --json        machine-readable output (audit only)
  --dry-run     describe changes, don't execute (tool only)
  --yes / -y    skip confirmation prompts (tool only)
  --list        enumerate available items (audit, tool)
  --no-color    disable colored output

examples:
  sudo plesk-toolbox audit sec
  sudo plesk-toolbox audit --list
  sudo plesk-toolbox tool domain/show example.com
  sudo plesk-toolbox tool fix/plesk-repair-mail --dry-run
  sudo plesk-toolbox mod enable motd

legacy shims: plesk-sec-audit, plesk-audit, plesk-tool, plesk-mod
EOF
}

# Parse global flags out of argv, leaving positional args in _DISPATCH_ARGS
_parse_global_flags() {
    _DISPATCH_ARGS=()
    local a
    for a in "$@"; do
        case "$a" in
            --json)      JSON_OUTPUT=1 ;;
            --dry-run)   DRY_RUN=1 ;;
            --yes|-y)    ASSUME_YES=1 ;;
            --list)      DISPATCH_LIST=1 ;;
            --no-color)  C_RST=''; C_DIM=''; C_BOLD=''; C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_CYN='' ;;
            *)           _DISPATCH_ARGS+=("$a") ;;
        esac
    done
    export JSON_OUTPUT DRY_RUN ASSUME_YES
}

# dispatch_audit [profile]
dispatch_audit() {
    _load_config
    _runner_reset_counters
    local profile="${1:-}"
    if [[ "${DISPATCH_LIST:-0}" -eq 1 ]]; then
        list_audits "$profile"
        return 0
    fi
    local start=$(date +%s)
    if [[ "$JSON_OUTPUT" -eq 1 ]]; then
        printf '{"results":['
    else
        section "plesk-toolbox audit ${profile:-all}"
    fi
    run_audit_profile "$profile"
    if [[ "$JSON_OUTPUT" -eq 1 ]]; then
        printf '],"summary":{"pass":%d,"warn":%d,"fail":%d,"skip":%d}}\n' \
            "$_CNT_PASS" "$_CNT_WARN" "$_CNT_FAIL" "$_CNT_SKIP"
    else
        audit_summary
    fi
    local dur=$(( $(date +%s) - start ))
    log_audit_run "audit" "${profile:-all}" "$_CNT_PASS" "$_CNT_WARN" "$_CNT_FAIL" "$_CNT_SKIP" "$dur"
    # Exit non-zero if any fails
    [[ "$_CNT_FAIL" -gt 0 ]] && return 1
    return 0
}

# dispatch_tool <group/name> [args...]
dispatch_tool() {
    _load_config
    # shellcheck source=safety.sh
    . "${PTBOX_ROOT}/lib/safety.sh"
    if [[ "${DISPATCH_LIST:-0}" -eq 1 ]]; then
        list_tools
        return 0
    fi
    local spec="${1:-}"; shift || true
    if [[ -z "$spec" ]]; then
        list_tools
        return 0
    fi
    run_tool "$spec" "$@"
}

# dispatch_mod <subcmd> [args...]
dispatch_mod() {
    _load_config
    # shellcheck source=safety.sh
    . "${PTBOX_ROOT}/lib/safety.sh"
    local sub="${1:-list}"; shift || true
    local mods_dir="${PTBOX_ROOT}/mods.d"
    local state_dir="/var/lib/plesk-toolbox/mods"
    mkdir -p "$state_dir" 2>/dev/null || true

    case "$sub" in
        list)
            local m name status
            for m in "$mods_dir"/*/; do
                [[ -d "$m" ]] || continue
                name="$(basename "$m")"
                if [[ -f "${state_dir}/${name}.manifest" ]]; then
                    status="enabled"
                else
                    status="disabled"
                fi
                printf '  %-20s %s\n' "$name" "$status"
            done
            ;;
        status)
            local name="${1:?usage: plesk-mod status <name>}"
            if [[ -f "${state_dir}/${name}.manifest" ]]; then
                printf '%s: enabled\n' "$name"
                printf '  manifest: %s\n' "${state_dir}/${name}.manifest"
                printf '  files:\n'
                sed 's/^/    /' "${state_dir}/${name}.manifest"
            else
                printf '%s: disabled\n' "$name"
            fi
            ;;
        enable)
            local name="${1:?usage: plesk-mod enable <name>}"
            local script="${mods_dir}/${name}/install.sh"
            [[ -f "$script" ]] || { printf 'mod not found: %s\n' "$name" >&2; return 2; }
            PTBOX_MOD_NAME="$name" PTBOX_MOD_STATE="$state_dir" \
                bash "$script"
            log_mod_event "$name" "enable"
            ;;
        disable)
            local name="${1:?usage: plesk-mod disable <name>}"
            local script="${mods_dir}/${name}/uninstall.sh"
            [[ -f "$script" ]] || { printf 'mod not found: %s\n' "$name" >&2; return 2; }
            PTBOX_MOD_NAME="$name" PTBOX_MOD_STATE="$state_dir" \
                bash "$script"
            log_mod_event "$name" "disable"
            ;;
        *)
            echo "usage: plesk-mod {list|status|enable|disable} [name]" >&2
            return 2
            ;;
    esac
}

# dispatch_main <pillar> [args...]
dispatch_main() {
    local pillar="${1:-}"; shift || true
    _parse_global_flags "$@"
    # Bash 4.2 (CentOS 7) + set -u: ${arr[@]} on an empty array is "unbound".
    # The +"…" expansion preserves emptiness without tripping nounset.
    set -- ${_DISPATCH_ARGS[@]+"${_DISPATCH_ARGS[@]}"}
    case "$pillar" in
        audit)    dispatch_audit "$@" ;;
        tool)     dispatch_tool "$@" ;;
        mod)      dispatch_mod "$@" ;;
        help|-h|--help|"") dispatch_usage ;;
        *)        printf 'unknown command: %s\n' "$pillar" >&2; dispatch_usage; return 2 ;;
    esac
}
