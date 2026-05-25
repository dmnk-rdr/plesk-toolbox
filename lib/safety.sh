# lib/safety.sh - dry-run, confirmation, locking, reversible file ops
# Opt-in helpers for tools that make system changes.
[[ -n "${__PTBOX_SAFETY_LOADED:-}" ]] && return 0
__PTBOX_SAFETY_LOADED=1

: "${DRY_RUN:=0}"            # set by dispatcher from --dry-run
: "${ASSUME_YES:=0}"         # set by dispatcher from --yes / -y
: "${PTBOX_LOCK:=/run/plesk-toolbox.lock}"

_PTBOX_TOOL_ID=""
_PTBOX_TOOL_START=0
_PTBOX_TOOL_LOCK_FD=""
_PTBOX_TOOL_RESULT="ok"

# tool_begin <id> <description>
# Acquires lock, records start time, logs a "start" line.
tool_begin() {
    _PTBOX_TOOL_ID="$1"
    local desc="${2:-}"
    _PTBOX_TOOL_START=$(date +%s)

    # common.sh may or may not be loaded; don't hard-require it
    if declare -F section >/dev/null; then
        section "tool: ${_PTBOX_TOOL_ID}"
    else
        printf '== tool: %s ==\n' "${_PTBOX_TOOL_ID}"
    fi
    [[ -n "$desc" ]] && printf '  %s\n' "$desc"
    [[ "$DRY_RUN" -eq 1 ]] && printf '  (dry-run: no changes will be made)\n'

    # Acquire lock (non-blocking; fail fast if busy).
    # NOTE: `2>/dev/null` on a command-less `exec` redirects the *shell's*
    # stderr permanently — losing every error message every tool ever
    # prints. Wrap in a brace-group so the stderr redirect is scoped.
    if ! { exec {_PTBOX_TOOL_LOCK_FD}>"$PTBOX_LOCK"; } 2>/dev/null; then
        printf '  warning: could not open lock file %s\n' "$PTBOX_LOCK" >&2
        _PTBOX_TOOL_LOCK_FD=""
        return 0
    fi
    if ! flock -n "$_PTBOX_TOOL_LOCK_FD" 2>/dev/null; then
        printf '  error: another plesk-toolbox tool is running (lock: %s)\n' "$PTBOX_LOCK" >&2
        _PTBOX_TOOL_RESULT="locked"
        return 1
    fi
    return 0
}

# tool_confirm <prompt>
# Returns 0 if user confirms, 1 otherwise. Honors ASSUME_YES and DRY_RUN.
tool_confirm() {
    local prompt="${1:-Proceed?}"
    [[ "$DRY_RUN" -eq 1 ]] && return 0        # dry-run never asks
    [[ "$ASSUME_YES" -eq 1 ]] && return 0
    if [[ ! -t 0 || ! -t 1 ]]; then
        printf '  refusing: no TTY, pass --yes to confirm non-interactively\n' >&2
        return 1
    fi
    local ans
    read -r -p "  ${prompt} [y/N] " ans
    [[ "$ans" == "y" || "$ans" == "Y" ]]
}

# tool_run <cmd...>
# In dry-run: prints "would run: ...". In apply mode: executes.
tool_run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '  would run: %s\n' "$*"
        return 0
    fi
    printf '  run: %s\n' "$*"
    "$@"
}

# tool_end [result]
# Releases lock, writes log line.
tool_end() {
    local result="${1:-$_PTBOX_TOOL_RESULT}"
    local dur=$(( $(date +%s) - _PTBOX_TOOL_START ))
    if [[ -n "$_PTBOX_TOOL_LOCK_FD" ]]; then
        # Same brace-group trick as in tool_begin — command-less `exec` would
        # otherwise leak the 2>/dev/null into the shell's stderr.
        { exec {_PTBOX_TOOL_LOCK_FD}>&-; } 2>/dev/null || true
        _PTBOX_TOOL_LOCK_FD=""
    fi
    if declare -F log_tool_run >/dev/null; then
        log_tool_run "$_PTBOX_TOOL_ID" "${_PTBOX_TOOL_ARGS:-}" "$result" "$dur" "$DRY_RUN"
    fi
}

# --- Reversible file helpers for mods ---

# hide_file <path>
# Renames path → .disabled-<basename> next to it. No-op if path missing.
hide_file() {
    local p="$1"
    [[ -e "$p" ]] || return 0
    local dir base target
    dir="$(dirname "$p")"
    base="$(basename "$p")"
    target="${dir}/.disabled-${base}"
    [[ -e "$target" ]] && return 0   # already hidden
    tool_run mv "$p" "$target"
}

# restore_file <path>
# Inverse of hide_file.
restore_file() {
    local p="$1"
    local dir base source
    dir="$(dirname "$p")"
    base="$(basename "$p")"
    source="${dir}/.disabled-${base}"
    [[ -e "$source" ]] || return 0
    tool_run mv "$source" "$p"
}
