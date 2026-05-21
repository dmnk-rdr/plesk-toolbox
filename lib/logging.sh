# lib/logging.sh - structured logging to /var/log/plesk-toolbox/
[[ -n "${__PTBOX_LOGGING_LOADED:-}" ]] && return 0
__PTBOX_LOGGING_LOADED=1

: "${LOG_DIR:=/var/log/plesk-toolbox}"
: "${__PTBOX_COMMON_LOADED:=}"

# Ensure log dir exists (best-effort; if we can't, fall back to syslog/stderr)
_log_ensure_dir() {
    [[ -d "$LOG_DIR" ]] && return 0
    mkdir -p "$LOG_DIR" 2>/dev/null || return 1
}

# _log_append <file> <json-line>
_log_append() {
    local file="$1" line="$2"
    _log_ensure_dir || { printf '%s\n' "$line" >&2; return 0; }
    printf '%s\n' "$line" >> "${LOG_DIR}/${file}" 2>/dev/null || \
        printf '%s\n' "$line" >&2
}

# log_audit_run <pillar> <profile> <pass> <warn> <fail> <skip> <duration_s>
log_audit_run() {
    local pillar="$1" profile="$2" p="$3" w="$4" f="$5" s="$6" dur="$7"
    local ts user
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    user="${SUDO_USER:-${USER:-root}}"
    _log_append "audit.log" \
        "{\"ts\":\"${ts}\",\"user\":\"${user}\",\"pillar\":\"${pillar}\",\"profile\":\"${profile}\",\"pass\":${p},\"warn\":${w},\"fail\":${f},\"skip\":${s},\"duration_s\":${dur}}"
}

# log_tool_run <id> <args> <result> <duration_s> [dry_run]
log_tool_run() {
    local id="$1" args="$2" result="$3" dur="$4" dry="${5:-0}"
    local ts user tty
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    user="${SUDO_USER:-${USER:-root}}"
    tty="$(tty 2>/dev/null || echo 'none')"
    # escape args quotes minimally
    args="${args//\\/\\\\}"; args="${args//\"/\\\"}"
    _log_append "tool.log" \
        "{\"ts\":\"${ts}\",\"user\":\"${user}\",\"tty\":\"${tty}\",\"id\":\"${id}\",\"args\":\"${args}\",\"result\":\"${result}\",\"duration_s\":${dur},\"dry_run\":${dry}}"
}

# log_mod_event <mod> <event> [detail]
log_mod_event() {
    local mod="$1" event="$2" detail="${3:-}"
    local ts user
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    user="${SUDO_USER:-${USER:-root}}"
    detail="${detail//\\/\\\\}"; detail="${detail//\"/\\\"}"
    _log_append "mod.log" \
        "{\"ts\":\"${ts}\",\"user\":\"${user}\",\"mod\":\"${mod}\",\"event\":\"${event}\",\"detail\":\"${detail}\"}"
}
