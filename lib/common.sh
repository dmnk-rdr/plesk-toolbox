# lib/common.sh - shared emit API, config loading, formatting
# Source once from runners. Safe to re-source.

[[ -n "${__PTBOX_COMMON_LOADED:-}" ]] && return 0
__PTBOX_COMMON_LOADED=1

# --- Colors (only on TTY, never in JSON mode) ---
if [[ -t 1 && "${JSON_OUTPUT:-0}" -eq 0 && "${NO_COLOR:-}" == "" ]]; then
    C_RST=$'\e[0m'; C_DIM=$'\e[2m'; C_BOLD=$'\e[1m'
    C_RED=$'\e[31m'; C_GRN=$'\e[32m'; C_YEL=$'\e[33m'; C_BLU=$'\e[34m'; C_CYN=$'\e[36m'
else
    C_RST=''; C_DIM=''; C_BOLD=''; C_RED=''; C_GRN=''; C_YEL=''; C_BLU=''; C_CYN=''
fi

# --- Counters (reset per run by the runner) ---
: "${_CNT_PASS:=0}" "${_CNT_FAIL:=0}" "${_CNT_WARN:=0}" "${_CNT_SKIP:=0}"
: "${_JSON_FIRST:=1}"

# --- Config loading ---
# Looks in /etc/plesk-toolbox.conf and $PTBOX_CONF (if set)
_load_config() {
    local candidates=(/etc/plesk-toolbox.conf "${PTBOX_CONF:-}")
    local f
    for f in "${candidates[@]}"; do
        [[ -n "$f" && -r "$f" ]] && . "$f"
    done
    return 0
}

# --- Severity override lookup ---
# SEVERITY_OVERRIDE_<id_with_dots_as_underscores> can downgrade a result
_severity_override() {
    local id="$1" var key
    # Sanitize to a valid shell var name: keep [A-Za-z0-9_], replace rest with _
    key="${id//[^A-Za-z0-9_]/_}"
    var="SEVERITY_OVERRIDE_${key}"
    printf '%s' "${!var:-}"
}

# --- emit: the unified reporting API ---
# Usage: emit <id> <severity> <status> <message> [fix_hint]
#   severity: info | low | medium | high | critical
#   status:   pass | warn | fail | skip
emit() {
    local id="$1" severity="$2" status="$3" message="$4" fix="${5:-}"
    local override
    override="$(_severity_override "$id")"
    if [[ -n "$override" ]]; then
        case "$override" in
            info)    severity="info"; [[ "$status" == "fail" ]] && status="warn" ;;
            low|medium|high|critical) severity="$override" ;;
        esac
    fi

    case "$status" in
        pass) _CNT_PASS=$((_CNT_PASS+1)) ;;
        fail) _CNT_FAIL=$((_CNT_FAIL+1)) ;;
        warn) _CNT_WARN=$((_CNT_WARN+1)) ;;
        skip) _CNT_SKIP=$((_CNT_SKIP+1)) ;;
    esac

    if [[ "${JSON_OUTPUT:-0}" -eq 1 ]]; then
        [[ $_JSON_FIRST -eq 1 ]] && _JSON_FIRST=0 || printf ','
        printf '{"id":%s,"severity":%s,"status":%s,"message":%s,"fix":%s}' \
            "$(_json_str "$id")" \
            "$(_json_str "$severity")" \
            "$(_json_str "$status")" \
            "$(_json_str "$message")" \
            "$(_json_str "$fix")"
        return 0
    fi

    local tag color
    case "$status" in
        pass) tag="PASS"; color="$C_GRN" ;;
        fail) tag="FAIL"; color="$C_RED" ;;
        warn) tag="WARN"; color="$C_YEL" ;;
        skip) tag="SKIP"; color="$C_DIM" ;;
        *)    tag="????"; color="" ;;
    esac
    printf '  %s[%s]%s %-38s %s\n' "$color" "$tag" "$C_RST" "$id" "$message"
    if [[ -n "$fix" && "$status" != "pass" && "$status" != "skip" ]]; then
        printf '         %s↳ %s%s\n' "$C_DIM" "$fix" "$C_RST"
    fi
}

# Minimal JSON string escaper
_json_str() {
    local s="${1:-}"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"; s="${s//$'\t'/\\t}"; s="${s//$'\r'/\\r}"
    printf '"%s"' "$s"
}

# Section header for grouped output
section() {
    [[ "${JSON_OUTPUT:-0}" -eq 1 ]] && return 0
    printf '\n%s== %s ==%s\n' "$C_BOLD" "$1" "$C_RST"
}

# Pretty "label: value" line, used by MOTD and audit prelude
label_line() {
    local label="$1" value="$2"
    printf '  %s%-14s%s %s\n' "$C_DIM" "$label" "$C_RST" "$value"
}

# Human-readable bytes (KB/MB/GB), one decimal. Pure bash — no bc dependency.
hr_bytes() {
    local b="${1:-0}" div unit
    if   (( b >= 1073741824 )); then div=1073741824; unit=G
    elif (( b >= 1048576 ));    then div=1048576;    unit=M
    elif (( b >= 1024 ));       then div=1024;       unit=K
    else                              printf '%dB' "$b"; return
    fi
    # Integer maths: whole.tenths
    printf '%d.%d%s' "$(( b / div ))" "$(( (b * 10 / div) % 10 ))" "$unit"
}

# Progress bar for resource usage
# bar <percent> [width] [threshold_warn] [threshold_fail]
bar() {
    local pct="${1:-0}" width="${2:-30}"
    local tw="${3:-70}" tf="${4:-90}"
    local filled=$(( pct * width / 100 ))
    (( filled > width )) && filled=$width
    (( filled < 0 ))     && filled=0
    local color="$C_GRN"
    (( pct >= tw )) && color="$C_YEL"
    (( pct >= tf )) && color="$C_RED"
    printf '%s' "$color"
    local i
    for ((i=0; i<filled; i++)); do printf '█'; done
    printf '%s' "$C_DIM"
    for ((i=filled; i<width; i++)); do printf '·'; done
    printf '%s %3d%%' "$C_RST" "$pct"
}

# Run a check file in a safe subshell wrapper — used by runners
run_check_file() {
    local f="$1"
    # shellcheck disable=SC1090
    . "$f"
}
