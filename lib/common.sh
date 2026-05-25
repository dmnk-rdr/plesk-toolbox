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

    # Audits that render their results as a table suppress per-row prose; the
    # counters above still tick so the summary line stays accurate. Stash
    # actionable details (warn/fail with a fix hint) so table_render can
    # print them in a "details:" section after the table.
    if [[ "${_EMIT_SILENT:-0}" -eq 1 ]]; then
        if [[ -n "$fix" && ( "$status" == "warn" || "$status" == "fail" ) ]]; then
            _TBL_DETAILS+=("${status}"$'\x1f'"${id}"$'\x1f'"${message}"$'\x1f'"${fix}")
        fi
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

# ─── Table API ──────────────────────────────────────────────────────────────
# For audits that report one row per subject (domain, port, mount …) — much
# more readable than a flat list of [PASS]/[WARN] lines. Counters keep ticking
# via emit() while the per-row prose is suppressed; the table is rendered once
# at the end of the audit.
#
# Usage:
#     table_init "Domain" "SPF" "DKIM" "DMARC"      # column headers
#     for d in "${domains[@]}"; do
#         spf_cell="$(status_cell pass '-all')"
#         …
#         table_row "$d" "$spf_cell" "$dkim_cell" "$dmarc_cell"
#         emit "health.mail.${d}" "$worst_sev" "$worst_status" "summary" "fix"
#     done
#     table_render
#
# JSON mode (`--json`): table_* are no-ops; emit() emits structured rows.

_TBL_HEADERS=()
_TBL_ROWS=()
_TBL_DETAILS=()
_TBL_ACTIVE=0

# table_init <header1> <header2> …
table_init() {
    [[ "${JSON_OUTPUT:-0}" -eq 1 ]] && return 0
    _TBL_HEADERS=("$@")
    _TBL_ROWS=()
    _TBL_DETAILS=()
    _TBL_ACTIVE=1
    _EMIT_SILENT=1
}

# table_row <cell1> <cell2> …
# Cells may contain ANSI colour codes; width is measured on stripped text.
table_row() {
    [[ "${JSON_OUTPUT:-0}" -eq 1 ]] && return 0
    [[ "${_TBL_ACTIVE:-0}" -eq 1 ]] || return 0
    local row=""
    local first=1
    local c
    for c in "$@"; do
        if (( first )); then row="$c"; first=0
        else row="${row}"$'\x1f'"${c}"; fi
    done
    _TBL_ROWS+=("$row")
}

# Visible width of a cell — strips ANSI escapes, counts UTF-8 chars (not bytes).
# Relies on the shell running under a UTF-8 locale; install.sh ensures that.
_cell_width() {
    local s="$1"
    local out="" i ch in_esc=0
    for (( i=0; i<${#s}; i++ )); do
        ch="${s:i:1}"
        if (( in_esc )); then
            [[ "$ch" =~ [a-zA-Z] ]] && in_esc=0
            continue
        fi
        if [[ "$ch" == $'\x1b' ]]; then in_esc=1; continue; fi
        out+="$ch"
    done
    printf '%d' "${#out}"
}

# Pad a cell to width (right-pad with spaces). ANSI-aware.
_cell_pad() {
    local cell="$1" width="$2"
    local visible
    visible="$(_cell_width "$cell")"
    local pad=$(( width - visible ))
    (( pad < 0 )) && pad=0
    printf '%s%*s' "$cell" "$pad" ""
}

# table_render — flush buffered table to stdout, reset state.
table_render() {
    if [[ "${JSON_OUTPUT:-0}" -eq 1 ]]; then
        _EMIT_SILENT=0; _TBL_ACTIVE=0; _TBL_HEADERS=(); _TBL_ROWS=()
        return 0
    fi
    [[ "${_TBL_ACTIVE:-0}" -eq 1 ]] || return 0

    local ncols=${#_TBL_HEADERS[@]}
    if (( ncols == 0 )) || (( ${#_TBL_ROWS[@]} == 0 )); then
        _EMIT_SILENT=0; _TBL_ACTIVE=0
        _TBL_HEADERS=(); _TBL_ROWS=()
        return 0
    fi

    # Compute per-column widths
    local -a widths
    local i
    for (( i=0; i<ncols; i++ )); do
        widths[i]=$(_cell_width "${_TBL_HEADERS[i]}")
    done

    local row cells w
    for row in "${_TBL_ROWS[@]}"; do
        IFS=$'\x1f' read -ra cells <<< "$row"
        for (( i=0; i<ncols; i++ )); do
            w=$(_cell_width "${cells[i]:-}")
            (( w > widths[i] )) && widths[i]=$w
        done
    done

    # Header row
    printf '  '
    for (( i=0; i<ncols; i++ )); do
        printf '%s%s%s' "$C_BOLD" "$(_cell_pad "${_TBL_HEADERS[i]}" "${widths[i]}")" "$C_RST"
        (( i < ncols-1 )) && printf '  '
    done
    printf '\n'

    # Separator
    printf '  '
    for (( i=0; i<ncols; i++ )); do
        printf '%s' "$C_DIM"
        local n=0
        while (( n < widths[i] )); do printf '─'; n=$((n+1)); done
        printf '%s' "$C_RST"
        (( i < ncols-1 )) && printf '  '
    done
    printf '\n'

    # Data rows
    for row in "${_TBL_ROWS[@]}"; do
        IFS=$'\x1f' read -ra cells <<< "$row"
        printf '  '
        for (( i=0; i<ncols; i++ )); do
            printf '%s' "$(_cell_pad "${cells[i]:-}" "${widths[i]}")"
            (( i < ncols-1 )) && printf '  '
        done
        printf '\n'
    done

    # Detail block: per-row fix hints collected during silent emit().
    # Surfaces the *why* of every ⚠/✗ in the table so the operator doesn't
    # have to re-run with --json or dig through code to find out what's
    # actually wrong.
    if (( ${#_TBL_DETAILS[@]} > 0 )); then
        local d_status _d_id d_msg d_fix sym color
        printf '\n  %sdetails:%s\n' "${C_BOLD:-}" "${C_RST:-}"
        for row in "${_TBL_DETAILS[@]}"; do
            IFS=$'\x1f' read -r d_status _d_id d_msg d_fix <<< "$row"
            case "$d_status" in
                warn) sym='⚠'; color="$C_YEL" ;;
                fail) sym='✗'; color="$C_RED" ;;
                *)    sym='·'; color="$C_DIM" ;;
            esac
            printf '    %s%s %s%s\n' "$color" "$sym" "${d_msg}" "$C_RST"
            printf '      %s↳ %s%s\n' "$C_DIM" "$d_fix" "$C_RST"
        done
    fi

    _EMIT_SILENT=0
    _TBL_ACTIVE=0
    _TBL_HEADERS=()
    _TBL_ROWS=()
    _TBL_DETAILS=()
}

# status_cell <status> [short-text]
# status: pass | warn | fail | skip | info
# Returns a coloured cell with a symbol prefix; safe inside table_row.
status_cell() {
    local status="$1" short="${2:-}"
    local sym color
    case "$status" in
        pass) sym='✓'; color="$C_GRN" ;;
        fail) sym='✗'; color="$C_RED" ;;
        warn) sym='⚠'; color="$C_YEL" ;;
        skip) sym='·'; color="$C_DIM" ;;
        info) sym='ⓘ'; color="$C_BLU" ;;
        *)    sym='?'; color="" ;;
    esac
    if [[ -n "$short" ]]; then
        printf '%s%s %s%s' "$color" "$sym" "$short" "$C_RST"
    else
        printf '%s%s%s' "$color" "$sym" "$C_RST"
    fi
}

# worst_status <status1> <status2> …
# Returns the most severe status (fail > warn > skip > info > pass).
worst_status() {
    local s out="pass"
    for s in "$@"; do
        case "$s" in
            fail) echo "fail"; return ;;
            warn) out="warn" ;;
            skip) [[ "$out" == "pass" ]] && out="skip" ;;
            info) [[ "$out" == "pass" ]] && out="info" ;;
        esac
    done
    echo "$out"
}

# truncate <string> <max-len>
# Domains get an ellipsis in the middle so prefix (subdomain) AND suffix (TLD)
# stay readable. Prefix gets ~40%, suffix ~60% of the budget.
truncate() {
    local s="$1" max="$2"
    local len=${#s}
    (( len <= max )) && { printf '%s' "$s"; return; }
    local pre=$(( (max - 1) * 4 / 10 ))
    local suf=$(( max - 1 - pre ))
    (( pre < 1 )) && pre=1
    (( suf < 1 )) && suf=1
    printf '%s…%s' "${s:0:pre}" "${s: -suf}"
}

# worst_severity <sev1> <sev2> …
# Returns the highest severity (critical > high > medium > low > info).
worst_severity() {
    local s out="info"
    declare -A rank=([info]=0 [low]=1 [medium]=2 [high]=3 [critical]=4)
    local out_rank=0
    for s in "$@"; do
        local r="${rank[$s]:-0}"
        if (( r > out_rank )); then out_rank=$r; out="$s"; fi
    done
    echo "$out"
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
