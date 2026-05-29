# audits.d/health/44-mail-greylist.sh — greylisting-induced delivery delay
#
# Parses the last N days of /var/log/maillog (incl. rotated *.gz) for inbound
# mail to local mailboxes. Measures the wall-clock delay between the FIRST
# SMTP attempt (when psa-pc-remote first logs a queue id for a sender/recipient
# pair) and the FIRST successful delivery via plesk_virtual. Delays ≥ 60s are
# attributed to greylisting (5xx retries from large senders with rotating IPs
# are the dominant cause).
#
# Output:
#   - Summary emit:   count, % delayed, avg-of-delayed, p95, max
#   - Top-N table:    most-delayed sender domains with count / avg / max
# Status thresholds (avg of delayed mails):
#   pass  < MAIL_GREYLIST_WARN_AVG_MIN
#   warn  ≥ warn, < fail
#   fail  ≥ MAIL_GREYLIST_FAIL_AVG_MIN

section "health: greylisting / delivery delay"

: "${MAIL_GREYLIST_DAYS:=7}"
: "${MAIL_GREYLIST_WARN_AVG_MIN:=5}"
: "${MAIL_GREYLIST_FAIL_AVG_MIN:=15}"
: "${MAIL_GREYLIST_TOP_N:=5}"
: "${MAIL_GREYLIST_LOG_DIR:=/var/log}"
: "${MAIL_GREYLIST_MIN_DELAY_SEC:=60}"

# Find log files (active + rotated, including .gz).
mapfile -t _gl_logs < <(find "$MAIL_GREYLIST_LOG_DIR" -maxdepth 1 \
    \( -name 'maillog' -o -name 'maillog.*' -o -name 'mail.log' -o -name 'mail.log.*' \) \
    -type f 2>/dev/null | sort)
if (( ${#_gl_logs[@]} == 0 )); then
    emit "health.greylist.delay" "info" "skip" \
        "no maillog found in $MAIL_GREYLIST_LOG_DIR"
    return 0
fi

# Cutoff = N days ago.
_gl_cutoff="$(date -d "${MAIL_GREYLIST_DAYS} days ago" +%s 2>/dev/null || \
    echo $(( $(date +%s) - MAIL_GREYLIST_DAYS * 86400 )))"
_gl_year="$(date +%Y)"
_gl_month="$(date +%-m)"

_gl_format_min() {
    # seconds → "Xmin" or "Xh Ymin" for human-readable display.
    local s="$1"
    if (( s < 60 )); then printf '%ds' "$s"; return; fi
    local m=$(( s / 60 ))
    if (( m < 60 )); then printf '%dmin' "$m"; return; fi
    printf '%dh %dmin' $(( m / 60 )) $(( m % 60 ))
}

# Single awk pass over all logs. Emits KEY=VAL lines + TOP|domain|count|avg|max.
_gl_result="$({
    for f in "${_gl_logs[@]}"; do
        case "$f" in
            *.gz) zcat -f "$f" 2>/dev/null ;;
            *)    cat "$f" 2>/dev/null ;;
        esac
    done
} | awk -v cutoff="$_gl_cutoff" -v cy="$_gl_year" -v cm="$_gl_month" \
        -v mindelay="$MAIL_GREYLIST_MIN_DELAY_SEC" '
BEGIN {
    split("Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec", mn, " ")
    for (i=1; i<=12; i++) months[mn[i]] = i
}
function ts_of(mon, day, time,    mnum, year, t) {
    mnum = months[mon]
    if (mnum == 0) return 0
    # Year-wrap: log month much greater than current month → previous year.
    year = cy
    if (mnum > cm + 1) year = cy - 1
    split(time, t, ":")
    return mktime(sprintf("%d %02d %02d %s %s %s", year, mnum, day, t[1], t[2], t[3]))
}
# psa-pc-remote logs from=/to= before milter decision; captures every attempt.
/psa-pc-remote/ && /from=<.*> to=<.*>/ && !/queued as/ && !/py-limit/ {
    ts = ts_of($1, $2, $3); if (ts == 0 || ts < cutoff) next
    if (!match($0, /[A-F0-9]{9,12}:/)) next
    qid = substr($0, RSTART, RLENGTH-1)
    if (!match($0, /from=<[^>]*>/)) next
    f = substr($0, RSTART+6, RLENGTH-7)
    if (!match($0, /to=<[^>]+>/)) next
    t = substr($0, RSTART+4, RLENGTH-5)
    if (f == "" || t == "") next
    qfrom[qid] = f; qto[qid] = t
    key = f "|" t
    if (!(key in firstSeen) || ts < firstSeen[key]) firstSeen[key] = ts
}
/status=sent/ && /delivered via plesk_virtual/ {
    ts = ts_of($1, $2, $3); if (ts == 0 || ts < cutoff) next
    if (!match($0, /[A-F0-9]{9,12}:/)) next
    qid = substr($0, RSTART, RLENGTH-1)
    if (!(qid in qfrom)) next
    key = qfrom[qid] "|" qto[qid]
    if (key in done) next
    done[key] = 1
    delay = ts - firstSeen[key]
    if (delay < 0) delay = 0
    n++
    sum_all += delay
    delays[n] = delay
    if (delay > max_all) { max_all = delay }
    if (delay >= mindelay) {
        n_delayed++
        sum_delayed += delay
        # Per-domain stats for the top-N list.
        split(qfrom[qid], parts, "@")
        dom = (parts[2] == "") ? qfrom[qid] : parts[2]
        d_count[dom]++
        d_sum[dom] += delay
        if (delay > d_max[dom]) d_max[dom] = delay
    }
}
END {
    if (n == 0) { print "EMPTY=1"; exit }
    asort(delays)
    p95i = int(n * 0.95 + 0.5); if (p95i < 1) p95i = 1; if (p95i > n) p95i = n
    avg_all = sum_all / n
    avg_delayed = (n_delayed > 0) ? (sum_delayed / n_delayed) : 0
    pct = (n_delayed * 100.0) / n
    printf "TOTAL=%d\n", n
    printf "DELAYED=%d\n", n_delayed
    printf "PCT=%.1f\n", pct
    printf "AVG_ALL=%d\n", avg_all + 0.5
    printf "AVG_DELAYED=%d\n", avg_delayed + 0.5
    printf "P95=%d\n", delays[p95i]
    printf "MAX=%d\n", max_all
    for (d in d_count) {
        printf "TOP|%s|%d|%d|%d\n", d, d_count[d], d_sum[d] / d_count[d], d_max[d]
    }
}
')"

if [[ -z "$_gl_result" ]] || grep -q '^EMPTY=1$' <<< "$_gl_result"; then
    emit "health.greylist.delay" "info" "skip" \
        "no inbound deliveries in last ${MAIL_GREYLIST_DAYS} day(s)"
    return 0
fi

declare -A _gl_v
while IFS= read -r _gl_line; do
    [[ "$_gl_line" == TOP\|* ]] && continue
    [[ "$_gl_line" == *=* ]] || continue
    _gl_v["${_gl_line%%=*}"]="${_gl_line#*=}"
done <<< "$_gl_result"

_gl_total="${_gl_v[TOTAL]:-0}"
_gl_delayed="${_gl_v[DELAYED]:-0}"
_gl_pct="${_gl_v[PCT]:-0.0}"
_gl_avg_delayed="${_gl_v[AVG_DELAYED]:-0}"
_gl_p95="${_gl_v[P95]:-0}"
_gl_max="${_gl_v[MAX]:-0}"

# Status: based on avg-of-delayed (the "when delayed, how bad" metric).
_gl_avg_min=$(( _gl_avg_delayed / 60 ))
if (( _gl_delayed == 0 )); then
    _gl_status="pass"; _gl_sev="info"
elif (( _gl_avg_min >= MAIL_GREYLIST_FAIL_AVG_MIN )); then
    _gl_status="fail"; _gl_sev="medium"
elif (( _gl_avg_min >= MAIL_GREYLIST_WARN_AVG_MIN )); then
    _gl_status="warn"; _gl_sev="low"
else
    _gl_status="pass"; _gl_sev="info"
fi

_gl_fix=""
if [[ "$_gl_status" != "pass" ]]; then
    _gl_fix="review top senders below — add safe HELO patterns via: plesk bin grey_listing --update-server -domains-whitelist add:<pattern>"
fi

emit "health.greylist.delay" "$_gl_sev" "$_gl_status" \
    "${MAIL_GREYLIST_DAYS}d: ${_gl_total} delivered, ${_gl_delayed} delayed (${_gl_pct}%), avg-of-delayed $(_gl_format_min "$_gl_avg_delayed"), p95 $(_gl_format_min "$_gl_p95"), max $(_gl_format_min "$_gl_max")" \
    "$_gl_fix"

# Top-N sender domains by recurrence (count desc, then avg desc).
# Recurring senders are the actionable whitelist candidates; one-off long
# delays are typically spam senders that eventually retried.
mapfile -t _gl_tops < <(grep '^TOP|' <<< "$_gl_result" \
    | sort -t'|' -k3,3 -rn -k4,4 -rn | head -n "$MAIL_GREYLIST_TOP_N")

if (( ${#_gl_tops[@]} > 0 )); then
    table_init "Sender domain" "Count" "Avg delay" "Max delay"
    for _gl_row in "${_gl_tops[@]}"; do
        IFS='|' read -r _ _gl_dom _gl_c _gl_avg _gl_dmax <<< "$_gl_row"
        _gl_label="$(truncate "$_gl_dom" 32)"
        _gl_avg_h="$(_gl_format_min "$_gl_avg")"
        _gl_max_h="$(_gl_format_min "$_gl_dmax")"
        table_row "$_gl_label" "$_gl_c" "$_gl_avg_h" "$_gl_max_h"
    done
    table_render
fi
