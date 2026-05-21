# audits.d/health/14-system-memory.sh - memory pressure (cgroup-aware)
section "health: memory"

: "${MEM_WARN_PCT:=85}"
: "${MEM_FAIL_PCT:=95}"

# Prefer cgroup v2 memory.max if present and set (container/VPS-aware)
total_kb=0
used_kb=0
source=""

if [[ -r /sys/fs/cgroup/memory.max && -r /sys/fs/cgroup/memory.current ]]; then
    max="$(cat /sys/fs/cgroup/memory.max 2>/dev/null)"
    if [[ "$max" != "max" && -n "$max" ]]; then
        total_kb=$(( max / 1024 ))
        cur="$(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo 0)"
        used_kb=$(( cur / 1024 ))
        source="cgroup-v2"
    fi
fi

if [[ -z "$source" ]]; then
    # fall back to /proc/meminfo
    total_kb="$(awk '/^MemTotal:/  {print $2}' /proc/meminfo)"
    avail_kb="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
    used_kb=$(( total_kb - avail_kb ))
    source="proc-meminfo"
fi

(( total_kb > 0 )) || { emit "health.system.memory" "medium" "skip" "could not determine memory"; return 0; }

pct=$(( used_kb * 100 / total_kb ))
total_bytes=$(( total_kb * 1024 ))
used_bytes=$(( used_kb * 1024 ))
total_hr="$(hr_bytes "$total_bytes")"
used_hr="$(hr_bytes "$used_bytes")"

msg="${used_hr} / ${total_hr} (${pct}%, ${source})"
if (( pct >= MEM_FAIL_PCT )); then
    emit "health.system.memory" "high" "fail" "$msg" "investigate top consumers: ps aux --sort=-rss | head"
elif (( pct >= MEM_WARN_PCT )); then
    emit "health.system.memory" "medium" "warn" "$msg"
else
    emit "health.system.memory" "info" "pass" "$msg"
fi

# Plesk sw-engine RSS: a common memory hog
if command -v pgrep >/dev/null 2>&1 && pgrep -x sw-engine >/dev/null 2>&1; then
    sw_total_kb="$(ps -C sw-engine -o rss= 2>/dev/null | awk '{s+=$1} END{print s+0}')"
    sw_total_bytes=$(( sw_total_kb * 1024 ))
    sw_pct=$(( sw_total_kb * 100 / total_kb ))
    msg="sw-engine RSS: $(hr_bytes "$sw_total_bytes") (${sw_pct}% of memory)"
    if (( sw_pct >= 30 )); then
        emit "health.system.sw_engine_rss" "medium" "warn" "$msg" \
            "consider systemctl restart sw-engine during low traffic"
    else
        emit "health.system.sw_engine_rss" "info" "pass" "$msg"
    fi
fi
