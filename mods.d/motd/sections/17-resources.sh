#!/usr/bin/env bash
# motd section: memory and disk usage bars
PTBOX_ROOT="${PTBOX_ROOT:-/opt/plesk-toolbox}"
# shellcheck source=../../../lib/common.sh
. "${PTBOX_ROOT}/lib/common.sh" 2>/dev/null || exit 0

# Memory (cgroup-aware)
total_kb=0; used_kb=0
if [[ -r /sys/fs/cgroup/memory.max ]]; then
    max="$(cat /sys/fs/cgroup/memory.max 2>/dev/null)"
    if [[ "$max" != "max" && -n "$max" ]]; then
        total_kb=$(( max / 1024 ))
        used_kb=$(( $(cat /sys/fs/cgroup/memory.current 2>/dev/null || echo 0) / 1024 ))
    fi
fi
if (( total_kb == 0 )); then
    total_kb="$(awk '/^MemTotal:/  {print $2}' /proc/meminfo)"
    avail_kb="$(awk '/^MemAvailable:/{print $2}' /proc/meminfo)"
    used_kb=$(( total_kb - avail_kb ))
fi
pct=$(( used_kb * 100 / total_kb ))

printf '\n'
printf '  %s%-14s%s %s  %s / %s\n' \
    "${C_DIM:-}" "memory" "${C_RST:-}" \
    "$(bar "$pct" 28 80 92)" \
    "$(hr_bytes $(( used_kb * 1024 )))" \
    "$(hr_bytes $(( total_kb * 1024 )))"

# Disk: show the root filesystem and /var if separate
for mount in / /var; do
    if ! mountpoint -q "$mount" 2>/dev/null && [[ "$mount" != "/" ]]; then
        continue
    fi
    line="$(df -hP "$mount" 2>/dev/null | tail -1)"
    [[ -z "$line" ]] && continue
    read -r _ size used _ pct _ <<< "$line"
    dp="${pct%%%}"
    [[ "$dp" =~ ^[0-9]+$ ]] || continue
    printf '  %s%-14s%s %s  %s / %s\n' \
        "${C_DIM:-}" "disk $mount" "${C_RST:-}" \
        "$(bar "$dp" 28 80 92)" \
        "$used" "$size"
done
