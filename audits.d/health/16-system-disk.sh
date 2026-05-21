# audits.d/health/16-system-disk.sh - disk and inode usage
section "health: disk"

: "${DISK_WARN_PCT:=80}"
: "${DISK_FAIL_PCT:=92}"

while read -r fs size used avail pct mount; do
    [[ "$fs" == "Filesystem" ]] && continue
    [[ -z "$mount" ]] && continue
    # Skip pseudo filesystems
    case "$fs" in tmpfs|devtmpfs|udev|overlay*) continue ;; esac
    p="${pct%%%}"
    [[ "$p" =~ ^[0-9]+$ ]] || continue
    msg="${mount}: ${used}/${size} used (${pct})"
    id="health.system.disk_${mount//\//_}"
    if (( p >= DISK_FAIL_PCT )); then
        emit "$id" "high" "fail" "$msg" "free space or expand the filesystem"
    elif (( p >= DISK_WARN_PCT )); then
        emit "$id" "medium" "warn" "$msg"
    else
        emit "$id" "info" "pass" "$msg"
    fi
done < <(df -hPT -x tmpfs -x devtmpfs -x squashfs 2>/dev/null \
         | awk 'NR==1 || $2!="tmpfs" {print $1,$3,$4,$5,$6,$7}')

# Inode check on / only (most common exhaustion spot)
if inode_line="$(df -iP / 2>/dev/null | tail -1)"; then
    ipct="$(awk '{print $5}' <<< "$inode_line")"
    ip="${ipct%%%}"
    if [[ "$ip" =~ ^[0-9]+$ ]]; then
        if   (( ip >= 95 )); then emit "health.system.disk_inodes_root" "high" "fail" "inode usage on /: ${ipct}"
        elif (( ip >= 85 )); then emit "health.system.disk_inodes_root" "medium" "warn" "inode usage on /: ${ipct}"
        else                      emit "health.system.disk_inodes_root" "info" "pass" "inode usage on /: ${ipct}"
        fi
    fi
fi
