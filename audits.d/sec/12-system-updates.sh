# audits.d/sec/12-system-updates.sh - pending security updates
section "security: package updates"

if command -v apt-get >/dev/null 2>&1; then
    # -s simulation, no locking, no network fetch
    out="$(apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null || true)"
    total="$(awk '/^Inst/ {c++} END {print c+0}' <<< "$out")"
    security="$(awk '/^Inst.*-security/ {c++} END {print c+0}' <<< "$out")"
    if (( security > 0 )); then
        emit "sec.system.updates_security" "high" "fail" \
            "${security} security updates pending" \
            "run: apt-get update && apt-get upgrade"
    elif (( total > 0 )); then
        emit "sec.system.updates_security" "low" "warn" \
            "${total} non-security updates pending"
    else
        emit "sec.system.updates_security" "high" "pass" "no pending updates"
    fi
elif command -v dnf >/dev/null 2>&1; then
    if dnf -q updateinfo list security 2>/dev/null | grep -q .; then
        count="$(dnf -q updateinfo list security 2>/dev/null | wc -l)"
        emit "sec.system.updates_security" "high" "fail" \
            "${count} security updates pending" \
            "run: dnf upgrade --security"
    else
        emit "sec.system.updates_security" "high" "pass" "no pending security updates"
    fi
else
    emit "sec.system.updates_security" "medium" "skip" "no supported package manager found"
fi
