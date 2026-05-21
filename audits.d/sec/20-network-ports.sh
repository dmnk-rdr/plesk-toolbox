# audits.d/sec/20-network-ports.sh - externally-bound listening ports
section "security: listening ports"

: "${EXPECTED_PORTS:=21 22 25 53 80 110 143 443 465 587 993 995 4190 4643 8443 8447 8880}"

if ! command -v ss >/dev/null 2>&1; then
    emit "sec.network.listening_ports" "medium" "skip" "ss(8) not available"
    return 0
fi

# Collect externally-bound TCP listening ports (not 127.0.0.1, not ::1)
external_ports="$(ss -tlnH 2>/dev/null \
    | awk '{print $4}' \
    | awk -F: '{print $NF, $0}' \
    | awk '$2 !~ /^127\./ && $2 !~ /^\[::1\]/ {print $1}' \
    | sort -un)"

unexpected=""
for p in $external_ports; do
    if ! grep -qw "$p" <<< "$EXPECTED_PORTS"; then
        unexpected+="${p} "
    fi
done

if [[ -z "$unexpected" ]]; then
    emit "sec.network.listening_ports" "medium" "pass" \
        "all externally-bound ports in whitelist"
else
    emit "sec.network.listening_ports" "medium" "warn" \
        "unexpected open ports: ${unexpected% }" \
        "review or add to EXPECTED_PORTS in /etc/plesk-toolbox.conf"
fi

# Report a count of local-only services for context
local_count="$(ss -tlnH 2>/dev/null | awk '$4 ~ /^(127\.|\[::1\])/' | wc -l)"
emit "sec.network.listening_local" "info" "pass" "${local_count} local-only listeners"
