# audits.d/health/18-system-services.sh - critical Plesk service status
section "health: critical services"

: "${CRITICAL_SERVICES:=nginx apache2 mariadb mysql postfix dovecot sw-cp-server psa}"

# Some services are packaged under different unit names depending on distro
# (Debian/Ubuntu vs CentOS/RHEL). Resolve to whichever unit actually exists.
declare -A _SVC_ALIASES=(
    [apache2]="apache2 httpd"
    [httpd]="httpd apache2"
    [mariadb]="mariadb mysql mysqld"
    [mysql]="mysql mariadb mysqld"
)

_unit_exists() {
    systemctl list-unit-files --type=service 2>/dev/null \
        | awk '{print $1}' | grep -qx "$1.service"
}

# Echoes the first installed unit name from the alias list, or empty.
_resolve_unit() {
    local name="$1"
    local candidates="${_SVC_ALIASES[$name]:-$name}"
    local c
    for c in $candidates; do
        _unit_exists "$c" && { printf '%s' "$c"; return 0; }
    done
    return 1
}

for svc in $CRITICAL_SERVICES; do
    if ! unit="$(_resolve_unit "$svc")"; then
        emit "health.system.svc_${svc}" "info" "skip" "${svc}: not installed"
        continue
    fi
    if systemctl is-active --quiet "$unit" 2>/dev/null; then
        emit "health.system.svc_${svc}" "high" "pass" "${unit}: active"
    else
        state="$(systemctl is-active "$unit" 2>/dev/null || echo unknown)"
        emit "health.system.svc_${svc}" "high" "fail" "${unit}: ${state}" \
            "systemctl status ${unit} ; journalctl -u ${unit} -n 50"
    fi
done
