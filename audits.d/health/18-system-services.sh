# audits.d/health/18-system-services.sh - critical Plesk service status
section "health: critical services"

: "${CRITICAL_SERVICES:=nginx apache2 mariadb mysql postfix dovecot sw-cp-server psa}"

for svc in $CRITICAL_SERVICES; do
    # Does the unit exist at all?
    if ! systemctl list-unit-files --type=service 2>/dev/null | awk '{print $1}' | grep -qx "${svc}.service"; then
        emit "health.system.svc_${svc}" "info" "skip" "${svc}: not installed"
        continue
    fi
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        emit "health.system.svc_${svc}" "high" "pass" "${svc}: active"
    else
        state="$(systemctl is-active "$svc" 2>/dev/null || echo unknown)"
        emit "health.system.svc_${svc}" "high" "fail" "${svc}: ${state}" \
            "systemctl status ${svc} ; journalctl -u ${svc} -n 50"
    fi
done
