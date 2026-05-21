# audits.d/sec/10-system-ssh.sh - SSH hardening checks
section "security: SSH"

sshd_conf="/etc/ssh/sshd_config"
if [[ ! -r "$sshd_conf" ]]; then
    emit "sec.system.ssh_config" "high" "skip" "$sshd_conf not readable"
    return 0
fi

# Effective settings via sshd -T if available, else parse the file
_ssh_get() {
    local key="$1"
    if command -v sshd >/dev/null 2>&1; then
        sshd -T 2>/dev/null | awk -v k="${key,,}" 'tolower($1)==k {print $2; exit}'
    else
        awk -v k="${key}" 'BEGIN{IGNORECASE=1} $1==k {print $2; exit}' "$sshd_conf"
    fi
}

# PermitRootLogin: prohibit-password or no (yes = fail)
root_login="$(_ssh_get PermitRootLogin)"
case "${root_login,,}" in
    no|prohibit-password|without-password)
        emit "sec.system.ssh_root_login" "high" "pass" "PermitRootLogin=${root_login}"
        ;;
    yes|"")
        emit "sec.system.ssh_root_login" "high" "fail" \
            "PermitRootLogin=${root_login:-unset}" \
            "set 'PermitRootLogin prohibit-password' in $sshd_conf"
        ;;
    *)
        emit "sec.system.ssh_root_login" "medium" "warn" "PermitRootLogin=${root_login}"
        ;;
esac

# PasswordAuthentication: should be no on a key-authenticated server
pwd_auth="$(_ssh_get PasswordAuthentication)"
case "${pwd_auth,,}" in
    no)
        emit "sec.system.ssh_password_auth" "high" "pass" "PasswordAuthentication=no"
        ;;
    yes|"")
        emit "sec.system.ssh_password_auth" "high" "warn" \
            "PasswordAuthentication=${pwd_auth:-unset}" \
            "consider key-only auth: 'PasswordAuthentication no' once keys are deployed"
        ;;
esac

# Port: non-default is a weak obscurity win but we just report
port="$(_ssh_get Port)"
if [[ -n "$port" && "$port" != "22" ]]; then
    emit "sec.system.ssh_port" "info" "pass" "SSH listening on non-default port ${port}"
else
    emit "sec.system.ssh_port" "info" "pass" "SSH on default port 22"
fi

# Protocol 2 only (defaulted since OpenSSH 7, but check anyway)
protocol="$(_ssh_get Protocol)"
if [[ -z "$protocol" || "$protocol" == "2" ]]; then
    emit "sec.system.ssh_protocol" "medium" "pass" "SSH protocol 2"
else
    emit "sec.system.ssh_protocol" "high" "fail" "SSH protocol=${protocol}" \
        "remove 'Protocol 1' from $sshd_conf"
fi
