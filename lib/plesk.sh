# lib/plesk.sh - Plesk-specific helpers
[[ -n "${__PTBOX_PLESK_LOADED:-}" ]] && return 0
__PTBOX_PLESK_LOADED=1

_plesk_available() {
    command -v plesk >/dev/null 2>&1
}

# Cached list of hosted domains (one per line), honors $IGNORE_DOMAINS (space-sep)
_PLESK_DOMAINS_CACHE=""
_plesk_domains() {
    if [[ -z "$_PLESK_DOMAINS_CACHE" ]]; then
        _plesk_available || { _PLESK_DOMAINS_CACHE="__none__"; return 1; }
        local raw
        raw="$(plesk db -Ne "SELECT d.name FROM domains d \
               JOIN hosting h ON h.dom_id=d.id WHERE d.htype='vrt_hst';" 2>/dev/null)"
        if [[ -z "$raw" ]]; then
            _PLESK_DOMAINS_CACHE="__none__"
            return 1
        fi
        local ignore=" ${IGNORE_DOMAINS:-} "
        local out=""
        while IFS= read -r d; do
            [[ -z "$d" ]] && continue
            [[ "$ignore" == *" $d "* ]] && continue
            out+="$d"$'\n'
        done <<< "$raw"
        _PLESK_DOMAINS_CACHE="${out%$'\n'}"
    fi
    [[ "$_PLESK_DOMAINS_CACHE" == "__none__" ]] && return 1
    printf '%s\n' "$_PLESK_DOMAINS_CACHE"
}

_plesk_vhost_conf_dir() {
    local d="$1"
    # Plesk Onyx+ path; apache vhost conf is here
    printf '/var/www/vhosts/system/%s/conf\n' "$d"
}

_plesk_version() {
    _plesk_available || { echo "unknown"; return 1; }
    plesk version 2>/dev/null | awk -F: '/Product version/ {gsub(/ /,"",$2); print $2}'
}

# Server-wide quick test: is the mail subsystem actually used?
# Returns 0 if any mailbox exists on any hosted domain, 1 otherwise.
_PLESK_MAIL_IN_USE_CACHE=""
_plesk_mail_in_use() {
    if [[ -z "$_PLESK_MAIL_IN_USE_CACHE" ]]; then
        _plesk_available || { _PLESK_MAIL_IN_USE_CACHE="no"; return 1; }
        local n
        n="$(plesk db -Ne "SELECT COUNT(*) FROM mail;" 2>/dev/null || echo 0)"
        if [[ "${n:-0}" =~ ^[0-9]+$ ]] && (( n > 0 )); then
            _PLESK_MAIL_IN_USE_CACHE="yes"
        else
            _PLESK_MAIL_IN_USE_CACHE="no"
        fi
    fi
    [[ "$_PLESK_MAIL_IN_USE_CACHE" == "yes" ]]
}

# Cached list of domains where the Plesk mail service is enabled.
# Filters out IGNORE_DOMAINS like _plesk_domains.
_PLESK_MAIL_DOMAINS_CACHE=""
_plesk_mail_domains() {
    if [[ -z "$_PLESK_MAIL_DOMAINS_CACHE" ]]; then
        _plesk_available || { _PLESK_MAIL_DOMAINS_CACHE="__none__"; return 1; }
        # Primary path: mail_settings.mail_service='true' joined to vrt_hst domains.
        # Fallback: any domain that has at least one row in `mail`.
        local raw
        raw="$(plesk db -Ne "
            SELECT d.name
              FROM domains d
              JOIN mail_settings ms ON ms.domain_id = d.id
             WHERE d.htype = 'vrt_hst'
               AND ms.mail_service = 'true';" 2>/dev/null)"
        if [[ -z "$raw" ]]; then
            raw="$(plesk db -Ne "
                SELECT DISTINCT d.name
                  FROM domains d
                  JOIN mail m ON m.dom_id = d.id
                 WHERE d.htype = 'vrt_hst';" 2>/dev/null)"
        fi
        if [[ -z "$raw" ]]; then
            _PLESK_MAIL_DOMAINS_CACHE="__none__"
            return 1
        fi
        local ignore=" ${IGNORE_DOMAINS:-} "
        local out=""
        while IFS= read -r d; do
            [[ -z "$d" ]] && continue
            [[ "$ignore" == *" $d "* ]] && continue
            out+="$d"$'\n'
        done <<< "$raw"
        _PLESK_MAIL_DOMAINS_CACHE="${out%$'\n'}"
    fi
    [[ "$_PLESK_MAIL_DOMAINS_CACHE" == "__none__" ]] && return 1
    printf '%s\n' "$_PLESK_MAIL_DOMAINS_CACHE"
}

# Mailboxes for a domain (local part only, one per line).
_plesk_mailboxes() {
    local d="$1"
    _plesk_available || return 1
    plesk db -Ne "
        SELECT m.mail_name
          FROM mail m
          JOIN domains dm ON dm.id = m.dom_id
         WHERE dm.name = '${d//\'/\'\'}'
         ORDER BY m.mail_name;" 2>/dev/null
}

# Path to a mailbox's Sieve script (qmail layout used by Plesk).
_plesk_sieve_path() {
    local d="$1" user="$2"
    printf '/var/qmail/mailnames/%s/%s/sieve/.dovecot.sieve\n' "$d" "$user"
}

# Path to a mailbox's .qmail control file (qmail layout used by Plesk).
_plesk_qmail_path() {
    local d="$1" user="$2"
    printf '/var/qmail/mailnames/%s/%s/.qmail\n' "$d" "$user"
}

# Mailgroup forward addresses configured in Plesk DB for a mailbox.
# One address per line; empty output = no forwards configured.
_plesk_mail_forwards() {
    local d="$1" user="$2"
    _plesk_available || return 1
    plesk db -Ne "
        SELECT mr.address
          FROM mail_redir mr
          JOIN mail m      ON m.id = mr.mn_id
          JOIN domains dm  ON dm.id = m.dom_id
         WHERE dm.name = '${d//\'/\'\'}'
           AND m.mail_name = '${user//\'/\'\'}'
         ORDER BY mr.address;" 2>/dev/null
}

# All IPs Plesk knows about — authoritative source for "this server's IPs".
# Cached. Output: one IP per line (both v4 and v6).
_PLESK_SERVER_IPS_CACHE=""
_plesk_server_ips() {
    if [[ -z "$_PLESK_SERVER_IPS_CACHE" ]]; then
        local raw=""
        if _plesk_available; then
            raw="$(plesk db -Ne "SELECT ip_address FROM IP_Addresses;" 2>/dev/null)"
        fi
        # Fallback: routing-based discovery if DB query came up empty.
        if [[ -z "$raw" ]]; then
            local v4 v6
            v4="$(ip -4 -o route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
            v6="$(ip -6 -o route get 2606:4700:4700::1111 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
            raw="$(printf '%s\n%s\n' "$v4" "$v6")"
        fi
        _PLESK_SERVER_IPS_CACHE="$(printf '%s\n' "$raw" | awk 'NF')"
    fi
    [[ -n "$_PLESK_SERVER_IPS_CACHE" ]] && printf '%s\n' "$_PLESK_SERVER_IPS_CACHE"
}

# Path to a domain's local DKIM private key (Plesk Obsidian layout).
_plesk_dkim_key_path() {
    local d="$1" sel="${2:-default}"
    printf '/etc/domainkeys/%s/%s\n' "$d" "$sel"
}
