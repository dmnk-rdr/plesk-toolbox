# audits.d/health/46-mail-mailboxes.sh - mailbox inventory + sieve sanity
# shellcheck source=../../lib/plesk.sh
. "${PTBOX_ROOT}/lib/plesk.sh"

section "health: mailbox inventory"

: "${MAIL_MAILBOX_MAX_DOMAINS:=50}"
: "${MAIL_SIEVE_CHECK:=1}"

if ! _plesk_available; then
    emit "health.mail.mailboxes" "medium" "skip" "plesk CLI not available"
    return 0
fi

if ! _plesk_mail_in_use; then
    emit "health.mail.mailboxes" "info" "skip" "mail subsystem not in use on this server"
    return 0
fi

mapfile -t domains < <(_plesk_mail_domains 2>/dev/null || true)
(( ${#domains[@]} > 0 )) || { emit "health.mail.mailboxes" "info" "skip" "no mail-enabled domains"; return 0; }

total_mailboxes=0
total_sieve_bug=0
total_sieve_owner=0
checked=0

for d in "${domains[@]}"; do
    (( checked >= MAIL_MAILBOX_MAX_DOMAINS )) && break
    checked=$((checked + 1))

    mapfile -t boxes < <(_plesk_mailboxes "$d" 2>/dev/null || true)
    n=${#boxes[@]}
    total_mailboxes=$((total_mailboxes + n))

    if (( n == 0 )); then
        emit "health.mail.mailbox_count.${d}" "info" "pass" "${d}: 0 mailboxes (mail-enabled, no users)"
        continue
    fi

    emit "health.mail.mailbox_count.${d}" "info" "pass" "${d}: ${n} mailboxes"

    (( MAIL_SIEVE_CHECK == 1 )) || continue

    # Per-mailbox sieve sanity. Roll up the failure set into one finding
    # per domain to avoid emit explosion on big servers.
    bad_inbox=()
    bad_owner=()
    for u in "${boxes[@]}"; do
        sieve="$(_plesk_sieve_path "$d" "$u")"
        [[ -r "$sieve" ]] || continue

        # Plesk bug: `fileinto "INBOX"` instead of `fileinto "INBOX.Spam"` →
        # spam ends up in the inbox. Detect any naked-INBOX fileinto.
        if grep -qE 'fileinto[[:space:]]+"INBOX"' "$sieve" 2>/dev/null; then
            bad_inbox+=("${u}")
        fi

        # Owner sanity: Plesk expects popuser:popuser. A wrong owner usually
        # means a tool ran as root and forgot to chown — Dovecot may then
        # silently fall back to the global filter.
        owner="$(stat -c '%U:%G' "$sieve" 2>/dev/null || echo "")"
        if [[ -n "$owner" && "$owner" != "popuser:popuser" ]]; then
            bad_owner+=("${u}(${owner})")
        fi
    done

    if (( ${#bad_inbox[@]} > 0 )); then
        total_sieve_bug=$((total_sieve_bug + ${#bad_inbox[@]}))
        emit "health.mail.sieve_inbox.${d}" "medium" "warn" \
            "${d}: sieve uses fileinto \"INBOX\" for ${#bad_inbox[@]} mailbox(es): ${bad_inbox[*]}" \
            "change to fileinto \"INBOX.Spam\" (or \"Spam\" on prefix='') and run sievec"
    fi
    if (( ${#bad_owner[@]} > 0 )); then
        total_sieve_owner=$((total_sieve_owner + ${#bad_owner[@]}))
        emit "health.mail.sieve_owner.${d}" "low" "warn" \
            "${d}: ${#bad_owner[@]} sieve file(s) with wrong owner: ${bad_owner[*]}" \
            "chown popuser:popuser /var/qmail/mailnames/${d}/<user>/sieve/.dovecot.sieve"
    fi
done

emit "health.mail.mailbox_total" "info" "pass" \
    "${total_mailboxes} mailboxes across ${checked} domains"

if (( MAIL_SIEVE_CHECK == 1 && (total_sieve_bug + total_sieve_owner) == 0 )); then
    emit "health.mail.sieve_all" "info" "pass" "all sieve scripts look sane"
fi
