# plesk-toolbox

A collection of command-line tools for daily operations on Plesk servers.

Three-pillar architecture: **audits** (read-only checks), **tools**
(imperative utilities and fix scripts), **mods** (persistent system
customisations like a replacement MOTD dashboard).

## Install

```bash
git clone https://github.com/dmnk-rdr/plesk-toolbox
cd plesk-toolbox
sudo ./install.sh
```

The installer:

- Copies sources to `/opt/plesk-toolbox/`
- Creates `plesk-toolbox`, `plesk-audit`, `plesk-sec-audit`, `plesk-tool`,
  `plesk-mod` shims in `/usr/local/bin/`
- Creates runtime dirs (`/var/log/plesk-toolbox/`, `/var/lib/plesk-toolbox/`)
- Writes `/etc/plesk-toolbox.conf` from the example if missing
- Enables the `motd` mod (branded SSH login dashboard)

Update:

```bash
cd plesk-toolbox
git pull
sudo ./install.sh        # idempotent — syncs the new tree to /opt/plesk-toolbox/
```

Uninstall:

```bash
sudo ./install.sh --uninstall
```

## Pillar 1 — audits (read-only)

Structured checks that never modify the system. Output is either human-readable
(PASS/WARN/FAIL with suggested fixes) or JSON for downstream consumption.

```bash
sudo plesk-toolbox audit                    # full audit
sudo plesk-toolbox audit sec                # security only
sudo plesk-toolbox audit health             # health only
sudo plesk-toolbox audit --list             # enumerate available checks
sudo plesk-toolbox audit sec --json > out.json

# Legacy aliases still work:
sudo plesk-sec-audit
sudo plesk-audit
```

### Security checks (`audits.d/sec/`)

- `10-system-ssh` — PermitRootLogin, PasswordAuthentication, Protocol, Port
- `12-system-updates` — pending security updates (apt/dnf)
- `20-network-ports` — externally-bound listeners vs. whitelist
- `30-plesk-panel` — panel 2FA, panel cert, admin email
- `32-plesk-fail2ban` — service, jails, recent ban count
- `50-web-tls` — per-domain certificate expiry
- `54-mail-tls` — per mail-enabled domain: `mail.<d>` on 25/465/587/993/995
  — reachability + cert expiry + hostname match
- `56-mail-mta-sts` — per mail-enabled domain: MTA-STS TXT + policy file
  (RFC 8461) + TLSRPT (RFC 8460)
- `58-mail-autoconfig` — per mail-enabled domain: Thunderbird autoconfig
  (`autoconfig.<d>` or `.well-known`) + Outlook autodiscover
  (`autodiscover.<d>` host or `_autodiscover._tcp` SRV)

All mail-suite audits (`42`, `46`, `54`, `56`, `58`) share one filter:
they enumerate Plesk domains whose mail service is **actually enabled**
(`mail_settings.mail_service='true'`), and self-skip with a single `info`
emit on a server that hosts no mail at all. No false warnings on
web-only servers.

### Health checks (`audits.d/health/`)

- `14-system-memory` — cgroup-aware memory + sw-engine RSS
- `16-system-disk` — per-mountpoint usage + inode pressure
- `18-system-services` — nginx/apache/mariadb/postfix/dovecot/sw-cp-server/psa
- `40-plesk-license` — status and expiry
- `42-mail-hygiene` — per **mail-enabled** domain: SPF/DKIM/DMARC with
  dynamic selector resolution; Null-MX domains (RFC 7505) skipped cleanly
- `46-mail-mailboxes` — per mail-enabled domain: mailbox count + sieve
  sanity (detects Plesk's `fileinto "INBOX"` bug + wrong owner)

## Pillar 2 — tools (imperative utilities + fixes)

Ad-hoc operator utilities. May read or write. Fix scripts live under
`tools.d/fix/` and use the `safety.sh` helpers (optional `--dry-run`, TTY
confirmation, logging, flock).

```bash
# Daily utilities
sudo plesk-tool domain/show example.com            # dump a hosted domain
sudo plesk-tool domain/reissue-cert example.com --with-www
sudo plesk-tool mail/queue-flush --older-than=7d
sudo plesk-tool mail/tail-maillog example.com
sudo plesk-tool mail/spam-top-senders
sudo plesk-tool plesk/slow-queries
sudo plesk-tool plesk/sw-engine-rss
sudo plesk-tool system/top-open-files

# Fix scripts — dry-run optional
sudo plesk-tool fix/plesk-repair-mail --dry-run    # describe only
sudo plesk-tool fix/plesk-repair-mail              # prompts on TTY
sudo plesk-tool fix/postfix-tls-policy --yes       # non-interactive
sudo plesk-tool fix/letsencrypt-renew-all

sudo plesk-toolbox tool --list                     # enumerate tools
```

Every tool invocation appends a JSONL line to
`/var/log/plesk-toolbox/tool.log` (`ts`, `user`, `tty`, `id`, `args`,
`result`, `duration_s`, `dry_run`).

## Pillar 3 — mods (persistent system customisations)

Each mod is a self-contained directory with `install.sh` and `uninstall.sh`.
Enabling a mod writes a manifest to `/var/lib/plesk-toolbox/mods/<name>.manifest`
that tracks every file it created, linked, or hid — so disabling cleanly
reverses exactly those operations.

```bash
sudo plesk-mod list                   # status of every mod
sudo plesk-mod status motd            # files owned by this mod
sudo plesk-mod enable motd
sudo plesk-mod disable motd
```

### `motd` mod — SSH login dashboard

Replaces the default Debian/Ubuntu MOTD with a branded dashboard showing OS,
kernel, uptime, IPs, memory/disk bars, critical service status, pending
updates, fail2ban jails, and recent logins. Slow data (updates count, public
IP, last logins) is prerendered every 10 min via a systemd timer into
`/var/cache/server-motd/`, so SSH login stays fast.

Noisy defaults (`10-uname`, `50-motd-news`, `90-updates-available`, etc.) are
**renamed** to `.disabled-*` rather than deleted, so `plesk-mod disable motd`
restores them.

## Configuration

See [`plesk-toolbox.conf.example`](plesk-toolbox.conf.example) for all
tunables: port whitelists, memory/disk thresholds, severity overrides (for
"I accept this risk" cases), MOTD branding, and more.

## Requirements

- Debian 11/12, Ubuntu 22.04/24.04, or RHEL-family with Plesk Obsidian
- `bash`, `coreutils`, `ss`, `openssl`, `systemctl` — all standard
- Optional: `testssl.sh` for richer TLS audits, `sqlite3` for fail2ban history,
  `pt-query-digest` or `mysqldumpslow` for nicer slow-query summaries

## Architecture

```
plesk-toolbox/
├── bin/
│   ├── plesk-toolbox          # subcommand dispatcher
│   ├── plesk-audit            # shim → audit
│   ├── plesk-sec-audit        # shim → audit sec
│   ├── plesk-tool             # shim → tool
│   ├── plesk-mod              # shim → mod
│   └── server-motd-refresh    # systemd timer worker
├── lib/
│   ├── common.sh              # emit API, formatting, config loading
│   ├── plesk.sh               # plesk CLI helpers, domain enumeration
│   ├── tls.sh                 # testssl.sh / openssl wrapper
│   ├── dispatch.sh            # top-level subcommand router
│   ├── runner.sh              # audits.d/ + tools.d/ loader
│   ├── safety.sh              # dry-run, confirm, lock, reversible ops
│   └── logging.sh             # JSONL log writer
├── audits.d/
│   ├── sec/                   # NN-<group>-<name>.sh
│   └── health/
├── tools.d/
│   ├── fix/                   # opt-in --dry-run, confirmation, logging
│   ├── mail/
│   ├── domain/
│   ├── plesk/
│   └── system/
├── mods.d/
│   └── motd/
│       ├── install.sh
│       ├── uninstall.sh
│       └── sections/          # /etc/update-motd.d/ targets
├── share/
│   ├── systemd/
│   └── completion/
├── install.sh
└── plesk-toolbox.conf.example
```

Adding a new check: drop `audits.d/<pillar>/NN-<group>-<name>.sh` — no installer
edit required, the runner auto-discovers.

Adding a new tool: drop `tools.d/<group>/<name>.sh` with a `main()` function;
source `lib/safety.sh` and use `tool_begin`/`tool_confirm`/`tool_run`/`tool_end`
if the tool writes.

Adding a new mod: create `mods.d/<name>/{install,uninstall}.sh` and use
`hide_file`/`restore_file` for reversible system changes.

## License

MIT
