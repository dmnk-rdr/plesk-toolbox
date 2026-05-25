# plesk-toolbox

> **Day-2 operations toolkit for Plesk servers** — the bits the panel doesn't give you.

[![Shell](https://img.shields.io/badge/shell-bash%204%2B-4EAA25?logo=gnubash&logoColor=white)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/platform-Debian%20%7C%20Ubuntu%20%7C%20RHEL-orange)](#requirements)
[![Plesk](https://img.shields.io/badge/Plesk-Obsidian-1175c1)](https://www.plesk.com/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](#license)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)

Plesk is great for provisioning. **Day-2 operations** — the part where you keep
the box healthy, certificates fresh, mail reputation intact, and surprises
out of the on-call rotation — is mostly left as an exercise for the operator.

`plesk-toolbox` is the toolkit a Plesk-running sysadmin builds for themselves
over the years, packaged up: read-only audits, ad-hoc tools, and a handful of
opt-in system mods. Built to be **safe to run on production** (audits are
read-only, tools support `--dry-run`, mods are fully reversible), **easy to
extend** (drop a file in a directory, no installer edit), and **honest about
what it changed** (everything writes a JSONL audit log).

---

## ✨ Highlights

- 🛡️ **Security audit** — SSH hardening, fail2ban, panel 2FA, exposed ports,
  TLS expiry on every domain, the 9 OWASP HTTP response headers (skipping
  vhosts that still serve Plesk's "Domain Default page"), MTA-STS,
  mail-client autoconfig + autodiscover, webmail reachability …
- 💚 **Health audit** — memory/disk pressure, critical services
  (auto-aliases `apache2`↔`httpd`/`mariadb`↔`mysql`), Plesk license expiry,
  consolidated mail hygiene (SPF + DKIM + DMARC + mailbox sieve sanity)
  per domain in a single coloured table — with a **details:** block under
  every table listing exactly which mailbox / setting tripped each ⚠/✗
- 🔧 **Operator tools** — flush the mail queue, tail one domain's maillog,
  reissue a Let's Encrypt cert with `www`, hunt top spam senders, dump slow
  MySQL queries, **rotate weak/stale DKIM keys with zero signing-gap** — all
  logged, all reversible where it matters
- 🎨 **MOTD mod** — replace the noisy default SSH login banner with a clean
  branded dashboard (services, mem/disk bars, recent logins, pending updates)
- 📋 **Structured output** — human-readable tables on a TTY, `--json` for
  Prometheus exporters, log shippers, or your favourite IRC bot
- ❓ **`--help` on every layer** — `plesk-toolbox --help`, `… audit --help`,
  `… tool --help`, **`… tool mail/dkim-rotate --help`** — drill down as far
  as you need
- 🪶 **Zero runtime deps** — stock `bash`, `coreutils`, `openssl`,
  `systemctl`. No Python, no Ruby, no agents.

## 📸 What it looks like

```
== health: mail hygiene ==
  Domain          SPF     DKIM      DMARC     Mailboxes
  ──────────────  ──────  ────────  ────────  ─────────
  example.com     ✓ -all  ✓ 2048b   ✓ reject  ✓ 8
  example.org     ✓ -all  ✓ 2048b   ⚠ p=none  ✓ 23
  example.net     ⚠ ~all  ✗ stale   ✓ quar    ⚠ 5
  acme.test       ✗ miss  ✓ 1024b   ✗ miss    · 0

  details:
    ⚠ example.org: spf=pass dkim=pass dmarc=warn mbx=pass/23
      ↳ DMARC policy is p=none — collect rua= reports for a few weeks,
        then move to p=quarantine
    ✗ example.net: spf=pass dkim=fail dmarc=warn mbx=warn/5
      ↳ DNS pubkey doesn't match local key — republish
        default._domainkey.example.net TXT |
        sieve fileinto "INBOX" bug in 1 mailbox(es): marketing
        — change to "INBOX.Spam"

== security: web response headers ==
  Domain          HSTS   XFO     XCTO   CSP     RP      PP      COOP    COEP    CORP
  ──────────────  ─────  ──────  ─────  ──────  ──────  ──────  ──────  ──────  ───────
  example.com     ✓ 1y   ✓ SAME  ✓ set  ✓ set   ✓ set   ✓ set   ✓ set   ✗ miss  ✓ set
  example.org     ⚠ 6mo  ✓ DENY  ✓ set  ✗ miss  ⚠ unsa  ✗ miss  ✗ miss  ✗ miss  ⚠ cross
  legacy.example  · default
  example.net     ✓ 1y   ✓ SAME  ✓ set  ✓ set   ✓ set   ✓ set   ✗ miss  ✗ miss  ✓ set

== security: mail webmail ==
  Domain          DNS     TLS      Webmail
  ──────────────  ──────  ───────  ─────────
  example.com     ✓ A     ✓ valid  ✓ roundcube
  example.org     ✓ A     ⚠ self   ⚠ default
  example.net     ⚠ miss  · n/a    · n/a

summary: 47 pass  9 warn  3 fail  2 skip
```

Exit code is non-zero when anything fails — pipe it into cron with confidence.

---

## 🚀 Quick start

```bash
git clone https://github.com/dmnk-rdr/plesk-toolbox
cd plesk-toolbox
sudo ./install.sh
sudo plesk-toolbox audit          # full audit, takes 5-30s depending on domain count
```

The installer is **idempotent** — run it again to update; nothing is overwritten
that you customised.

- Copies sources to `/opt/plesk-toolbox/`
- Adds shims in `/usr/local/bin/`: `plesk-toolbox`, `plesk-audit`,
  `plesk-sec-audit`, `plesk-tool`, `plesk-mod`
- Creates `/var/log/plesk-toolbox/` and `/var/lib/plesk-toolbox/`
- Writes `/etc/plesk-toolbox.conf` from the example **if missing** (your edits
  survive future installs)
- Enables the `motd` mod by default (disable with `sudo plesk-mod disable motd`
  if you want to keep the default Debian/Ubuntu MOTD)

**Update:**

```bash
cd plesk-toolbox && git pull && sudo ./install.sh
```

**Uninstall** (restores any files the mods replaced):

```bash
sudo ./install.sh --uninstall
```

---

## 🎯 Day-2 operations in practice

A few realistic scenarios this toolkit was built for:

### "Is anything on fire?"

The 5-second answer before your coffee gets cold.

```bash
sudo plesk-toolbox audit             # full coloured report, exit 1 on failures
```

Wire it into cron with `--json` and pipe to your alerting:

```bash
0 7 * * * /usr/local/bin/plesk-toolbox audit --json | jq '.results[] | select(.status=="fail")'
```

### "Why did Outlook stop autoconfiguring for one domain?"

```bash
sudo plesk-toolbox audit sec/mail            # autoconfig + autodiscover + webmail
# The details: block under the table tells you exactly which subdomain or
# record is missing per affected domain.
```

### "Mail queue is backed up after a network blip"

```bash
sudo plesk-tool mail/queue-flush --older-than=4h --dry-run    # show what would go
sudo plesk-tool mail/queue-flush --older-than=4h              # actually flush
```

### "Customer says their cert is expiring"

```bash
sudo plesk-tool domain/show example.com                       # who owns it, where it lives
sudo plesk-tool domain/reissue-cert example.com --with-www    # reissue from Let's Encrypt
```

### "DKIM stopped validating yesterday"

The single most common Plesk mail bug: the panel rotated the key locally
but the new public key never made it to DNS — especially when the zone
lives on an external provider Plesk can't update directly (AutoDNS,
Cloudflare, registrar's web UI).

```bash
sudo plesk-toolbox audit health/mail
# Each warning row now expands in the "details:" block below the table:
#   ✗ example.com — DNS pubkey doesn't match local key — republish
#     default._domainkey.example.com TXT
```

Get the *exact* record to publish, byte-for-byte:

```bash
sudo plesk-tool mail/dkim-show example.com
# Prints a copy-paste-ready block:
#
#   Publish this DNS record:
#     name  default._domainkey.example.com
#     type  TXT
#     value (copy the line below, single string):
#   ────────────────────────────────────────────────────────────
#   v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG…IDAQAB
#   ────────────────────────────────────────────────────────────
```

Or, for a bulk migration sweep:

```bash
sudo plesk-tool mail/dkim-show-all          # only the problem domains
sudo plesk-tool mail/dkim-show-all --all    # also the passing ones
```

If the local key is *weak* (≤1024-bit), don't downgrade DNS — rotate to a
fresh 2048-bit key with **zero signing-gap**:

```bash
sudo plesk-tool mail/dkim-rotate example.com
#  → generates default.new alongside the live key
#  → prints the new TXT record to publish
#  → live key keeps signing while DNS propagates
```

Publish the printed TXT in your DNS provider, then once propagated:

```bash
sudo plesk-tool mail/dkim-verify example.com           # confirm DNS = staged key
sudo plesk-tool mail/dkim-rotate example.com --activate
#  → re-verifies DNS one last time, takes a timestamped backup of the
#    old key, atomic-swaps, restarts pc-remote + postfix
#  → refuses to swap if DNS still doesn't match (safety check)
```

End-to-end check (sends a signed mail through the port25 verifier):

```bash
sudo plesk-tool mail/dkim-verify example.com --verifier --from postmaster@example.com
```

### "Quick visual on this new server"

After installing the `motd` mod, every SSH login starts with:

```
  Acme Hosting · Managed Server
  ───────────────────────────────────────────
  OS:      Debian 12 (bookworm)         Plesk: Obsidian 18.0.62
  Uptime:  37 days                      Load:  0.42, 0.55, 0.51

  CPU      ████░░░░░░░░░░░░░░░░░░░░░░░░░░  14%
  Memory   █████████░░░░░░░░░░░░░░░░░░░░░  30% (4.8G / 16G)
  Disk /   ███████░░░░░░░░░░░░░░░░░░░░░░░  24% (47G / 196G)

  ✓ nginx · psa · postfix · dovecot       ✗ — none down
  🛡 fail2ban: 4 jails active, 12 bans in last 24h
  📦 5 pending security updates (apt)
```

### "Audit-trail for a compliance review"

Every tool invocation appends a JSONL line to `/var/log/plesk-toolbox/tool.log`:

```json
{"ts":"2026-05-25T08:14:02Z","user":"alice","tty":"pts/0","id":"mail/queue-flush","args":["--older-than=4h"],"result":"ok","duration_s":1.2,"dry_run":false}
```

Ship it with `vector` / `journalbeat` / `rsyslog imfile` and you have a
permanent record of every operator action.

---

## 🏛️ Architecture: three pillars

The codebase is organised around a clear distinction between **observe**,
**act**, and **change** — so you always know what a command can do before
you run it.

### 🛡️ Pillar 1 — `audits` (read-only)

Structured checks that **never** modify the system. Output is human-readable
(coloured PASS/WARN/FAIL tables with suggested fixes) or machine-readable
(`--json`).

```bash
sudo plesk-toolbox audit                    # full audit (sec + health)
sudo plesk-toolbox audit sec                # security pillar only
sudo plesk-toolbox audit health             # health pillar only
sudo plesk-toolbox audit mail               # mail-related checks across both
sudo plesk-toolbox audit --list             # enumerate available checks
sudo plesk-toolbox audit sec --json > out.json
```

Legacy shims still work: `plesk-sec-audit`, `plesk-audit`.

<details>
<summary><b>Security checks</b> (<code>audits.d/sec/</code>)</summary>

| ID | What it checks |
|----|----------------|
| `10-system-ssh` | PermitRootLogin, PasswordAuthentication, Protocol, Port |
| `12-system-updates` | pending security updates (apt/dnf) |
| `20-network-ports` | externally-bound listeners vs. whitelist |
| `30-plesk-panel` | panel 2FA, panel cert, admin email |
| `32-plesk-fail2ban` | service, jails, recent ban count |
| `50-web-tls` | per-domain certificate expiry on :443 |
| `52-web-security-headers` | per-domain HTTP response headers — HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy, Permissions-Policy, COOP, COEP, CORP. Auto-skips vhosts serving the Plesk "Domain Default page" placeholder (set `WEB_HEADERS_SKIP_DEFAULT_PAGE=0` to keep them) |
| `54-mail-tls` | per mail-enabled domain: `mail.<d>` on 25/465/587/993/995 — reachability + cert expiry + hostname match |
| `56-mail-mta-sts` | MTA-STS TXT + policy file (RFC 8461) + TLSRPT (RFC 8460) |
| `58-mail-autoconfig` | Thunderbird autoconfig (`autoconfig.<d>` or `.well-known`) + Outlook autodiscover (`autodiscover.<d>` host or `_autodiscover._tcp` SRV) |
| `60-mail-webmail` | per mail-enabled domain: `webmail.<d>` DNS + TLS (strict vs. insecure to distinguish self-signed from no-service) + content classification (Roundcube, Horde, SOGo, RainLoop, SnappyMail, AfterLogic, or Plesk default page) |

</details>

<details>
<summary><b>Health checks</b> (<code>audits.d/health/</code>)</summary>

| ID | What it checks |
|----|----------------|
| `14-system-memory` | cgroup-aware memory + sw-engine RSS |
| `16-system-disk` | per-mountpoint usage + inode pressure |
| `18-system-services` | nginx/apache/mariadb/postfix/dovecot/sw-cp-server/psa — aliases `apache2`↔`httpd` and `mariadb`↔`mysql` so the same audit fires on Debian/Ubuntu and CentOS/RHEL |
| `40-plesk-license` | license validity, edition, expiry days from `keyinfo --list` |
| `42-mail-hygiene` | consolidated per-domain table — **SPF** (uniqueness, server-IP coverage, all-qualifier, lookup count, `ptr`), **DKIM** (key bits, DNS↔local byte equality, `p=` revocation, `t=y` flag), **DMARC** (policy strength, `rua=`, multi-record), **Mailboxes** (count + Plesk `fileinto "INBOX"` sieve bug + owner check) |

</details>

All mail-suite audits (`42`, `54`, `56`, `58`, `60`) share one filter:
they only enumerate domains where Plesk's mail service is **actually
enabled** (`mail_settings.mail_service='true'`), and self-skip on a
web-only server. No false warnings on hosts that don't do mail.

**Every table audit prints a `details:` block** under the table that
expands each ⚠/✗ row with the *why* and the *how to fix* — so a
warning in the Mailboxes column isn't just "⚠ 14", it's "sieve
`fileinto \"INBOX\"` bug in mailbox `marketing` — change to
`\"INBOX.Spam\"`".

### 🔧 Pillar 2 — `tools` (imperative utilities + fixes)

Ad-hoc operator utilities. May read or write. Fix scripts under `tools.d/fix/`
use `lib/safety.sh` — they always offer `--dry-run`, prompt before destructive
actions on a TTY, and write a JSONL log line per invocation.

```bash
# Daily utilities
sudo plesk-tool domain/show example.com               # everything about one domain
sudo plesk-tool domain/reissue-cert example.com --with-www
sudo plesk-tool mail/queue-flush --older-than=7d
sudo plesk-tool mail/tail-maillog example.com         # filtered maillog tail
sudo plesk-tool mail/spam-top-senders                 # top abusers
sudo plesk-tool plesk/slow-queries                    # mysql slow log digest
sudo plesk-tool plesk/sw-engine-rss                   # PHP-FPM memory hogs
sudo plesk-tool system/top-open-files

# DKIM operator suite (see "DKIM stopped validating yesterday" recipe above)
sudo plesk-tool mail/dkim-show example.com            # paste-ready TXT for one domain
sudo plesk-tool mail/dkim-show-all                    # same, all problem domains
sudo plesk-tool mail/dkim-verify example.com          # local match-check; --verifier for end-to-end
sudo plesk-tool mail/dkim-rotate example.com          # stage new 2048-bit key (no swap)
sudo plesk-tool mail/dkim-rotate example.com --activate  # swap once DNS confirms

# Fix scripts — dry-run optional, confirmation by default
sudo plesk-tool fix/plesk-repair-mail --dry-run       # describe only
sudo plesk-tool fix/plesk-repair-mail                 # prompts on TTY
sudo plesk-tool fix/postfix-tls-policy --yes          # non-interactive
sudo plesk-tool fix/letsencrypt-renew-all

# Discoverability
sudo plesk-toolbox tool --list                        # enumerate available tools
sudo plesk-toolbox tool mail/dkim-rotate --help       # per-tool usage block
```

**Every tool supports `--help`.** Each one carries an embedded `usage()`
function listing modes, flags, side effects, and (where applicable)
exactly which files it writes and which services it restarts. Tools
without an explicit help block fall back to printing their leading
header comment so you still get a one-paragraph orientation.

### 🎨 Pillar 3 — `mods` (persistent system customisations)

Each mod is a self-contained directory with `install.sh` and `uninstall.sh`.
Enabling a mod writes a manifest to `/var/lib/plesk-toolbox/mods/<name>.manifest`
that tracks every file it created, linked, or hid — so disabling cleanly
reverses exactly those operations. **No "I'm not sure what this did to my system"
moments.**

```bash
sudo plesk-mod list                   # status of every mod (enabled / disabled)
sudo plesk-mod status motd            # files owned by this mod
sudo plesk-mod enable motd
sudo plesk-mod disable motd
```

**`motd` mod — SSH login dashboard.** Replaces the default Debian/Ubuntu MOTD
with a branded dashboard showing OS, kernel, uptime, IPs, memory/disk bars,
critical service status, pending updates, fail2ban jails, and recent logins.
Slow data (updates count, public IP, last logins) is prerendered every 10 min
via a systemd timer into `/var/cache/server-motd/`, so SSH login stays fast.

The default Ubuntu MOTD scripts (`10-uname`, `50-motd-news`,
`90-updates-available`, …) are **renamed** to `.disabled-*` rather than deleted,
so `plesk-mod disable motd` restores them byte-for-byte.

---

## ⚙️ Configuration

All knobs live in `/etc/plesk-toolbox.conf` — start from the comprehensive
[`plesk-toolbox.conf.example`](plesk-toolbox.conf.example).

Most useful options:

- `IGNORE_DOMAINS="legacy.example.com dev.example.com"` — skip noisy domains
- `EXPECTED_PORTS="22 25 80 443 …"` — the port whitelist for the network audit
- `SEVERITY_OVERRIDE_<check_id>="info"` — "I accept this risk" downgrades for
  specific findings (e.g. you deliberately don't run fail2ban: override
  `sec.plesk.panel.fail2ban` to `info`)
- `MAIL_DOMAIN_TRUNCATE=22` — narrow tables for very long domain names
- `MOTD_BRAND="Acme Hosting · Managed Server"` — your brand on the SSH banner

---

## 📦 Requirements

- **OS**: Debian 11/12, Ubuntu 22.04/24.04, or RHEL family with Plesk Obsidian
- **Required**: `bash` 4+, `coreutils`, `ss`, `openssl`, `systemctl` — all standard on a Plesk box
- **Optional**: `testssl.sh` (richer TLS audits), `sqlite3` (fail2ban history),
  `pt-query-digest` or `mysqldumpslow` (nicer slow-query summaries)

No Python, no Ruby, no agents, no outbound calls from the audit path.

---

## 🗂️ Repo layout

```
plesk-toolbox/
├── bin/                      # entry-point shims
│   ├── plesk-toolbox         #   subcommand dispatcher
│   ├── plesk-audit           #   → audit
│   ├── plesk-sec-audit       #   → audit sec
│   ├── plesk-tool            #   → tool
│   ├── plesk-mod             #   → mod
│   └── server-motd-refresh   #   systemd timer worker
├── lib/                      # shared bash libraries
│   ├── common.sh             #   emit API, tables (with auto details:),
│   │                         #   formatting, config loading
│   ├── plesk.sh              #   plesk CLI helpers, domain enumeration
│   ├── dkim.sh               #   DKIM keyfile/pubkey/record helpers
│   ├── tls.sh                #   testssl.sh / openssl wrapper
│   ├── dispatch.sh           #   top-level subcommand router (--help aware)
│   ├── runner.sh             #   audits.d/ + tools.d/ loader (--help aware)
│   ├── safety.sh             #   dry-run, confirm, lock, reversible ops
│   └── logging.sh            #   JSONL log writer
├── audits.d/
│   ├── sec/                  # NN-<group>-<name>.sh
│   └── health/
├── tools.d/
│   ├── fix/                  # opt-in --dry-run, confirmation, logging
│   ├── mail/
│   ├── domain/
│   ├── plesk/
│   └── system/
├── mods.d/
│   └── motd/
├── share/
│   ├── systemd/              # timer + service units
│   └── completion/           # bash completion
├── install.sh
└── plesk-toolbox.conf.example
```

---

## 🤝 Contributing

The whole point of the file-per-check layout is that **adding a check should
take ten minutes**, not a tour of the codebase.

**A new audit check**: drop `audits.d/<pillar>/NN-<group>-<name>.sh` — that's
it. The runner auto-discovers via `lib/runner.sh`. Use the `emit` / `table_*`
APIs from `lib/common.sh`. Look at any existing check as a template.

**A new tool**: drop `tools.d/<group>/<name>.sh` with a `main()` function.
If it writes anything, source `lib/safety.sh` and use
`tool_begin` / `tool_confirm` / `tool_run` / `tool_end` so `--dry-run`,
confirmation, and logging come for free.

**A new mod**: create `mods.d/<name>/{install,uninstall}.sh` and use
`hide_file` / `restore_file` for reversible changes. Always write a manifest.

**Issues, PRs, and "this would be nice to have" tickets are welcome.** If you
already wrote the check or fix script for yourself, even better — send it
over, we probably want it too.

Run `shellcheck` before opening a PR:

```bash
shellcheck -x -s bash -e SC1090,SC1091 bin/* lib/*.sh audits.d/*/*.sh tools.d/*/*.sh
```

---

## 📄 License

[MIT](LICENSE) — see also [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md) and
[`SECURITY.md`](SECURITY.md).
