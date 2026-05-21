# Security Policy

## Reporting a vulnerability

plesk-toolbox runs as root on production Plesk servers, so security
issues are taken seriously even though the codebase is small.

Please report vulnerabilities **privately** via GitHub's built-in
advisory workflow:

→ <https://github.com/dmnk-rdr/plesk-toolbox/security/advisories/new>

Please do **not** open a regular issue or a public pull request for a
suspected security problem.

A useful report includes:

- a short description of the issue and its impact
- the affected file(s) and audit/tool ID where relevant
- steps to reproduce, ideally on a stock Debian or Ubuntu Plesk install
- the commit SHA you tested against

You will get an acknowledgement within a few days. From there we will
agree on a disclosure timeline (usually 30–90 days depending on
severity) before any public discussion.

## Supported versions

The project tracks `main`. Only the current `main` is supported with
security fixes. There are no long-term-support branches.

## Scope

In scope:

- privilege escalation by an unprivileged user on a Plesk server that
  has plesk-toolbox installed
- command injection in any audit, tool, or mod
- writes performed by an audit (audits are required to be read-only —
  any write is a bug)
- credentials or other secrets leaking into logs, JSON output, or the
  MOTD dashboard

Out of scope:

- vulnerabilities in Plesk itself (please report to Plesk)
- vulnerabilities in third-party tools we shell out to
  (`openssl`, `dig`, `curl`, `rsync`, etc.)
- denial of service caused by an audit running on a host that lacks the
  resources to run it (e.g. running a per-domain TLS audit on a server
  with thousands of domains)
