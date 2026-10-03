#!/usr/bin/env bash
# Selftest for audits.d/sec/53-web-bot-allowlist.sh — runs locally, no network, no panel.
# Official lists come in as file:// URLs, the log is a fixture. Every case checks the STATUS (and
# for warnings the SEVERITY — bin/plesk-audit-notify mails only fail and high warn), and the cases
# are built so that each branch flips one of them.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fail=0

cat > "$T/oai.json" <<'J'
{"creationTime": "x", "prefixes": [{"ipv4Prefix": "74.7.228.0/28"}, {"ipv6Prefix": "2001:db8::/32"}]}
J
cat > "$T/cu.json" <<'J'
{"creationTime": "x", "prefixes": [{"ipv4Prefix": "9.129.0.0/17"}, {"ipv4Prefix": "52.0.0.0/28"}]}
J
cat > "$T/snap-ok.conf" <<'C'
geo $ts_chatgpt_user_ip {
    default 0;
    9.129.0.0/17 1;
    52.0.0.0/28 1;
}
C
grep -v '52.0.0.0' "$T/snap-ok.conf" > "$T/snap-alt.conf"
cat > "$T/snap-leer.conf" <<'C'
geo $x {
    default 0;
}
C
UA_OAI='Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot'
# real OAI-SearchBot v4 + v6 (IP in list) blocked · forged OAI-SearchBot (IP not in list) blocked · real one served
{
  printf '74.7.228.5 - - [03/Oct/2026:10:00:00 +0000] "GET /en HTTP/2.0" 444 0 "https://trikotscout.co.uk" "%s"\n' "$UA_OAI"
  printf '2001:db8::7 - - [03/Oct/2026:10:00:00 +0000] "GET /en HTTP/2.0" 444 0 "https://trikotscout.co.uk" "%s"\n' "$UA_OAI"
  printf '203.0.113.9 - - [03/Oct/2026:10:00:01 +0000] "GET /en HTTP/2.0" 444 0 "https://trikotscout.co.uk" "%s"\n' "$UA_OAI"
  printf '74.7.228.6 - - [03/Oct/2026:10:00:02 +0000] "GET /en HTTP/2.0" 200 512 "https://trikotscout.co.uk" "%s"\n' "$UA_OAI"
} > "$T/blocked.log"
grep -v -e '^74.7.228.5 ' -e '^2001:db8::7 ' "$T/blocked.log" > "$T/clean.log"
# format drift: an extra quoted field after the UA — the bot is in the line, but not where we read it
printf '74.7.228.5 - - [03/Oct/2026:10:00:00 +0000] "GET /en HTTP/2.0" 444 0 "-" "%s" "extra"\n' "$UA_OAI" > "$T/drift.log"
echo '{"creationTime": "x", "prefixes": []}' > "$T/oai-leer.json"
# status moved: an extra field between request and status (e.g. $request_time)
printf '74.7.228.5 - - [03/Oct/2026:10:00:00 +0000] "GET /en HTTP/2.0" 0.001 444 0 "-" "%s"\n' "$UA_OAI" > "$T/drift2.log"
# a log in a different format altogether (JSON) — first line does not match
printf '{"ip":"74.7.228.5","status":444,"ua":"x"}\n' > "$T/json.log"

run() {  # $1 snapshot, $2 log, $3 lists, $4 snapshot source → prints "id status severity|message" lines
    (
        export PTBOX_ROOT="$ROOT" JSON_OUTPUT=1 NO_COLOR=1
        # shellcheck source=/dev/null
        . "$ROOT/lib/common.sh"
        # shellcheck source=/dev/null
        . "$ROOT/lib/runner.sh"
        _runner_reset_counters
        export BOT_ALLOWLIST_PAIRS="$1=${4:-file://$T/cu.json}" BOT_LOG_GLOB="$2" BOT_LISTS="$3" BOT_TIMEOUT=2
        # shellcheck source=/dev/null
        . "$ROOT/audits.d/sec/53-web-bot-allowlist.sh"
    ) | python3 -c '
import sys, json, re
for m in re.finditer(r"\{[^{}]*\}", sys.stdin.read()):
    try:
        d = json.loads(m.group(0))
    except ValueError:
        continue
    if "id" in d and "status" in d:
        print("%s %s %s|%s" % (d["id"], d["status"], d.get("severity", ""), d.get("message", "")))'
}
expect() {  # $1 name, $2 output, $3 regex for one line ("id status severity|message")
    if grep -qE "^$3" <<< "$2"; then echo "ok   $1"; else echo "FAIL $1 — expected /$3/, got:"; echo "       ${2//$'\n'/$'\n'       }"; fail=1; fi
}
all_warns_high() {  # $1 name, $2 output — every warn must be high, or the notify run drops it
    if grep -E ' warn ' <<< "$2" | grep -vqE ' warn high\|'; then echo "FAIL $1 — warn below high:"; echo "       ${2//$'\n'/$'\n'       }"; fail=1; else echo "ok   $1"; fi
}

LISTS="OAI-SearchBot=file://$T/oai.json ChatGPT-User=file://$T/cu.json"
o="$(run "$T/snap-ok.conf" "$T/clean.log" "$LISTS")"
expect "snapshot matches list"            "$o" "sec.web.botlist.current pass "
expect "forged UA and 200 are not a hit"  "$o" "sec.web.botlist.blocked pass "

o="$(run "$T/snap-alt.conf" "$T/blocked.log" "$LISTS")"
expect "snapshot behind the list"         "$o" "sec.web.botlist.current warn high\|"
expect "real bot v4+v6 answered with 444" "$o" "sec.web.botlist.blocked fail [a-z]*\|.*OAI-SearchBot 2x"
all_warns_high "stale snapshot is mailed"  "$o"

o="$(run "$T/snap-ok.conf" "$T/blocked.log" "$LISTS DuckDuckBot=file://$T/fehlt.json")"
expect "fail names the unchecked list"    "$o" "sec.web.botlist.blocked fail [a-z]*\|.*not readable or empty: DuckDuckBot"

o="$(run "$T/snap-ok.conf" "$T/clean.log" "OAI-SearchBot=file://$T/fehlt.json" "file://$T/fehlt.json")"
expect "unreadable list is not a pass"    "$o" "sec.web.botlist.blocked warn high\|"
expect "unreadable source is not a pass"  "$o" "sec.web.botlist.current warn high\|"
all_warns_high "unreadable is mailed"      "$o"

o="$(run "$T/snap-ok.conf" "$T/drift.log" "$LISTS")"
expect "unparsable bot 444 is not clean"  "$o" "sec.web.botlist.blocked warn high\|.*not evaluable"

o="$(run "$T/snap-ok.conf" "$T/drift2.log" "$LISTS")"
expect "moved status is not clean"        "$o" "sec.web.botlist.blocked warn high\|.*not evaluable"

o="$(run "$T/snap-ok.conf" "$T/json.log" "$LISTS")"
expect "unknown log format is not clean"  "$o" "sec.web.botlist.blocked warn high\|.*unknown format"

o="$(run "$T/snap-ok.conf" "$T/blocked.log" "OAI-SearchBot=file://$T/oai-leer.json")"
expect "empty official list is not a pass" "$o" "sec.web.botlist.blocked warn high\|.*or empty: OAI-SearchBot"

if [[ "$(id -u)" -ne 0 ]]; then  # chmod 000 does not stop root
    cp "$T/clean.log" "$T/zu.log"; chmod 000 "$T/zu.log"
    o="$(run "$T/snap-ok.conf" "$T/zu.log" "$LISTS")"
    expect "unreadable log is not clean"  "$o" "sec.web.botlist.blocked warn high\|.*log\(s\) not readable"
    cp "$T/snap-ok.conf" "$T/snap-zu.conf"; chmod 000 "$T/snap-zu.conf"
    o="$(run "$T/snap-zu.conf" "$T/clean.log" "$LISTS")"
    expect "broken part 1 → its own warn" "$o" "sec.web.botlist.current warn high\|check error"
    expect "… and part 2 still reports"   "$o" "sec.web.botlist.blocked pass "
    chmod 600 "$T/zu.log" "$T/snap-zu.conf"
else
    echo "skip chmod cases (running as root)"
fi

o="$(run "$T/snap-leer.conf" "$T/clean.log" "$LISTS")"
expect "empty snapshot is not a pass"     "$o" "sec.web.botlist.current warn high\|"

o="$(run "$T/fehlt.conf" "$T/nolog-*.log" "$LISTS")"
expect "no snapshot → skip"               "$o" "sec.web.botlist.current skip "
expect "no log → skip"                    "$o" "sec.web.botlist.blocked skip "

exit "$fail"
