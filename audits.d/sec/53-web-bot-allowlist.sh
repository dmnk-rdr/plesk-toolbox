# audits.d/sec/53-web-bot-allowlist.sh — official bot IP lists: still current, and does nginx still block those bots?
# shellcheck shell=bash
#
# Why: the crawler protection in a vhost (444 by referer / country) also hit OpenAI's search bot
# and ChatGPT's live fetches — 1,149 times in 7 days, unnoticed for six weeks (trikotscout, found
# 03.10.2026). The fix exempts them, partly via a snapshot of OpenAI's published IP list. Such a
# snapshot goes stale silently: OpenAI changed chatgpt-user.json eight days before we copied it.
#
# Two checks:
#   sec.web.botlist.current  — each snapshot file still matches the list it was copied from
#   sec.web.botlist.blocked  — 444 answers since the last log rotation to a bot whose IP is in its
#                              OFFICIAL list (so: a real bot, not a forged user agent). Target: 0.
# Fail-closed: a list or log that cannot be read is a warn, never a pass. Every warn is `high`,
# because bin/plesk-audit-notify only mails fail and high warn — a medium warn reaches nobody.
# The proxy log is emptied daily (~06:41); the 06:20 cron sees roughly the last 23.5 h.

section "sec: bot allowlists (nginx)"

# snapshot-file=source-url, space separated. Missing files are skipped.
: "${BOT_ALLOWLIST_PAIRS:=/etc/nginx/conf.d/21-ts-chatgpt-user.conf=https://openai.com/chatgpt-user.json}"
# user-agent-token=official-list-url, space separated.
: "${BOT_LISTS:=OAI-SearchBot=https://openai.com/searchbot.json ChatGPT-User=https://openai.com/chatgpt-user.json DuckDuckBot=https://duckduckgo.com/duckduckbot.json}"
# system/<domain>/logs covers every vhost incl. subdomains (same inode as vhosts/<d>/logs, no duplicates).
: "${BOT_LOG_GLOB:=/var/www/vhosts/system/*/logs/proxy_access_ssl_log}"
: "${BOT_TIMEOUT:=15}"

if ! command -v python3 >/dev/null 2>&1; then
    emit "sec.web.botlist.current" "high" "warn" "python3 missing — bot allowlists not checked"
    return 0
fi

_bl_out="$(BOT_ALLOWLIST_PAIRS="$BOT_ALLOWLIST_PAIRS" BOT_LISTS="$BOT_LISTS" \
    BOT_LOG_GLOB="$BOT_LOG_GLOB" BOT_TIMEOUT="$BOT_TIMEOUT" python3 - <<'PY'
import glob, ipaddress, json, os, re, time, urllib.request

timeout = float(os.environ["BOT_TIMEOUT"])
_cache = {}

def fetch(url):
    """Network set of an official list, or None if it cannot be read (fetched once per run).
    Own user agent and one retry: duckduckgo.com sometimes refused urllib's default UA (seen twice
    on panel, 03.10.2026) — without this the result flips pass↔warn and every flip sends a mail."""
    if url not in _cache:
        _cache[url] = None
        for _ in range(2):
            try:
                req = urllib.request.Request(url, headers={"User-Agent": "plesk-toolbox-botlist/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    data = json.load(r)
                _cache[url] = {ipaddress.ip_network(p.get("ipv4Prefix") or p.get("ipv6Prefix"), strict=False)
                               for p in data["prefixes"]}
                break
            except Exception:
                time.sleep(2)
    return _cache[url]

def say(*f):
    print("|".join(str(x).replace("|", "/").replace("\n", " ") for x in f))

def current():
    pairs = [p.split("=", 1) for p in os.environ["BOT_ALLOWLIST_PAIRS"].split() if "=" in p]
    checked = 0
    for path, url in pairs:
        if not os.path.isfile(path):
            continue
        checked += 1
        have = set()
        with open(path, errors="replace") as fh:
            for line in fh:
                m = re.match(r"\s*([0-9a-fA-F:.]+/\d+)\s+1\s*;", line)
                if m:
                    try:
                        have.add(ipaddress.ip_network(m.group(1), strict=False))
                    except ValueError:
                        pass
        live = fetch(url)
        if live is None:
            say("sec.web.botlist.current", "high", "warn", f"{path}: list {url} not readable — snapshot age unknown",
                "check network/URL; the snapshot may be stale")
        elif not have:
            say("sec.web.botlist.current", "high", "warn", f"{path}: no prefixes found in the snapshot",
                "regenerate the file")
        elif have != live:
            say("sec.web.botlist.current", "high", "warn",
                f"{path}: snapshot differs from {url} (new {len(live - have)}, gone {len(have - live)})",
                "regenerate the file from the list, nginx -t, reload")
        else:
            say("sec.web.botlist.current", "info", "pass", f"{path}: matches {url} ({len(have)} prefixes)")
    if not checked:
        say("sec.web.botlist.current", "info", "skip", "no snapshot file present")

def blocked():
    bots = {}
    for item in os.environ["BOT_LISTS"].split():
        if "=" in item:
            token, url = item.split("=", 1)
            bots[token] = fetch(url)
    not_checked = sorted(t for t, n in bots.items() if not n)  # unreadable OR empty list: not checked
    line_re = re.compile(r'^(\S+) .*?" (\d{3}) .*"([^"]*)"\s*$')
    hits = {t: 0 for t in bots}
    files = sorted(f for f in glob.glob(os.environ["BOT_LOG_GLOB"]) if os.path.isfile(f))
    unread = []
    unparsed = 0  # lines that name a bot but cannot be evaluated — never silently clean
    unknown_format = []  # logs whose first line does not match the expected format
    for f in files:
        try:
            fh = open(f, errors="replace")
        except OSError:
            unread.append(f)
            continue
        with fh:
            first = True
            for line in fh:
                if first and line.strip():
                    first = False
                    if not line_re.match(line.rstrip("\n")):
                        unknown_format.append(f)  # whole file unreadable for us — a gap, not clean
                # Token first, format second: a status that moved (extra field, JSON log) must
                # become "not evaluable", never be skipped by a pre-filter on '" 444 '.
                named = [t for t in bots if t in line]
                if not named:
                    continue
                m = line_re.match(line.rstrip("\n"))
                if not m or not any(t in m.group(3) for t in named):
                    unparsed += 1  # format changed? the bot is in the line, but not where we read it
                    continue
                if m.group(2) != "444":
                    continue
                ua = m.group(3)
                try:
                    ip = ipaddress.ip_address(m.group(1))
                except ValueError:
                    unparsed += 1
                    continue
                for token, nets in bots.items():
                    if nets and token in ua and any(ip in n for n in nets):
                        hits[token] += 1
                        break
    gaps = []
    if not_checked:
        gaps.append("lists not readable or empty: " + ", ".join(not_checked))
    if unread:
        gaps.append(f"{len(unread)} log(s) not readable")
    if unparsed:
        gaps.append(f"{unparsed} bot line(s) not evaluable (log format?)")
    if unknown_format:
        gaps.append(f"{len(unknown_format)} log(s) in unknown format")
    gap_txt = (" — " + "; ".join(gaps)) if gaps else ""
    found = {t: n for t, n in hits.items() if n}
    if not files:
        say("sec.web.botlist.blocked", "info", "skip", f"no log matches {os.environ['BOT_LOG_GLOB']}")
    elif found:
        say("sec.web.botlist.blocked", "medium", "fail",
            "real bots answered with 444 since last rotation: "
            + ", ".join(f"{t} {n}x" for t, n in sorted(found.items())) + gap_txt,
            "find the guard in the vhost (referer/geo/net); refresh the IP snapshot if a list changed")
    elif gaps:
        say("sec.web.botlist.blocked", "high", "warn", "not fully checked" + gap_txt, "check network/URL and log permissions")
    else:
        say("sec.web.botlist.blocked", "info", "pass",
            f"0 real-bot 444 in {len(files)} log(s) ({', '.join(sorted(bots))})")

for name, part in (("sec.web.botlist.current", current), ("sec.web.botlist.blocked", blocked)):
    try:
        part()
    except Exception as ex:  # one broken part must not swallow the other's result
        say(name, "high", "warn", f"check error: {type(ex).__name__}: {ex}", "run the check by hand")
PY
)"

if [[ -z "$_bl_out" ]]; then
    emit "sec.web.botlist.current" "high" "warn" "check produced no result (python error?)"
    return 0
fi
while IFS='|' read -r _bl_id _bl_sev _bl_st _bl_msg _bl_fix; do
    [[ -n "$_bl_id" ]] || continue
    emit "$_bl_id" "$_bl_sev" "$_bl_st" "$_bl_msg" "$_bl_fix"
done <<< "$_bl_out"
