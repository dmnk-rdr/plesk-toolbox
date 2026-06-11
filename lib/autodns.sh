# shellcheck shell=bash
# lib/autodns.sh - AutoDNS / SchlundTech JSON API client
#
# Talks to the InterNetX Domain Robot JSON API. AutoDNS and SchlundTech
# speak the same protocol on the same endpoint — they differ only in the
# request context header:
#
#     AutoDNS       X-Domainrobot-Context: 4
#     SchlundTech   X-Domainrobot-Context: 10
#
# Credentials live in a root-only secrets file (never in conf/repo):
#     /etc/plesk-toolbox.secrets
#         AUTODNS_USER="account"
#         AUTODNS_PASSWORD="secret"
#         AUTODNS_CONTEXT=10          # SchlundTech; AutoDNS = 4
#
# Path overridable via AUTODNS_SECRETS in /etc/plesk-toolbox.conf.
[[ -n "${__PTBOX_AUTODNS_LOADED:-}" ]] && return 0
__PTBOX_AUTODNS_LOADED=1

: "${AUTODNS_URL:=https://api.autodns.com/v1}"
: "${AUTODNS_CONTEXT:=4}"
: "${AUTODNS_SECRETS:=/etc/plesk-toolbox.secrets}"
: "${AUTODNS_TIMEOUT:=20}"

autodns_have_credentials() {
    [[ -n "${AUTODNS_USER:-}" && -n "${AUTODNS_PASSWORD:-}" ]]
}

# autodns_load_credentials
# Sources the secrets file unless creds are already in the environment.
# Returns 1 (with a hint on stderr) when no credentials can be found.
autodns_load_credentials() {
    if ! autodns_have_credentials && [[ -f "$AUTODNS_SECRETS" ]]; then
        local mode
        mode="$(stat -c '%a' "$AUTODNS_SECRETS" 2>/dev/null || echo '')"
        if [[ -n "$mode" && "$mode" != *00 ]]; then
            printf 'warning: %s is group/world-readable (mode %s) — chmod 600 it\n' \
                "$AUTODNS_SECRETS" "$mode" >&2
        fi
        # shellcheck disable=SC1090
        . "$AUTODNS_SECRETS"
    fi
    if ! autodns_have_credentials; then
        printf 'autodns: no credentials — set AUTODNS_USER / AUTODNS_PASSWORD in %s\n' \
            "$AUTODNS_SECRETS" >&2
        return 1
    fi
    return 0
}

# _autodns_call <method> <path> [json-body]
# Echoes the raw JSON response when .status.type == SUCCESS. Anything else
# prints the API's message text on stderr and returns 1. Credentials go
# through `curl --config` on a process-substitution fd so they never show
# up in the process list.
_autodns_call() {
    local method="$1" path="$2" body="${3:-}"
    local -a args=(
        -sS --max-time "$AUTODNS_TIMEOUT"
        -X "$method"
        -H 'Content-Type: application/json'
        -H "X-Domainrobot-Context: ${AUTODNS_CONTEXT}"
    )
    [[ -n "$body" ]] && args+=(--data "$body")

    local resp rc=0
    resp="$(curl "${args[@]}" \
        --config <(printf 'user = "%s:%s"\n' "$AUTODNS_USER" "$AUTODNS_PASSWORD") \
        "${AUTODNS_URL}${path}" 2>&1)" || rc=$?
    if (( rc != 0 )); then
        printf 'autodns: %s %s: curl failed: %s\n' "$method" "$path" "$resp" >&2
        return 1
    fi

    local stype
    stype="$(jq -r '.status.type // empty' <<< "$resp" 2>/dev/null || true)"
    if [[ "$stype" != "SUCCESS" ]]; then
        local msg
        msg="$(jq -r '[.messages[]?.text // empty] | join("; ")' <<< "$resp" 2>/dev/null || true)"
        printf 'autodns: %s %s: %s\n' "$method" "$path" \
            "${msg:-unexpected response: ${resp:0:200}}" >&2
        return 1
    fi
    printf '%s' "$resp"
}

# Zone lookups are cached per run — fqdn (and every parent label tried)
# maps to "zone vns" on hit, "-" on verified miss.
declare -A _AUTODNS_ZONE_CACHE

# autodns_zone_find <fqdn>
# Walks labels upward (a.b.example.com → b.example.com → example.com) until
# a zone managed by this account matches. Echoes "zone virtualNameServer".
# Returns 1 when no zone in the account covers the name, 2 on API errors.
autodns_zone_find() {
    local candidate="${1%.}"
    candidate="${candidate,,}"
    while [[ "$candidate" == *.* ]]; do
        local cached="${_AUTODNS_ZONE_CACHE[$candidate]:-}"
        if [[ "$cached" == "-" ]]; then
            candidate="${candidate#*.}"
            continue
        elif [[ -n "$cached" ]]; then
            printf '%s\n' "$cached"
            return 0
        fi

        local resp zone vns
        resp="$(_autodns_call POST /zone/_search \
            "$(jq -nc --arg z "$candidate" \
                '{filters:[{key:"name",operator:"EQUAL",value:$z}]}')")" || return 2
        zone="$(jq -r '.data[0].origin // empty' <<< "$resp")"
        vns="$(jq -r '.data[0].virtualNameServer // empty' <<< "$resp")"
        if [[ -n "$zone" ]]; then
            _AUTODNS_ZONE_CACHE[$candidate]="$zone $vns"
            printf '%s %s\n' "$zone" "$vns"
            return 0
        fi
        _AUTODNS_ZONE_CACHE[$candidate]="-"
        candidate="${candidate#*.}"
    done
    return 1
}

# autodns_zone_records <zone> <virtualNameServer>
# Echoes the zone's resourceRecords as a compact JSON array.
autodns_zone_records() {
    local resp
    resp="$(_autodns_call GET "/zone/${1}/${2}")" || return 1
    jq -c '.data[0].resourceRecords // []' <<< "$resp"
}

# autodns_rr_json <name> <type> <value> <ttl> [pref]
# Builds one ResourceRecord object. <name> is relative to the zone
# (empty string = apex). pref is only meaningful for MX/SRV.
autodns_rr_json() {
    local name="$1" type="$2" value="$3" ttl="$4" pref="${5:-}"
    if [[ -n "$pref" ]]; then
        jq -nc --arg n "$name" --arg t "$type" --arg v "$value" \
            --argjson ttl "$ttl" --argjson pref "$pref" \
            '{name:$n, type:$t, value:$v, ttl:$ttl, pref:$pref}'
    else
        jq -nc --arg n "$name" --arg t "$type" --arg v "$value" --argjson ttl "$ttl" \
            '{name:$n, type:$t, value:$v, ttl:$ttl}'
    fi
}

# autodns_zone_stream <zone> <adds-json-array> [rems-json-array]
# Incremental zone update: POST /zone/{name}/_stream {adds:[…], rems:[…]}.
# This is the idempotent-friendly path — no full-zone PUTs.
autodns_zone_stream() {
    local zone="$1" adds="$2" rems="${3:-[]}"
    local body
    body="$(jq -nc --argjson adds "$adds" --argjson rems "$rems" \
        '{adds:$adds, rems:$rems}')"
    _autodns_call POST "/zone/${zone}/_stream" "$body" >/dev/null
}
