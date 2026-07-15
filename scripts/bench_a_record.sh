#!/usr/bin/env bash

SERVER="127.0.0.1"
DOMAIN="google.com"

CONCURRENCY=200
TMP=$(mktemp)

cleanup() {
    rm -f "$TMP"
    pkill -P $$ 2>/dev/null
}

trap cleanup EXIT INT TERM

worker() {
    while true; do
        host="$(openssl rand -hex 8).$DOMAIN"

        out=$(dig @"$SERVER" "$host" +tries=1 +time=1 2>/dev/null)

        if grep -q "status: NOERROR\|status: NXDOMAIN" <<<"$out"; then
            ok=1
        else
            ok=0
        fi

        t=$(awk '/Query time:/ {print $4}' <<<"$out")
        [[ -z "$t" ]] && t=1000

        echo "$ok $t" >> "$TMP"
    done
}

for ((i=0;i<CONCURRENCY;i++)); do
    worker &
done

last_total=0

while true; do
    sleep 1

    total=0
    success=0
    failed=0
    sum=0
    max=0

    while read -r ok t; do
        ((total++))
        ((sum+=t))
        ((t>max)) && max=$t
        if ((ok)); then
            ((success++))
        else
            ((failed++))
        fi
    done < "$TMP"

    : > "$TMP"

    qps=$((total-last_total))
    last_total=$total

    if ((total>0)); then
        avg=$((sum/total))
        rate=$((success*100/total))
    else
        avg=0
        rate=0
    fi

    printf "\rRequests/s:%6d | Success:%8d | Failed:%6d | Avg:%4d ms | Max:%4d ms | Success:%3d%%" \
        "$qps" "$success" "$failed" "$avg" "$max" "$rate"
done
