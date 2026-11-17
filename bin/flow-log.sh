#!/bin/bash
# flow-log.sh FIRST LAST FILE: the end of every connection of a VPN client,
# with its byte counts, appended to FILE for the UI's traffic-by-section count.
#
# conntrack reports a connection when the kernel forgets it (DESTROY); with
# net.netfilter.nf_conntrack_acct=1 the line carries packets and bytes for
# both directions. Only connections whose original source lies in
# FIRST..LAST (the VPN subnet, as integers) are kept. Restarted when it exits.
set -u
first=$1 last=$2 out=$3

keep() {
    awk -v lo="$first" -v hi="$last" '
        {
            for (i = 1; i <= NF; i++) if ($i ~ /^src=/) { split(substr($i, 5), o, "."); break }
            ip = ((o[1] * 256 + o[2]) * 256 + o[3]) * 256 + o[4]
            if (ip >= lo && ip <= hi) { print; fflush() }
        }' >> "$out"
}

while :; do
    started=$(date +%s)
    conntrack -E -e DESTROY -o timestamp -b 4194304 2>/dev/null | keep
    # A kernel without the larger buffer ends at once: run with the default one.
    if (( $(date +%s) - started < 5 )); then
        conntrack -E -e DESTROY -o timestamp 2>&1 | keep
    fi
    sleep 5
done
