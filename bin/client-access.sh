#!/bin/bash
# client-connect / client-disconnect script: one address per device.
#
# A certificate may be used on several devices at once (duplicate-cn). A guest
# (a file guests/<name>) gets a free address from the guest range on every
# connection. A client with a static IP (staticclients/<name>) gets it unless
# another of its devices already holds it; that device gets a pool address.
#
# Leases live in /tmp and are cleared whenever OpenVPN starts. The script runs
# as the unprivileged OpenVPN user, and OpenVPN runs it synchronously, one
# client at a time, so leases cannot race.
OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
LEASES=/tmp/openvpn-leases
# GUEST_FIRST, GUEST_LAST and NETMASK, written by the entrypoint.
source /tmp/openvpn-access.env 2>/dev/null || exit 0

cn=${common_name:-}
[[ $cn =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$ ]] || exit 0
me="$cn ${untrusted_ip:-} ${untrusted_port:-}"

ip2int() { local IFS=.; set -- $1; echo $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 )); }
int2ip() { echo "$(( $1 >> 24 & 255 )).$(( $1 >> 16 & 255 )).$(( $1 >> 8 & 255 )).$(( $1 & 255 ))"; }

case ${script_type:-} in
client-connect)
    ip=
    if [[ -e $OPENVPN_DIR/guests/$cn ]]; then
        for (( i = $(ip2int "$GUEST_FIRST"); i <= $(ip2int "$GUEST_LAST"); i++ )); do
            [[ -e $LEASES/$(int2ip $i) ]] || { ip=$(int2ip $i); break; }
        done
        [[ -n $ip ]] || { echo "client-access: no free guest address for $cn" >&2; exit 1; }
    else
        ip=$(sed -n 's/^[[:space:]]*ifconfig-push[[:space:]]\+\([0-9.]\+\).*/\1/p' \
             "$OPENVPN_DIR/staticclients/$cn" 2>/dev/null | head -1)
        [[ -n $ip && -e $LEASES/$ip ]] && ip=     # another device holds it: use the pool
    fi
    if [[ -n $ip ]]; then
        echo "$me" > "$LEASES/$ip"
        echo "ifconfig-push $ip $NETMASK" > "$1"
    fi
    ;;
client-disconnect)
    grep -lxF -- "$me" "$LEASES"/* 2>/dev/null | xargs -r rm -f
    ;;
esac
exit 0
