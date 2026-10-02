#!/bin/bash
# client-connect / client-disconnect script: one address per device.
#
# A certificate may be used on several devices at once (duplicate-cn). A guest
# (a file guests/<name>) gets a free address from the guest range on every
# connection. A client with a static IP (staticclients/<name>) gets it unless
# another of its devices already holds it; that device gets a pool address.
# One certificate gets at most MAX_DEVICES connections at a time, so that a
# copied profile cannot fill the server.
#
# Every connection has a lease: a file named after its VPN address that holds
# "name real-address port". Leases live in /tmp and are cleared whenever OpenVPN
# starts. The script runs as the unprivileged OpenVPN user, and OpenVPN runs it
# synchronously, one client at a time, so leases cannot race. A non-zero exit
# makes OpenVPN refuse the client.
OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
LEASES=/tmp/openvpn-leases
# GUEST_FIRST, GUEST_LAST, NETMASK, MAX_DEVICES and the V6_* values, written by
# the entrypoint. Without them a guest could not be told from a full client.
source /tmp/openvpn-access.env 2>/dev/null || { echo "client-access: /tmp/openvpn-access.env is missing" >&2; exit 1; }

cn=${common_name:-}
# In the log's own format, so that the web UI lists it among the rejected attempts.
refuse() { echo "$(date '+%Y-%m-%d %H:%M:%S') client-access: refused cn='$cn' from='${untrusted_ip:-?}' reason=$1" >&2; exit 1; }
[[ $cn =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$ ]] || exit 0
me="$cn ${untrusted_ip:-} ${untrusted_port:-}"

ip2int() { local IFS=.; set -- $1; echo $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 )); }
int2ip() { echo "$(( $1 >> 24 & 255 )).$(( $1 >> 16 & 255 )).$(( $1 >> 8 & 255 )).$(( $1 & 255 ))"; }

case ${script_type:-} in
client-connect)
    if (( ${MAX_DEVICES:-0} > 0 )); then
        n=$(grep -lE "^${cn//./\\.} " "$LEASES"/* 2>/dev/null | wc -l)
        (( n < MAX_DEVICES )) || refuse too-many-devices
    fi
    ip=
    if [[ -e $OPENVPN_DIR/guests/$cn ]]; then
        for (( i = $(ip2int "$GUEST_FIRST"); i <= $(ip2int "$GUEST_LAST"); i++ )); do
            [[ -e $LEASES/$(int2ip $i) ]] || { ip=$(int2ip $i); break; }
        done
        [[ -n $ip ]] || refuse no-free-guest-address
    else
        ip=$(sed -n 's/^[[:space:]]*ifconfig-push[[:space:]]\+\([0-9.]\+\).*/\1/p' \
             "$OPENVPN_DIR/staticclients/$cn" 2>/dev/null | head -1)
        [[ -n $ip && -e $LEASES/$ip ]] && ip=     # another device holds it: use the pool
    fi
    if [[ -n $ip ]]; then
        echo "$me" > "$LEASES/$ip"
        echo "ifconfig-push $ip $NETMASK" > "$1"
        # OpenVPN's IPv6 pool is tied to its IPv4 pool, so a pushed IPv4 address needs its
        # own IPv6 one: the IPv4 address as the last 32 bits (10.0.70.129 -> fd00:70::a00:4681).
        n=$(ip2int "$ip")
        [[ -n ${V6_BASE:-} ]] && printf 'ifconfig-ipv6-push %s%x:%x/%s %s\n' \
            "$V6_BASE" $(( n >> 16 )) $(( n & 65535 )) "$V6_BITS" "$V6_GW" >> "$1"
    elif [[ ${ifconfig_pool_remote_ip:-} =~ ^[0-9.]+$ ]]; then
        echo "$me" > "$LEASES/$ifconfig_pool_remote_ip"     # an address from OpenVPN's own pool
    fi
    ;;
client-disconnect)
    grep -lxF -- "$me" "$LEASES"/* 2>/dev/null | xargs -r rm -f
    ;;
esac
exit 0
