#!/bin/bash
# Sourced by the entrypoint: what guests may reach.
#
# Guests get the internet through this host's default route (so the filtering
# of your LAN router applies), the pushed DNS servers and their portal. Nothing
# local: no LAN, no private ranges, no network the server pushes a route to, no
# other VPN client, no ping, and nothing on this host (OVPN-INPUT).
#
# The gateway's regular HTTPS listener is on the LAN, so out of reach. A guest's
# HTTPS connection to the gateway (TCP 443 to the listener's address, which your
# LAN DNS returns for the domain's websites) is redirected to the gateway's
# portal listener (GUEST_PORTAL_TARGET, "IPv4:port"). It serves only the
# personal portal pages and the guest links; any other hostname gets an error.

portal_ipv4() {   # a single unicast IPv4 address, no leading zeros
    local octet
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=.
    for octet in $1; do
        [[ $octet == 0 || $octet != 0* ]] && (( 10#$octet <= 255 )) || return 1
    done
    [[ $1 != 0.* && $1 != 127.* && $1 != 169.254.* ]] || return 1
    (( ${1%%.*} < 224 ))
}

guest_portal_validate() {   # sets PORTAL_IP and PORTAL_PORT
    GUEST_PORTAL_TARGET=${GUEST_PORTAL_TARGET:-}
    [[ -n $GUEST_PORTAL_TARGET ]] || return 0
    PORTAL_IP=${GUEST_PORTAL_TARGET%:*}
    PORTAL_PORT=${GUEST_PORTAL_TARGET##*:}
    portal_ipv4 "$PORTAL_IP" && [[ $PORTAL_PORT =~ ^[1-9][0-9]{3,4}$ ]] && (( PORTAL_PORT <= 65535 )) \
        || { echo 'The guest portal listener must be the gateway IPv4:port (port >= 1024)' >&2; return 1; }
}

guest_portal_rules() {   # -A installs the rules, -C checks that they are in place
    local operation=$1
    [[ -n $GUEST_PORTAL_TARGET ]] || return 0
    iptables -t nat "$operation" OVPN-PORTAL -i 'tun+' -s "$GUEST_SUB" -d "$PORTAL_IP" -p tcp --dport 443 \
        -j DNAT --to-destination "$GUEST_PORTAL_TARGET" || return 1
    iptables "$operation" OVPN-FORWARD -i 'tun+' -s "$GUEST_SUB" -d "$PORTAL_IP" -p tcp --dport "$PORTAL_PORT" \
        -m conntrack --ctstate DNAT --ctorigdstport 443 -j ACCEPT || return 1
    # Replies must come back through this host, whichever interface reaches the gateway.
    iptables -t nat "$operation" OVPN-NAT -s "$GUEST_SUB" -d "$PORTAL_IP" -p tcp --dport "$PORTAL_PORT" \
        -m conntrack --ctstate DNAT -j MASQUERADE
}

# Never reachable for guests, besides this host's own networks and the pushed routes.
GUEST_BLOCK='10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16'

guest_rules() {   # SERVER_CONF: the pushed DNS servers and routes
    local dns p net
    for dns in $(sed -n -e 's/^[[:space:]]*push[[:space:]]\+"dhcp-option DNS \([0-9.]\+\)".*/\1/p' \
                        -e 's/^[[:space:]]*push[[:space:]]\+"dns server [0-9]\+ address \([0-9.]\+\)".*/\1/p' "$1" | sort -u); do
        for p in udp tcp; do iptables -A OVPN-FORWARD -s "$GUEST_SUB" -d "$dns" -p $p --dport 53 -j ACCEPT; done
    done
    iptables -A OVPN-FORWARD -s "$GUEST_SUB" -p icmp --icmp-type echo-request -j DROP
    for net in $GUEST_BLOCK $(ip -4 -o route show scope link 2>/dev/null | awk '$1 ~ /^[0-9.]+(\/[0-9]+)?$/ {print $1}' | sort -u); do
        iptables -A OVPN-FORWARD -s "$GUEST_SUB" -d "$net" -j DROP
    done
    # push "route NET [MASK]": a host route without a mask; not the default routes, which would
    # cut guests off the internet. A mistyped route must not keep the server from starting.
    for net in $(sed -n 's/^[[:space:]]*push[[:space:]]\+"route[[:space:]]\+\([0-9.]\+\)[[:space:]"]\+\([0-9.]*\).*/\1\/\2/p' "$1" \
                 | sed 's|/$|/255.255.255.255|' | grep -vE '/(0|128)\.0\.0\.0$' || true); do
        iptables -A OVPN-FORWARD -s "$GUEST_SUB" -d "$net" -j DROP 2>/dev/null \
            || warn "Cannot block guests from the pushed route '$net' - check that line in server.conf"
    done
}
