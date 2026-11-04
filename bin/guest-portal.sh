#!/bin/bash
# Sourced by the entrypoint: the guests' only way out of the tunnel.
#
# Guests get no internet and no LAN. Every HTTPS connection a guest opens
# (TCP 443, any address) is redirected to the gateway's portal listener
# (GUEST_PORTAL_TARGET, "IPv4:port"), which serves only the personal portal
# pages of the OpenVPN website; any other hostname gets an error there. So
# https://openvpn.<domain>/ works whatever address a guest's DNS returns for it.

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
    iptables -t nat "$operation" OVPN-PORTAL -i 'tun+' -s "$GUEST_SUB" -p tcp --dport 443 \
        -j DNAT --to-destination "$GUEST_PORTAL_TARGET" || return 1
    iptables "$operation" OVPN-FORWARD -i 'tun+' -s "$GUEST_SUB" -d "$PORTAL_IP" -p tcp --dport "$PORTAL_PORT" \
        -m conntrack --ctstate DNAT --ctorigdstport 443 -j ACCEPT || return 1
    # Replies must come back through this host, whichever interface reaches the gateway.
    iptables -t nat "$operation" OVPN-NAT -s "$GUEST_SUB" -d "$PORTAL_IP" -p tcp --dport "$PORTAL_PORT" \
        -m conntrack --ctstate DNAT -j MASQUERADE
}
