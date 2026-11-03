#!/bin/bash
# Sourced by the entrypoint. The destination must serve ONLY portal paths.
portal_ipv4() {
    local octet
    [[ $1 =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=.
    for octet in $1; do
        [[ $octet == 0 || $octet != 0* ]] && (( 10#$octet <= 255 )) || return 1
    done
    [[ $1 != 0.* && $1 != 127.* && $1 != 169.254.* ]] || return 1
    (( ${1%%.*} < 224 ))
}

guest_portal_validate() {
    GUEST_PORTAL_TARGET=${GUEST_PORTAL_TARGET:-}
    GUEST_PORTAL_DESTINATIONS=${GUEST_PORTAL_DESTINATIONS:-}
    [[ -n $GUEST_PORTAL_TARGET || -n $GUEST_PORTAL_DESTINATIONS ]] || return 0
    PORTAL_IP=${GUEST_PORTAL_TARGET%:*}
    PORTAL_PORT=${GUEST_PORTAL_TARGET##*:}
    portal_ipv4 "$PORTAL_IP" && [[ $PORTAL_PORT =~ ^[1-9][0-9]{3,4}$ ]] \
        && (( PORTAL_PORT >= 1024 && PORTAL_PORT <= 65535 )) \
        || { echo 'GUEST_PORTAL_TARGET must be the dedicated portal IPv4:port (>=1024)' >&2; return 1; }
    [[ -n $GUEST_PORTAL_DESTINATIONS ]] \
        || { echo 'Set GUEST_PORTAL_DESTINATIONS to the portal DNS IPv4 addresses' >&2; return 1; }
    local destination
    for destination in $GUEST_PORTAL_DESTINATIONS; do
        portal_ipv4 "$destination" \
            || { echo 'GUEST_PORTAL_DESTINATIONS must contain individual IPv4 addresses' >&2; return 1; }
    done
}

guest_portal_rules() {
    # -A installs; -C verifies the same rules in the periodic firewall check.
    local operation=$1 destination
    [[ -n $GUEST_PORTAL_TARGET ]] || return 0
    for destination in $GUEST_PORTAL_DESTINATIONS; do
        iptables -t nat "$operation" OVPN-PORTAL -i 'tun+' -s "$GUEST_SUB" \
            -d "$destination" -p tcp --dport 443 -j DNAT --to-destination "$GUEST_PORTAL_TARGET" || return 1
        iptables "$operation" OVPN-FORWARD -i 'tun+' -s "$GUEST_SUB" \
            -d "$PORTAL_IP" -p tcp --dport "$PORTAL_PORT" -m conntrack \
            --ctstate DNAT --ctorigdst "$destination" --ctorigdstport 443 -j ACCEPT || return 1
    done
    # Return traffic must come back through this VPN host, even on another LAN interface.
    iptables -t nat "$operation" OVPN-NAT -s "$GUEST_SUB" -d "$PORTAL_IP" \
        -p tcp --dport "$PORTAL_PORT" -m conntrack --ctstate DNAT -j MASQUERADE
}
