#!/bin/bash
# Read validated UI output as data. Never execute a settings file as shell code.
load_network_settings() {
    local path="$OPENVPN_DIR/config/network/settings.conf" key value ip mask number=0 bits=0 octet
    if [[ -f $path ]]; then
        while IFS='=' read -r key value; do
            case "$key" in
                TRUST_SUB) TRUST_SUB=$value ;;
                GUEST_SUB) GUEST_SUB=$value ;;
                LAN_CIDRS) LAN_CIDRS=$value ;;
                GUEST_BLOCK) GUEST_BLOCK=$value ;;
                GUEST_PORTAL_HOST) GUEST_PORTAL_HOST=$value ;;
                GUEST_PORTAL_TARGET) GUEST_PORTAL_TARGET=$value ;;
                GUEST_PORTAL_DESTINATIONS) GUEST_PORTAL_DESTINATIONS=$value ;;
            esac
        done < "$path"
    fi
    # Bootstrap from the installed server.conf, not a deployment-specific subnet.
    read -r ip mask < <(awk '$1 == "server" {print $2, $3; exit}' "$SERVER_CONF")
    TRUST_SUB=${TRUST_SUB:-$ip/$mask}
    if [[ -z ${GUEST_SUB:-} ]]; then
        local IFS=.
        for octet in $mask; do
            case $octet in 255) ((bits+=8));; 254) ((bits+=7));; 252) ((bits+=6));; 248) ((bits+=5));;
                240) ((bits+=4));; 224) ((bits+=3));; 192) ((bits+=2));; 128) ((bits+=1));; 0) :;; *) return 1;; esac
        done
        (( bits >= 1 && bits <= 28 )) || return 1
        for octet in $ip; do number=$(( (number << 8) + octet )); done
        number=$(( number + (1 << (31 - bits)) ))
        GUEST_SUB="$((number >> 24 & 255)).$((number >> 16 & 255)).$((number >> 8 & 255)).$((number & 255))/$((bits + 1))"
    fi
    guest_portal_validate
}
