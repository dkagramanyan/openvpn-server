#!/bin/bash
# OpenVPN server container entrypoint.
#
#  1. Initialises the PKI on first start (CA, server cert, CRL, tls-crypt key).
#  2. Checks IPv4 forwarding and installs idempotent iptables rules.
#  3. Runs OpenVPN under a small supervisor loop so that the web UI can
#     restart the daemon through the management interface (signal SIGTERM)
#     without needing access to the Docker socket. The firewall rules are
#     rebuilt on each of these starts.
set -euo pipefail

OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
EASYRSA_DIR=${EASYRSA_DIR:-/usr/share/easy-rsa}
PKI_DIR=$OPENVPN_DIR/pki
LOG_DIR=/var/log/openvpn
SERVER_CONF=$OPENVPN_DIR/server.conf
MGMT_PW_FILE=$OPENVPN_DIR/config/management.pw

TRUST_SUB=${TRUST_SUB:-10.0.70.0/24}
GUEST_SUB=${GUEST_SUB:-10.0.70.128/25}
HOME_SUB=${HOME_SUB:-170.134.51.0/24}
GUEST_BLOCK=${GUEST_BLOCK:-10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 100.64.0.0/10 169.254.0.0/16}
OVPN_STRICT_FORWARD=${OVPN_STRICT_FORWARD:-1}
OVPN_LOG_STDOUT=${OVPN_LOG_STDOUT:-1}
OVPN_LOG_MAX_BYTES=${OVPN_LOG_MAX_BYTES:-10485760}
OVPN_CRL_RENEW_DAYS=${OVPN_CRL_RENEW_DAYS:-30}
OVPN_MSS=${OVPN_MSS:-1400}
OVPN_MAX_DEVICES=${OVPN_MAX_DEVICES:-10}

log()  { printf '%s [entrypoint] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
warn() { printf '%s [entrypoint] WARNING: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die()  { printf '%s [entrypoint] ERROR: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; exit 1; }

export EASYRSA_BATCH=1
export EASYRSA_PKI=$PKI_DIR
easyrsa() { "$EASYRSA_DIR/easyrsa" "$@"; }

log "OpenVPN $(openvpn --version | head -1 | awk '{print $2}'), easy-rsa $(grep -m1 -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' "$EASYRSA_DIR/ChangeLog" 2>/dev/null || echo '?')"
log "OpenVPN dir: $OPENVPN_DIR  PKI: $PKI_DIR"

# Until OpenVPN runs, a stop signal ends the script after the current step
# (PID 1 ignores signals it has no handler for, and Docker would kill it
# mid-way through building the PKI).
trap 'log "Received stop signal"; exit 143' TERM INT

[[ -f $SERVER_CONF ]] || die "$SERVER_CONF not found. Mount the repository at $OPENVPN_DIR."
mkdir -p "$PKI_DIR" "$LOG_DIR" "$OPENVPN_DIR"/{clients,config,staticclients,guests,db}

# --------------------------------------------------------------------------
# 1. PKI
# --------------------------------------------------------------------------
if [[ ! -f $PKI_DIR/ca.crt ]]; then
    log "No CA found - initialising a new PKI"
    if [[ -n $(find "$PKI_DIR" -mindepth 1 -not -name '.*' 2>/dev/null | head -1) ]]; then
        warn "$PKI_DIR is not empty but has no ca.crt; leaving existing files in place"
    fi
    if [[ ! -f $PKI_DIR/openssl-easyrsa.cnf ]]; then
        # init-pki wipes its target, so build the skeleton in a scratch dir
        # and copy it into the (mounted) PKI directory.
        rm -rf /tmp/pki-init
        EASYRSA_PKI=/tmp/pki-init easyrsa init-pki >/dev/null
        cp -a /tmp/pki-init/. "$PKI_DIR/"
        rm -rf /tmp/pki-init
    fi
    if [[ -f $OPENVPN_DIR/config/easy-rsa.vars ]]; then
        cp "$OPENVPN_DIR/config/easy-rsa.vars" "$PKI_DIR/vars"
    fi
    log "easy-rsa variables:"
    sed -n 's/^set_var //p' "$PKI_DIR/vars" 2>/dev/null | sed 's/^/    /' || true
    log "Building the certificate authority"
    easyrsa build-ca nopass
else
    log "PKI already initialised"
fi
# Its own step: a start interrupted after the CA was built leaves no server
# certificate, and OpenVPN would fail on every start from then on.
conf_cert=$(sed -n 's/^[[:space:]]*cert[[:space:]]\+\([^[:space:]#]\+\).*/\1/p' "$SERVER_CONF" | head -1)
if [[ ${conf_cert#"$OPENVPN_DIR"/} == pki/issued/server.crt && ! -f $PKI_DIR/issued/server.crt ]]; then
    log "Building the server certificate"
    rm -f "$PKI_DIR/reqs/server.req" "$PKI_DIR/private/server.key"
    easyrsa --req-cn=server build-server-full server nopass
fi

# Per-client control channel keys (tls-crypt-v2, switched on the Server page).
if grep -qE '^[[:space:]]*tls-crypt-v2[[:space:]]' "$SERVER_CONF" && [[ ! -f $PKI_DIR/tc2-server.key ]]; then
    log "Generating tls-crypt-v2 server key"
    openvpn --genkey tls-crypt-v2-server "$PKI_DIR/tc2-server.key"
fi

if [[ ! -f $PKI_DIR/ta.key ]]; then
    log "Generating tls-crypt key"
    openvpn --genkey secret "$PKI_DIR/ta.key"
fi

if [[ ! -f $PKI_DIR/crl.pem ]]; then
    log "Generating certificate revocation list"
    easyrsa gen-crl
else
    # An expired CRL makes OpenVPN reject *every* client. Renew it early.
    next=$(openssl crl -in "$PKI_DIR/crl.pem" -noout -nextupdate 2>/dev/null | cut -d= -f2 || true)
    if [[ -n $next ]]; then
        next_epoch=$(date -d "$next" +%s 2>/dev/null || echo 0)
        if (( next_epoch - $(date +%s) < OVPN_CRL_RENEW_DAYS * 86400 )); then
            log "CRL expires on $next - regenerating"
            easyrsa gen-crl
        fi
    fi
fi

# Only generate DH parameters if the configuration still references a DH
# file (OpenVPN 2.7 defaults to "dh none" and uses ECDH instead).
dh_file=$(sed -n 's/^[[:space:]]*dh[[:space:]]\+\([^[:space:]#]\+\).*/\1/p' "$SERVER_CONF" | head -1)
if [[ -n $dh_file && $dh_file != none ]]; then
    dh_path=$dh_file; [[ $dh_path = /* ]] || dh_path=$OPENVPN_DIR/$dh_file
    if [[ ! -f $dh_path ]]; then
        log "server.conf references '$dh_file' - generating DH parameters (slow; consider 'dh none')"
        easyrsa gen-dh
        [[ $dh_path = "$PKI_DIR/dh.pem" ]] || cp "$PKI_DIR/dh.pem" "$dh_path"
    fi
fi

# Management interface password (used by the web UI).
if [[ ! -s $MGMT_PW_FILE ]]; then
    log "Generating management interface password"
    (umask 077; head -c 32 /dev/urandom | base64 | tr -d '/+=\n' | head -c 32 > "$MGMT_PW_FILE"; echo >> "$MGMT_PW_FILE")
fi
chmod 600 "$MGMT_PW_FILE"

# Files OpenVPN reads *after* dropping privileges to nobody must be readable.
chmod 644 "$PKI_DIR/crl.pem" "$PKI_DIR/ca.crt" 2>/dev/null || true
chmod 600 "$PKI_DIR/private/"*.key 2>/dev/null || true
chmod 755 "$PKI_DIR" "$OPENVPN_DIR/staticclients" "$OPENVPN_DIR/guests"
chmod 644 "$OPENVPN_DIR/staticclients/"* "$OPENVPN_DIR/guests/"* 2>/dev/null || true
# 2FA secrets: for the unprivileged OpenVPN user (the verify script) only.
if [[ -f $OPENVPN_DIR/clients/oath.secrets ]]; then
    chown nobody "$OPENVPN_DIR/clients/oath.secrets" && chmod 600 "$OPENVPN_DIR/clients/oath.secrets"
fi
# The 2FA verify script runs as nobody and appends to this log.
touch "$LOG_DIR/oath.log" && chown nobody "$LOG_DIR/oath.log" && chmod 644 "$LOG_DIR/oath.log"

# --------------------------------------------------------------------------
# 2. Networking
# --------------------------------------------------------------------------
if [[ ! -c /dev/net/tun ]]; then
    mknod /dev/net/tun c 10 200 2>/dev/null || die "/dev/net/tun is missing. Add 'devices: [/dev/net/tun]' to the container."
fi

# The kernel refuses per-container network sysctls in host network mode, so
# forwarding has to be on for the host (the Docker daemon usually enables it).
sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null || true
if [[ $(cat /proc/sys/net/ipv4/ip_forward) != 1 ]]; then
    die "IPv4 forwarding is disabled. Enable it on the host and start again:
      sudo sysctl -w net.ipv4.ip_forward=1   (persist it in /etc/sysctl.d/99-openvpn.conf)"
fi

# What server.conf says the tunnel network is, against what the firewall is told.
conf_net=$(sed -n 's/^[[:space:]]*server[[:space:]]\+\([0-9.]\+\)[[:space:]].*/\1/p' "$SERVER_CONF" | head -1)
if [[ -n $conf_net && $conf_net != "${TRUST_SUB%/*}" ]]; then
    warn "server.conf hands out addresses in $conf_net but TRUST_SUB is $TRUST_SUB: clients will have no internet. Set TRUST_SUB (and GUEST_SUB) in docker-compose.yml to match."
fi

# Our rules live in our own chains, flushed and rebuilt on every OpenVPN start,
# so a changed subnet or DNS server never leaves stale rules behind.
# OVPN-FORWARD (guest isolation) runs first - from DOCKER-USER when Docker
# manages the host firewall, so Docker's own accept rules cannot bypass it -
# and OVPN-ACCEPT last.
chain() {   # [IPT=ip6tables] chain TABLE NAME BUILTIN -I|-A
    local ipt=${IPT:-iptables}
    $ipt -t "$1" -N "$2" 2>/dev/null || $ipt -t "$1" -F "$2"
    $ipt -t "$1" -C "$3" -j "$2" 2>/dev/null || $ipt -t "$1" "$4" "$3" -j "$2"
}
forward_first() { iptables -n -L DOCKER-USER >/dev/null 2>&1 && echo DOCKER-USER || echo FORWARD; }

firewall() {
    local egress dns p net dir f c v6
    egress=${OVPN_EGRESS_IFACE:-$(ip -4 route show default 2>/dev/null \
        | awk '{for (i = 1; i < NF; i++) if ($i == "dev") {print $(i + 1); exit}}')}
    egress=${egress:-eth0}
    log "Configuring iptables in the current network namespace (the host's under network_mode: host)"
    log "Egress interface: $egress  trusted: $TRUST_SUB  guest: $GUEST_SUB  home: $HOME_SUB"
    chain nat OVPN-NAT POSTROUTING -A
    chain filter OVPN-INPUT INPUT -I
    chain filter OVPN-FORWARD "$(forward_first)" -I
    chain filter OVPN-ACCEPT FORWARD -A
    iptables -t nat -A OVPN-NAT -s "$TRUST_SUB" -o "$egress" -j MASQUERADE   # guests are inside TRUST_SUB

    # Guests: the pushed DNS servers and the internet, nothing else - no LAN, no
    # private ranges, no network the server pushes a route to, no other VPN
    # clients, no ping, and nothing on this host.
    for dns in $(sed -n -e 's/^[[:space:]]*push[[:space:]]\+"dhcp-option DNS \([0-9.]\+\)".*/\1/p' \
                        -e 's/^[[:space:]]*push[[:space:]]\+"dns server [0-9]\+ address \([0-9.]\+\)".*/\1/p' "$SERVER_CONF" | sort -u); do
        for p in udp tcp; do iptables -A OVPN-FORWARD -s "$GUEST_SUB" -d "$dns" -p $p --dport 53 -j ACCEPT; done
    done
    iptables -A OVPN-FORWARD -s "$GUEST_SUB" -p icmp --icmp-type echo-request -j DROP
    for net in "$HOME_SUB" $GUEST_BLOCK; do
        iptables -A OVPN-FORWARD -s "$GUEST_SUB" -d "$net" -j DROP
    done
    # push "route NET [MASK]": a host route without a mask; not the default routes, which would
    # cut guests off the internet. A mistyped route must not keep the server from starting.
    for net in $(sed -n 's/^[[:space:]]*push[[:space:]]\+"route[[:space:]]\+\([0-9.]\+\)[[:space:]"]\+\([0-9.]*\).*/\1\/\2/p' "$SERVER_CONF" \
                 | sed 's|/$|/255.255.255.255|' | grep -vE '/(0|128)\.0\.0\.0$' || true); do
        iptables -A OVPN-FORWARD -s "$GUEST_SUB" -d "$net" -j DROP 2>/dev/null \
            || warn "Cannot block guests from the pushed route '$net' - check that line in server.conf"
    done
    iptables -A OVPN-INPUT -i 'tun+' -s "$GUEST_SUB" -j DROP

    # Custom rules supplied by the user (see fw-rules.sh).
    for f in "$OPENVPN_DIR/fw-rules.sh" /opt/app/fw-rules.sh; do
        if [[ -s $f ]] && grep -qvE '^\s*(#|$)' "$f"; then
            log "Applying additional firewall rules from $f"
            bash "$f"
            break
        fi
    done

    iptables -A OVPN-ACCEPT -i 'tun+' -j ACCEPT
    if [[ $OVPN_STRICT_FORWARD = 1 ]]; then
        # Only VPN-originated traffic and replies to it are forwarded. Under
        # network_mode: host this sets the *host* FORWARD policy (the same value
        # Docker itself defaults to); OVPN_STRICT_FORWARD=0 leaves the policy
        # alone and also lets new connections in to VPN clients.
        iptables -A OVPN-ACCEPT -o 'tun+' -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        iptables -P FORWARD DROP
    else
        iptables -A OVPN-ACCEPT -o 'tun+' -j ACCEPT
    fi

    # IPv6. The tunnel has an IPv6 network only so that clients send their IPv6
    # traffic into it instead of around it; nothing there is meant to be reached.
    # OpenVPN answers such packets itself (block-ipv6), but with kernel offload
    # (DCO) they never pass through OpenVPN and arrive on this host, where the
    # rules above - all IPv4 - do not apply. Drop them.
    v6=$(sed -n 's/^[[:space:]]*ifconfig-ipv6[[:space:]]\+\([0-9a-fA-F:]\+\/[0-9]\+\).*/\1/p' "$SERVER_CONF" | head -1)
    if [[ -n $v6 ]]; then
        if IPT=ip6tables chain filter OVPN-INPUT INPUT -I 2>/dev/null \
                && IPT=ip6tables chain filter OVPN-FORWARD FORWARD -I 2>/dev/null; then
            ip6tables -A OVPN-INPUT -i 'tun+' -s "$v6" -j DROP
            ip6tables -A OVPN-FORWARD -i 'tun+' -s "$v6" -j DROP
            ip6tables -A OVPN-FORWARD -o 'tun+' -d "$v6" -j DROP
        else
            warn "No IPv6 firewall on this host (ip6tables failed) - IPv6 from VPN clients to this host is not filtered"
        fi
    fi

    # TCP segment size. OpenVPN's mssfix lowers the MSS that TCP connections
    # negotiate through the tunnel, so that an encrypted packet still fits the
    # path. With kernel offload (DCO) on Linux the data packets never pass through
    # OpenVPN and nothing lowers it. Do it here instead: 1400 is what the default
    # "mssfix 1492" gives for IPv4 over UDP with AES-GCM. OVPN_MSS=0 turns it off.
    if chain mangle OVPN-MSS FORWARD -A 2>/dev/null; then
        if (( OVPN_MSS > 0 )); then
            for dir in -i -o; do
                iptables -t mangle -A OVPN-MSS $dir 'tun+' -p tcp --tcp-flags SYN,RST SYN \
                    -m tcpmss --mss "$(( OVPN_MSS + 1 )):65535" -j TCPMSS --set-mss "$OVPN_MSS" \
                    || warn "Cannot clamp the TCP MSS (is xt_TCPMSS available on the host?) - continuing without it"
            done
        fi
    else
        warn "No mangle table on this host - the TCP MSS is left alone"
    fi

    for c in nat:OVPN-NAT filter:OVPN-INPUT filter:OVPN-FORWARD filter:OVPN-ACCEPT mangle:OVPN-MSS; do
        iptables -t "${c%%:*}" -S "${c#*:}" 2>/dev/null | sed 's/^/    /' || true
    done
    for c in OVPN-INPUT OVPN-FORWARD; do
        ip6tables -S "$c" 2>/dev/null | sed 's/^/    (IPv6) /' || true
    done
}

# True while the rules of firewall() are in place. A firewall reload on the host
# or a Docker restart can remove them behind our back.
firewall_intact() {
    iptables -t nat -C POSTROUTING -j OVPN-NAT 2>/dev/null \
        && iptables -t nat -S OVPN-NAT 2>/dev/null | grep -q MASQUERADE \
        && iptables -C INPUT -j OVPN-INPUT 2>/dev/null \
        && iptables -C OVPN-INPUT -i 'tun+' -s "$GUEST_SUB" -j DROP 2>/dev/null \
        && iptables -C "$(forward_first)" -j OVPN-FORWARD 2>/dev/null \
        && iptables -C FORWARD -j OVPN-ACCEPT 2>/dev/null \
        && iptables -C OVPN-ACCEPT -i 'tun+' -j ACCEPT 2>/dev/null
}

# --------------------------------------------------------------------------
# 3. Run OpenVPN under a supervisor loop
# --------------------------------------------------------------------------
# Copy-and-truncate: OpenVPN keeps the log open (O_APPEND), so this also works
# while it runs.
rotate_log() {
    local f=$LOG_DIR/openvpn.log
    [[ -f $f ]] || return 0
    if (( $(stat -c %s "$f") > OVPN_LOG_MAX_BYTES )); then
        cp -f "$f" "$f.1" && : > "$f"
    fi
}

if [[ $OVPN_LOG_STDOUT = 1 ]]; then
    touch "$LOG_DIR/openvpn.log"
    tail -n 0 -F "$LOG_DIR/openvpn.log" 2>/dev/null &
    TAIL_PID=$!
fi

STOP=0
OVPN_PID=
on_term() {
    STOP=1
    log "Received stop signal - shutting down OpenVPN"
    [[ -n $OVPN_PID ]] && kill -TERM "$OVPN_PID" 2>/dev/null || true
}
trap on_term TERM INT

# A DCO (kernel "ovpn") interface is a plain netdevice: it outlives an OpenVPN
# that did not exit cleanly and, in the host's namespace, keeps the tun0 name
# and the VPN subnet route. The next OpenVPN then gets tun1 while replies to
# clients are routed into the dead tun0. Remove our own leftovers: ovpn
# interfaces with no IPv4 address or with the server's tunnel address.
clean_stale_dco() {
    local net addr dev
    net=$(sed -n 's/^[[:space:]]*server[[:space:]]\+\([0-9.]\+\)[[:space:]].*/\1/p' "$SERVER_CONF" | head -1)
    [[ -n $net ]] || return 0
    addr=${net%.*}.$(( ${net##*.} + 1 ))
    for dev in $(ip -o link show type ovpn 2>/dev/null | awk -F': ' '{print $2}' | cut -d@ -f1); do
        if ! ip -o -4 addr show dev "$dev" | grep -q . || ip -o -4 addr show dev "$dev" | grep -q " $addr/"; then
            log "Removing leftover DCO interface $dev"
            ip link del "$dev" || true
        fi
    done
}

# Per-device addresses (bin/client-access.sh): the guest range and netmask for
# the script, and an empty lease directory, since no client is connected yet.
ip2int() { local IFS=.; set -- $1; echo $(( ($1 << 24) + ($2 << 16) + ($3 << 8) + $4 )); }
int2ip() { echo "$(( $1 >> 24 & 255 )).$(( $1 >> 16 & 255 )).$(( $1 >> 8 & 255 )).$(( $1 & 255 ))"; }
prepare_access() {
    local net=$(ip2int "${GUEST_SUB%/*}") size=$(( 1 << (32 - ${GUEST_SUB#*/}) ))
    local mask=$(sed -n 's/^[[:space:]]*server[[:space:]]\+[0-9.]\+[[:space:]]\+\([0-9.]\+\).*/\1/p' "$SERVER_CONF" | head -1)
    # "ifconfig-ipv6 fd00:70::1/64 ..." -> V6_BASE=fd00:70:: V6_BITS=64 V6_GW=fd00:70::1
    local v6=$(sed -n 's/^[[:space:]]*ifconfig-ipv6[[:space:]]\+\([0-9a-fA-F:]*::\)\([0-9a-fA-F]\+\)\/\([0-9]\+\).*/\1 \2 \3/p' "$SERVER_CONF" | head -1)
    local v6base v6host v6bits; read -r v6base v6host v6bits <<< "$v6"
    printf 'GUEST_FIRST=%s\nGUEST_LAST=%s\nNETMASK=%s\nV6_BASE=%s\nV6_BITS=%s\nV6_GW=%s\nMAX_DEVICES=%d\n' \
        "$(int2ip $(( net + 1 )))" "$(int2ip $(( net + size - 2 )))" "${mask:-255.255.255.0}" \
        "$v6base" "$v6bits" "${v6base:+$v6base$v6host}" "$OVPN_MAX_DEVICES" > /tmp/openvpn-access.env
    rm -rf /tmp/openvpn-leases
    install -d -o nobody -m 700 /tmp/openvpn-leases
}


# The disconnect script releases a device's lease, but OpenVPN does not run it
# for a client it turns away after the connect script (no common cipher, ...).
# Release the leases of addresses that no connected client has.
reap_leases() {
    local status clients f ip
    status=$(sed -n 's/^[[:space:]]*status[[:space:]]\+\([^[:space:]#]\+\).*/\1/p' "$SERVER_CONF" | head -1)
    [[ -n $status ]] || return 0
    [[ $status = /* ]] || status=$OPENVPN_DIR/$status
    [[ -n $(find "$status" -mmin -1 2>/dev/null) ]] || return 0     # only against a current client list
    clients=$(cat "$status")        # one read: OpenVPN rewrites the file in place
    for f in $(find /tmp/openvpn-leases -type f -mmin +1 2>/dev/null); do
        ip=${f##*/}
        if ! grep -qE "(^|[[:space:],])${ip//./\\.}([[:space:],]|\$)" <<< "$clients"; then
            log "Releasing the address $ip: its client is gone"
            rm -f "$f"
        fi
    done
}

# Once a minute while OpenVPN runs. Nothing here may end the script.
UNHEALTHY=0
maintain() {
    rotate_log || warn "Cannot rotate $LOG_DIR/openvpn.log (is the disk full?)"
    reap_leases || true
    if ! firewall_intact; then
        warn "The firewall rules are gone (a firewall reload on the host?) - installing them again"
        firewall || warn "Could not install the firewall rules"
    fi
    # Docker marks a container unhealthy but does not restart it, so a hung
    # OpenVPN (process alive, status file no longer written) is restarted here.
    if /opt/app/bin/healthcheck.sh; then
        UNHEALTHY=0
    elif (( ++UNHEALTHY >= 3 )); then
        warn "OpenVPN has stopped writing its status file - restarting it"
        kill -KILL "$OVPN_PID" 2>/dev/null || true
        UNHEALTHY=0
    fi
}

while :; do
    rotate_log || warn "Cannot rotate $LOG_DIR/openvpn.log (is the disk full?)"
    clean_stale_dco
    firewall
    prepare_access
    (( STOP )) && break         # a stop signal during the steps above
    log "Starting OpenVPN"
    /usr/sbin/openvpn --cd "$OPENVPN_DIR" --script-security 2 --config "$SERVER_CONF" &
    OVPN_PID=$!
    if (( STOP )); then kill -TERM "$OVPN_PID" 2>/dev/null || true; fi     # ... or right before this line
    UNHEALTHY=0
    # Wait for OpenVPN to exit, waking up once a minute for maintain(). A stop
    # signal interrupts the wait; on_term then ends OpenVPN.
    while :; do
        sleep 60 &
        tick=$!
        wait -n -p who "$OVPN_PID" "$tick" || true      # a signal leaves "who" unset
        kill "$tick" 2>/dev/null || true
        wait "$tick" 2>/dev/null || true
        if [[ ${who:-} == "$OVPN_PID" ]] || ! kill -0 "$OVPN_PID" 2>/dev/null; then break; fi
        if [[ ${who:-} == "$tick" ]]; then maintain; fi
    done
    wait "$OVPN_PID" && rc=0 || rc=$?
    OVPN_PID=
    if (( STOP )); then
        log "OpenVPN stopped (exit code $rc)"
        break
    fi
    if (( rc == 0 )); then
        log "OpenVPN exited (restart requested) - restarting in 2s"
        pause=2
    else
        warn "OpenVPN exited with code $rc - restarting in 5s (check $LOG_DIR/openvpn.log)"
        pause=5
    fi
    sleep "$pause" &
    wait $! || true             # a stop signal ends the pause
    (( STOP )) && break
done

kill ${TAIL_PID:-} 2>/dev/null || true
exit 0
