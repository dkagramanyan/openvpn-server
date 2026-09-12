#!/bin/bash
# OpenVPN server container entrypoint.
#
#  1. Initialises the PKI on first start (CA, server cert, CRL, tls-crypt key).
#  2. Checks IPv4 forwarding and installs idempotent iptables rules.
#  3. Runs OpenVPN under a small supervisor loop so that the web UI can
#     restart the daemon through the management interface (signal SIGTERM)
#     without needing access to the Docker socket.
set -euo pipefail

OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
EASYRSA_DIR=${EASYRSA_DIR:-/usr/share/easy-rsa}
PKI_DIR=$OPENVPN_DIR/pki
LOG_DIR=/var/log/openvpn
SERVER_CONF=$OPENVPN_DIR/server.conf
MGMT_PW_FILE=$OPENVPN_DIR/config/management.pw

TRUST_SUB=${TRUST_SUB:-10.0.70.0/24}
GUEST_SUB=${GUEST_SUB:-10.0.71.0/24}
HOME_SUB=${HOME_SUB:-192.168.88.0/24}
OVPN_STRICT_FORWARD=${OVPN_STRICT_FORWARD:-1}
OVPN_LOG_STDOUT=${OVPN_LOG_STDOUT:-1}
OVPN_LOG_MAX_BYTES=${OVPN_LOG_MAX_BYTES:-10485760}
OVPN_CRL_RENEW_DAYS=${OVPN_CRL_RENEW_DAYS:-30}

log()  { printf '%s [entrypoint] %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*"; }
warn() { printf '%s [entrypoint] WARNING: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; }
die()  { printf '%s [entrypoint] ERROR: %s\n' "$(date '+%Y-%m-%d %H:%M:%S')" "$*" >&2; exit 1; }

export EASYRSA_BATCH=1
export EASYRSA_PKI=$PKI_DIR
easyrsa() { "$EASYRSA_DIR/easyrsa" "$@"; }

log "OpenVPN $(openvpn --version | head -1 | awk '{print $2}'), easy-rsa $(grep -m1 -oE 'v?[0-9]+\.[0-9]+\.[0-9]+' "$EASYRSA_DIR/ChangeLog" 2>/dev/null || echo '?')"
log "OpenVPN dir: $OPENVPN_DIR  PKI: $PKI_DIR"

[[ -f $SERVER_CONF ]] || die "$SERVER_CONF not found. Mount the repository at $OPENVPN_DIR."
mkdir -p "$PKI_DIR" "$LOG_DIR" "$OPENVPN_DIR"/{clients,config,staticclients,db}

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
    log "Building the server certificate"
    easyrsa --req-cn=server build-server-full server nopass
else
    log "PKI already initialised"
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
chmod 755 "$PKI_DIR" "$OPENVPN_DIR/staticclients"
chmod 644 "$OPENVPN_DIR/staticclients/"* 2>/dev/null || true
[[ -f $OPENVPN_DIR/clients/oath.secrets ]] && chmod 644 "$OPENVPN_DIR/clients/oath.secrets"
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

egress=${OVPN_EGRESS_IFACE:-$(ip -4 route show default 2>/dev/null | awk '{print $5; exit}')}
egress=${egress:-eth0}
log "Egress interface: $egress  trusted: $TRUST_SUB  guest: $GUEST_SUB  home: $HOME_SUB"

# ipt TABLE RULE... : append RULE to TABLE only if it is not already present.
ipt() {
    local table=$1; shift
    iptables -t "$table" -C "$@" 2>/dev/null || iptables -t "$table" -A "$@"
}

log "Configuring iptables in the current network namespace (the host's under network_mode: host)"
ipt nat POSTROUTING -s "$TRUST_SUB" -o "$egress" -j MASQUERADE
ipt nat POSTROUTING -s "$GUEST_SUB"  -o "$egress" -j MASQUERADE

# Guest subnet: no ICMP echo, no access to the home network.
ipt filter FORWARD -s "$GUEST_SUB" -p icmp --icmp-type echo-request -j DROP
ipt filter FORWARD -s "$GUEST_SUB" -p icmp --icmp-type echo-reply   -j DROP
ipt filter FORWARD -s "$GUEST_SUB" -d "$HOME_SUB" -j DROP

# Custom rules supplied by the user (appended after the guest rules so DROPs
# still take effect before the accept rules below).
for f in "$OPENVPN_DIR/fw-rules.sh" /opt/app/fw-rules.sh; do
    if [[ -s $f ]] && grep -qvE '^\s*(#|$)' "$f"; then
        log "Applying additional firewall rules from $f"
        bash "$f"
        break
    fi
done

if [[ $OVPN_STRICT_FORWARD = 1 ]]; then
    # Only VPN-originated traffic and replies to it are forwarded. Under
    # network_mode: host this sets the *host* FORWARD policy (the same value
    # Docker itself defaults to); set OVPN_STRICT_FORWARD=0 to leave it alone.
    ipt filter FORWARD -i 'tun+' -j ACCEPT
    ipt filter FORWARD -o 'tun+' -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -P FORWARD DROP
fi

log "NAT rules:";     iptables -t nat -S POSTROUTING | sed 's/^/    /'
log "Forward rules:"; iptables -S FORWARD | sed 's/^/    /'

# --------------------------------------------------------------------------
# 3. Run OpenVPN under a supervisor loop
# --------------------------------------------------------------------------
rotate_log() {
    local f=$LOG_DIR/openvpn.log
    if [[ -f $f ]] && (( $(stat -c %s "$f") > OVPN_LOG_MAX_BYTES )); then
        mv -f "$f" "$f.1"
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

while :; do
    rotate_log
    log "Starting OpenVPN"
    /usr/sbin/openvpn --cd "$OPENVPN_DIR" --script-security 2 --config "$SERVER_CONF" &
    OVPN_PID=$!
    rc=0
    while kill -0 "$OVPN_PID" 2>/dev/null; do
        wait "$OVPN_PID" && rc=0 || rc=$?
    done
    OVPN_PID=
    if (( STOP )); then
        log "OpenVPN stopped (exit code $rc)"
        break
    fi
    if (( rc == 0 )); then
        log "OpenVPN exited (restart requested) - restarting in 2s"
        sleep 2
    else
        warn "OpenVPN exited with code $rc - restarting in 5s (check $LOG_DIR/openvpn.log)"
        sleep 5
    fi
done

[[ -n ${TAIL_PID:-} ]] && kill "$TAIL_PID" 2>/dev/null || true
exit 0
