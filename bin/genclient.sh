#!/bin/bash
# Create a client certificate and its .ovpn profile.
#
#   genclient.sh <name> [static_ip]
#
# Environment (optional):
#   OVPN_CERT_DAYS       certificate validity in days (default: EASYRSA_CERT_EXPIRE from pki/vars)
#   OVPN_KEY_PASSPHRASE  encrypt the private key with this passphrase
#
# A static IP is written to staticclients/<name> (ifconfig-push). Use an
# address from the guest subnet to restrict the client to internet-only access.
set -euo pipefail

OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
EASYRSA_DIR=${EASYRSA_DIR:-/usr/share/easy-rsa}
PKI_DIR=${EASYRSA_PKI:-$OPENVPN_DIR/pki}
BIN_DIR=$(cd "$(dirname "$0")" && pwd)
NAME=${1:-}
STATIC_IP=${2:-}

die() { echo "genclient: $*" >&2; exit 1; }

[[ $NAME =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$ ]] || die "invalid client name '$NAME' (allowed: letters, digits, _ . @ -)"
[[ $NAME != server && $NAME != ca ]] || die "'$NAME' is reserved"
for f in "$PKI_DIR/issued/$NAME.crt" "$PKI_DIR/reqs/$NAME.req" "$PKI_DIR/private/$NAME.key"; do
    [[ -e $f ]] && die "client '$NAME' already exists ($f)"
done
if [[ -n $STATIC_IP ]]; then
    [[ $STATIC_IP =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || die "invalid static IP '$STATIC_IP'"
fi

export EASYRSA_BATCH=1 EASYRSA_PKI=$PKI_DIR
opts=(--req-cn="$NAME")
[[ -n ${OVPN_CERT_DAYS:-} ]] && opts+=(--days="$OVPN_CERT_DAYS")

echo "Creating certificate for '$NAME'..."
if [[ -n ${OVPN_KEY_PASSPHRASE:-} ]]; then
    EASYRSA_PASSOUT="pass:$OVPN_KEY_PASSPHRASE" EASYRSA_PASSIN="pass:$OVPN_KEY_PASSPHRASE" \
        "$EASYRSA_DIR/easyrsa" "${opts[@]}" build-client-full "$NAME"
else
    "$EASYRSA_DIR/easyrsa" "${opts[@]}" build-client-full "$NAME" nopass
fi

if [[ -n $STATIC_IP ]]; then
    mask=$(sed -n 's/^[[:space:]]*server[[:space:]]\+[0-9.]\+[[:space:]]\+\([0-9.]\+\).*/\1/p' "$OPENVPN_DIR/server.conf" | head -1)
    mkdir -p "$OPENVPN_DIR/staticclients"
    echo "ifconfig-push $STATIC_IP ${mask:-255.255.255.0}" > "$OPENVPN_DIR/staticclients/$NAME"
    chmod 644 "$OPENVPN_DIR/staticclients/$NAME"
    echo "Static IP $STATIC_IP assigned"
fi

"$BIN_DIR/mkovpn.sh" "$NAME" >/dev/null
echo "Client profile written to $OPENVPN_DIR/clients/$NAME.ovpn"
