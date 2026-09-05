#!/bin/bash
# Renew a client certificate (same private key, new validity period).
#
#   renew.sh <name>
#
# Environment (optional):
#   OVPN_CERT_DAYS   validity of the new certificate in days
#
# The previous certificate stays valid until you run
#   revoke.sh --renewed <name>
# so the client keeps working until the new profile has been delivered.
set -euo pipefail

OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
EASYRSA_DIR=${EASYRSA_DIR:-/usr/share/easy-rsa}
PKI_DIR=${EASYRSA_PKI:-$OPENVPN_DIR/pki}
BIN_DIR=$(cd "$(dirname "$0")" && pwd)
NAME=${1:-}

die() { echo "renew: $*" >&2; exit 1; }

[[ $NAME =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$ ]] || die "invalid client name '$NAME'"
[[ $NAME != server && $NAME != ca ]] || die "refusing to renew '$NAME' from here"
[[ -f $PKI_DIR/issued/$NAME.crt ]] || die "client '$NAME' has no valid certificate"
[[ -f $PKI_DIR/renewed/issued/$NAME.crt ]] && die "'$NAME' already has a renewed certificate; revoke the previous one first (revoke.sh --renewed $NAME)"

export EASYRSA_BATCH=1 EASYRSA_PKI=$PKI_DIR
opts=()
[[ -n ${OVPN_CERT_DAYS:-} ]] && opts+=(--days="$OVPN_CERT_DAYS")

echo "Renewing certificate of '$NAME'..."
"$EASYRSA_DIR/easyrsa" "${opts[@]}" renew "$NAME"
"$BIN_DIR/mkovpn.sh" "$NAME" >/dev/null
echo "New profile written to $OPENVPN_DIR/clients/$NAME.ovpn"
echo "The previous certificate remains valid until: revoke.sh --renewed $NAME"
