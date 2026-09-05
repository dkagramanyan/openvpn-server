#!/bin/bash
# Revoke a client certificate and regenerate the CRL.
#
#   revoke.sh <name> [reason]              revoke the client's current certificate
#   revoke.sh --renewed <name> [reason]    revoke only the previous certificate of a
#                                          renewed client (see renew.sh)
#
# Reasons: unspecified keyCompromise CACompromise affiliationChanged superseded
#          cessationOfOperation certificateHold
#
# OpenVPN re-reads the CRL on every new connection, so revoked clients cannot
# reconnect immediately. Existing sessions are not cut: the web UI does that
# through the management interface, or restart the container.
set -euo pipefail

OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
EASYRSA_DIR=${EASYRSA_DIR:-/usr/share/easy-rsa}
PKI_DIR=${EASYRSA_PKI:-$OPENVPN_DIR/pki}

die() { echo "revoke: $*" >&2; exit 1; }

RENEWED_ONLY=0
if [[ ${1:-} = --renewed ]]; then RENEWED_ONLY=1; shift; fi
NAME=${1:-}
REASON=${2:-}

[[ $NAME =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$ ]] || die "invalid client name '$NAME'"
[[ $NAME != server && $NAME != ca ]] || die "refusing to revoke '$NAME'"

export EASYRSA_BATCH=1 EASYRSA_PKI=$PKI_DIR
easyrsa() { "$EASYRSA_DIR/easyrsa" "$@"; }

if [[ -f $PKI_DIR/renewed/issued/$NAME.crt ]]; then
    echo "Revoking previous (renewed) certificate of '$NAME'..."
    easyrsa revoke-renewed "$NAME" ${REASON:+"$REASON"}
elif (( RENEWED_ONLY )); then
    die "'$NAME' has no previous certificate pending revocation"
fi

if (( ! RENEWED_ONLY )); then
    [[ -f $PKI_DIR/issued/$NAME.crt ]] || die "client '$NAME' has no valid certificate"
    echo "Revoking certificate of '$NAME'..."
    easyrsa revoke "$NAME" ${REASON:+"$REASON"}
    rm -f "$OPENVPN_DIR/clients/$NAME.ovpn"
fi

echo "Regenerating CRL..."
easyrsa gen-crl
chmod 644 "$PKI_DIR/crl.pem"
echo "Done."
