#!/bin/bash
# Remove the artefacts of a revoked (or expired) client.
#
#   rmcert.sh <name>
#
# Removes the .ovpn profile, the 2FA secret and QR code, and the static IP
# assignment. The PKI database (pki/index.txt) and the revoked certificate
# under pki/revoked/ are deliberately left untouched: the CRL is generated
# from index.txt, and dropping a revoked entry would make that certificate
# valid again until it expires.
set -euo pipefail

OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
PKI_DIR=${EASYRSA_PKI:-$OPENVPN_DIR/pki}
BIN_DIR=$(cd "$(dirname "$0")" && pwd)
NAME=${1:-}

die() { echo "rmcert: $*" >&2; exit 1; }

[[ $NAME =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$ ]] || die "invalid client name '$NAME'"
[[ $NAME != server && $NAME != ca ]] || die "refusing to remove '$NAME'"

if [[ -f $PKI_DIR/issued/$NAME.crt ]]; then
    # A certificate file still exists: only allow removal when it has expired.
    if openssl x509 -in "$PKI_DIR/issued/$NAME.crt" -noout -checkend 0 >/dev/null 2>&1; then
        die "client '$NAME' still has a valid certificate; revoke it first (revoke.sh $NAME)"
    fi
fi

rm -f "$OPENVPN_DIR/clients/$NAME.ovpn" "$OPENVPN_DIR/clients/$NAME-2fa.png" "$OPENVPN_DIR/clients/$NAME.png"
rm -f "$OPENVPN_DIR/staticclients/$NAME"
"$BIN_DIR/oath-sec-rm.sh" "$NAME"
echo "Removed profile, static IP and 2FA data of '$NAME'."
