#!/bin/bash
# Assemble a client profile: clients/<name>.ovpn
#
#   mkovpn.sh <name>
#
# The profile is config/client.conf followed by the CA certificate, the
# client certificate and key, and the control channel key, all inline: the
# shared tls-crypt (or tls-auth) key, or with tls-crypt-v2 a key of this
# client's own, generated on first use in pki/tc2/<name>.key.
# The server certificate's common name is pinned with verify-x509-name, and
# clients enrolled in two-factor authentication additionally get
# "auth-user-pass" so the OpenVPN client prompts for the TOTP code.
set -euo pipefail

OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
PKI_DIR=${EASYRSA_PKI:-$OPENVPN_DIR/pki}
NAME=${1:-}

die() { echo "mkovpn: $*" >&2; exit 1; }

[[ $NAME =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$ ]] || die "invalid client name '$NAME'"
CERT=$PKI_DIR/issued/$NAME.crt
KEY=$PKI_DIR/private/$NAME.key
[[ -f $CERT ]] || die "certificate $CERT not found"
[[ -f $KEY ]]  || die "private key $KEY not found"
[[ -f $OPENVPN_DIR/config/client.conf ]] || die "$OPENVPN_DIR/config/client.conf not found"

OUT=$OPENVPN_DIR/clients/$NAME.ovpn
mkdir -p "$OPENVPN_DIR/clients"

# Match the control-channel protection used by the server.
if grep -qE '^[[:space:]]*tls-crypt-v2[[:space:]]' "$OPENVPN_DIR/server.conf"; then
    TA_BLOCK=tls-crypt-v2
    TA_KEY=$PKI_DIR/tc2/$NAME.key
    if [[ ! -f $TA_KEY ]]; then
        mkdir -p "$PKI_DIR/tc2"
        openvpn --tls-crypt-v2 "$PKI_DIR/tc2-server.key" --genkey tls-crypt-v2-client "$TA_KEY" >/dev/null
        chmod 600 "$TA_KEY"
    fi
elif grep -qE '^[[:space:]]*tls-auth[[:space:]]' "$OPENVPN_DIR/server.conf"; then
    TA_BLOCK=tls-auth TA_KEY=$PKI_DIR/ta.key
else
    TA_BLOCK=tls-crypt TA_KEY=$PKI_DIR/ta.key
fi

# Pin the server certificate name (taken from the actual server certificate).
SERVER_CN=$(openssl x509 -in "$PKI_DIR/issued/server.crt" -noout -subject -nameopt RFC2253 2>/dev/null \
            | sed -n 's/^subject=\(.*,\)\{0,1\}CN=\([^,]*\).*/\2/p')

{
    cat "$OPENVPN_DIR/config/client.conf"
    echo
    [[ -n $SERVER_CN ]] && echo "verify-x509-name $SERVER_CN name"
    if grep -qs "^${NAME//./\\.}:" "$OPENVPN_DIR/clients/oath.secrets"; then
        echo "# Two-factor authentication: username is the client name, password is the TOTP code"
        echo "auth-user-pass"
    fi
    [[ $TA_BLOCK = tls-auth ]] && echo "key-direction 1"
    echo "<ca>";   openssl x509 -in "$PKI_DIR/ca.crt"; echo "</ca>"
    echo "<cert>"; openssl x509 -in "$CERT";           echo "</cert>"
    echo "<key>";  cat "$KEY";                          echo "</key>"
    echo "<$TA_BLOCK>"; grep -v '^#' "$TA_KEY"; echo "</$TA_BLOCK>"
} > "$OUT.tmp"
chmod 600 "$OUT.tmp"
mv -f "$OUT.tmp" "$OUT"
echo "$OUT"
