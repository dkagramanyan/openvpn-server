#!/bin/bash
# Enrol a client in two-factor authentication (TOTP).
#
#   oath-sec-gen.sh <name> [issuer]
#
# Generates a new secret, stores it in clients/oath.secrets (replacing any
# previous entry for the same name), prints the otpauth:// URI and, when
# qrencode is available, writes clients/<name>-2fa.png.
set -euo pipefail

OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
OATH_SECRETS=$OPENVPN_DIR/clients/oath.secrets
NAME=${1:-}
ISSUER=${2:-OpenVPN}

die() { echo "oath-sec-gen: $*" >&2; exit 1; }
[[ $NAME =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$ ]] || die "invalid client name '$NAME'"

# 160-bit secret, stored as hex (the format oathtool reads by default).
SECRET=$(head -c 20 /dev/urandom | od -An -tx1 | tr -d ' \n')
BASE32=$(oathtool --totp -v "$SECRET" | sed -n 's/^Base32 secret: //p')

mkdir -p "$OPENVPN_DIR/clients"
touch "$OATH_SECRETS"
{ grep -v "^${NAME//./\\.}:" "$OATH_SECRETS" || true; echo "$NAME:$SECRET"; } > "$OATH_SECRETS.tmp"
mv -f "$OATH_SECRETS.tmp" "$OATH_SECRETS"
chmod 644 "$OATH_SECRETS"   # must stay readable by the unprivileged OpenVPN user

label=$(printf '%s' "$ISSUER:$NAME" | sed 's/ /%20/g')
issuer=$(printf '%s' "$ISSUER" | sed 's/ /%20/g')
URI="otpauth://totp/$label?secret=$BASE32&issuer=$issuer&algorithm=SHA1&digits=6&period=30"
echo "$URI"

if command -v qrencode >/dev/null 2>&1; then
    qrencode -o "$OPENVPN_DIR/clients/$NAME-2fa.png" "$URI"
fi
