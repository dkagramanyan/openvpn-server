#!/bin/bash
# Remove a client's two-factor authentication secret.
#
#   oath-sec-rm.sh <name>
set -euo pipefail

OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
OATH_SECRETS=$OPENVPN_DIR/clients/oath.secrets
NAME=${1:-}

[[ $NAME =~ ^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$ ]] || { echo "oath-sec-rm: invalid client name '$NAME'" >&2; exit 1; }

if [[ -f $OATH_SECRETS ]]; then
    { grep -v "^${NAME//./\\.}:" "$OATH_SECRETS" || true; } > "$OATH_SECRETS.tmp"
    mv -f "$OATH_SECRETS.tmp" "$OATH_SECRETS"
    chmod 644 "$OATH_SECRETS"
fi
rm -f "$OPENVPN_DIR/clients/$NAME-2fa.png"
