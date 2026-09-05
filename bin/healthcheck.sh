#!/bin/bash
# Container health check: OpenVPN must be running and, if a status file is
# configured, it must have been refreshed recently.
OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}

running=0
for p in /proc/[0-9]*; do
    [[ $(cat "$p/comm" 2>/dev/null) == openvpn ]] && { running=1; break; }
done
(( running )) || exit 1

status_file=$(sed -n 's/^[[:space:]]*status[[:space:]]\+\([^[:space:]#]\+\).*/\1/p' "$OPENVPN_DIR/server.conf" | head -1)
if [[ -n $status_file ]]; then
    [[ $status_file = /* ]] || status_file=$OPENVPN_DIR/$status_file
    [[ -n $(find "$status_file" -mmin -3 2>/dev/null) ]] || exit 1
fi
exit 0
