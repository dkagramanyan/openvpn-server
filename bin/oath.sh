#!/bin/bash
# Two-factor (TOTP) verification for OpenVPN.
#
# Used with:  auth-user-pass-verify /opt/app/bin/oath.sh via-file
#
# OpenVPN passes a temporary file containing the username on line 1 and the
# password (here: the 6-digit TOTP code) on line 2. The script exits 0 to
# accept the connection and 1 to reject it. It runs as the unprivileged
# OpenVPN user, so it must not need write access to anything but /tmp and
# the log file prepared by the entrypoint.
#
# Rules enforced:
#   * the username must equal the certificate common name (no borrowing
#     another user's token);
#   * users without an enrolled secret are rejected (never fail open);
#   * the code is checked with a +/-1 step window for clock drift;
#   * a code that was already accepted cannot be replayed;
#   * after 5 wrong codes in a row the client waits 5 minutes.

PASSFILE=$1
OPENVPN_DIR=${OPENVPN_DIR:-/etc/openvpn}
OATH_SECRETS=${OATH_SECRETS:-$OPENVPN_DIR/clients/oath.secrets}
LOG_FILE=${OATH_LOG:-/var/log/openvpn/oath.log}
USED_DIR=/tmp/openvpn-oath

user=$(sed -n '1p' "$PASSFILE" 2>/dev/null)
code=$(sed -n '2p' "$PASSFILE" 2>/dev/null)
cn=${common_name:-}

log()  { echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }
fail() { log "2FA FAIL user='$user' cn='$cn' from='${untrusted_ip:-?}' reason=$1"; exit 1; }

[[ -n $user ]]        || fail empty-username
[[ $user = "$cn" ]]   || fail username-does-not-match-certificate
[[ $code =~ ^[0-9]{6,8}$ ]] || fail malformed-code
[[ -r $OATH_SECRETS ]] || fail secrets-file-unreadable

secret=$(awk -F: -v u="$user" '$1 == u { print $2; exit }' "$OATH_SECRETS")
[[ -n $secret ]] || fail no-secret-enrolled

# The state of one client: codes accepted lately ("time code" lines) and the
# wrong codes in a row ("count time-of-the-last").
mkdir -p "$USED_DIR" 2>/dev/null
state=$USED_DIR/$(printf '%s' "$user" | sha256sum | cut -c1-32)
now=$(date +%s)
fails=0 last=0
[[ -f $state.fail ]] && read -r fails last < "$state.fail"
[[ $fails =~ ^[0-9]+$ && $last =~ ^[0-9]+$ ]] || { fails=0; last=0; }
(( now - last >= 300 )) && fails=0
(( fails >= 5 )) && fail too-many-wrong-codes

if ! oathtool --totp -w 1 "$secret" "$code" >/dev/null 2>&1; then
    echo "$(( fails + 1 )) $now" > "$state.fail" 2>/dev/null || true
    fail wrong-code
fi

# Replay protection: a code stays valid for up to 90 s, and may be used once.
if awk -v c="$code" -v t="$(( now - 120 ))" '$1 >= t && $2 == c { found = 1 } END { exit !found }' "$state" 2>/dev/null; then
    fail code-already-used
fi
{ tail -n 4 "$state" 2>/dev/null; echo "$now $code"; } > "$state.new" 2>/dev/null && mv -f "$state.new" "$state"
rm -f "$state.fail"

log "2FA OK user='$user' from='${untrusted_ip:-?}'"
exit 0
