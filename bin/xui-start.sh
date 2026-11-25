#!/bin/sh
# Entry point of the xui service (3x-ui). The panel listens on XUI_LISTEN only (this host by
# default). On the first start it gets a random login and base path (printed once), its
# subscription server is switched off, and an API token for the OpenVPN UI goes to
# /etc/x-ui/openvpn-ui.json (./xui/openvpn-ui.json, mode 600).
set -eu
cd /app
./x-ui setting -listenIP "${XUI_LISTEN:-127.0.0.1}" >/dev/null

STATE=/etc/x-ui/openvpn-ui.json
if [ ! -s "$STATE" ]; then
    random() { head -c "$1" /dev/urandom | base64 | tr -d '/+=\n'; }
    user="admin-$(random 6)"
    pass="$(random 18)"
    base="/$(random 9)/"
    ./x-ui setting -username "$user" -password "$pass" -webBasePath "$base" >/dev/null
    # The subscription server listens on every address and the OpenVPN UI does not use it:
    # off at first start (it can be switched on again in the panel).
    python3 -c "
import sqlite3
db = sqlite3.connect('/etc/x-ui/x-ui.db')
if not db.execute(\"UPDATE settings SET value = 'false' WHERE key = 'subEnable'\").rowcount:
    db.execute(\"INSERT INTO settings (key, value) VALUES ('subEnable', 'false')\")
db.commit()"
    token=$(./x-ui setting -tokenName openvpn-ui -getApiToken | sed -n 's/^apiToken: //p')
    if [ -z "$token" ]; then
        echo "xui-start: 3x-ui printed no API token" >&2
        exit 1
    fi
    umask 077
    printf '{"base_path": "%s", "token": "%s"}\n' "$base" "$token" > "$STATE.tmp"
    mv "$STATE.tmp" "$STATE"
    echo "3x-ui panel login (shown only now): $user / $pass"
    echo "3x-ui panel address: http://${XUI_LISTEN:-127.0.0.1}:${XUI_PORT:-2053}$base"
fi
exec /app/DockerEntrypoint.sh
