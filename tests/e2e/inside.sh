#!/bin/sh
# Runs inside the Docker-in-Docker container started by run.sh.
set -euo pipefail
cd /srv/openvpn

say()  { printf '\n== %s\n' "$*"; }
fail() { printf '\nFAILED: %s\n' "$*" >&2; docker logs --tail 40 openvpn 2>&1 | sed 's/^/    /' >&2; exit 1; }
api()  { docker exec openvpn-ui python /etc/openvpn/tests/e2e/api.py "$@"; }

NET=172.30.0          # clients; the server is reached at its gateway
[ -c /dev/net/tun ] || { mkdir -p /dev/net; mknod /dev/net/tun c 10 200; }
docker tag openvpn-server:e2e openvpn-server:local
docker tag openvpn-ui:e2e openvpn-ui:local
docker network create --subnet $NET.0/24 e2e >/dev/null

# Test settings: a short keepalive so a vanished client times out quickly, and
# OpenVPN's own mssfix off so that the firewall's clamp is what gets measured.
sed -i 's/^keepalive .*/keepalive 2 6/' server.conf
echo 'mssfix 0' >> server.conf
printf 'OPENVPN_ADMIN_PASSWORD=e2e-password\nOVPN_PUBLIC_HOST=%s\n' "$NET.1" > .env

up() {
    docker compose up -d --no-build 2>&1 | sed 's/^/    /'
    for _ in $(seq 90); do
        wget -qO- http://127.0.0.1:8080/healthz 2>/dev/null | grep -q '"openvpn":true' && return 0
        sleep 1
    done
    fail "the service did not come up"
}

# client NAME IP PROFILE [openvpn options]: an OpenVPN client in its own container
client() {
    name=$1 ip=$2 profile=$3; shift 3
    docker rm -f "$name" >/dev/null 2>&1 || true
    docker run -d --name "$name" --network e2e --ip "$ip" --privileged -v "/srv/e2e/$profile:/profile.ovpn:ro" \
        --entrypoint sh openvpn-server:local -c \
        'mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200; exec openvpn --config /profile.ovpn --mssfix 0 "$@"' \
        sh "$@" >/dev/null
    for _ in $(seq 40); do
        docker exec "$name" ip -4 addr show tun0 2>/dev/null | grep -q 'inet 10\.0\.70\.' && return 0
        sleep 0.5
    done
    docker logs "$name" 2>&1 | tail -20 >&2
    fail "client $name did not connect"
}

say "Start the service"
up
docker exec openvpn iptables -t mangle -S OVPN-MSS | grep -q 'set-mss 1400' || fail "no MSS clamp in the firewall"

say "Create clients"
mkdir -p /srv/e2e
api create alice
api create bob
api profile alice > /srv/e2e/alice.ovpn
api profile bob > /srv/e2e/bob.ovpn
grep -v ' udp$' /srv/e2e/alice.ovpn > /srv/e2e/alice-tcp.ovpn      # the TCP fallback only
grep -c '^remote ' /srv/e2e/alice.ovpn | grep -qx 2 || fail "the profile should list a UDP and a TCP remote"

# A web server behind a published port: reached through the tunnel, its traffic is forwarded.
docker run -d --name web -p 8000:8000 --entrypoint python openvpn-ui:local -m http.server 8000 >/dev/null
TARGET=$(ip -4 -o addr show eth0 | awk '{print $4}' | cut -d/ -f1)

say "alice over UDP: traffic through the tunnel, then a clean exit"
client alice-phone $NET.10 alice.ovpn --explicit-exit-notify 1
docker exec alice-phone wget -qO /dev/null -T 10 "http://$TARGET:8000/" || fail "no traffic through the tunnel"
docker exec alice-phone wget -qO- -T 10 http://10.0.70.1:8080/healthz | grep -q ok || fail "the server is not reachable through the tunnel"
sleep 12
docker stop -t 10 alice-phone >/dev/null

say "The firewall clamped the TCP segment size in both directions"
docker exec openvpn iptables -t mangle -L OVPN-MSS -v -n -x | sed 's/^/    /'
docker exec openvpn iptables -t mangle -L OVPN-MSS -v -n -x | awk '/TCPMSS/ && $1 > 0 {n++} END {exit n != 2}' \
    || fail "the MSS rules matched no packets"

say "alice over TCP from the same address"
sleep 6                                 # the server keeps a client that said goodbye for 5 s
client alice-phone $NET.10 alice-tcp.ovpn
docker exec alice-phone wget -qO /dev/null -T 10 "http://$TARGET:8000/" || fail "no traffic over TCP"
sleep 12
docker stop -t 10 alice-phone >/dev/null

say "bob vanishes without a word"
client bob-laptop $NET.20 bob.ovpn
sleep 12
docker kill bob-laptop >/dev/null

say "alice reconnects three times, a few seconds each"
for _ in 1 2 3; do
    client alice-phone $NET.10 alice.ovpn --explicit-exit-notify 1
    docker stop -t 10 alice-phone >/dev/null
done

say "Wait for the timeout and the collector"
sleep 30
api check || fail "the UI does not match what happened"

say "Backups: the UI's archive and the script's directory copy"
api backup
ARCHIVE=$(ls backups/openvpn-backup-*.tar.gz | tail -1)     # the first one was written by the daily task
[ "$(ls backups | wc -l)" -ge 2 ] || fail "the daily backup task wrote no archive"
docker run --rm -v /srv:/srv --entrypoint bash openvpn-ui:local /srv/openvpn/backup.sh -y -b /srv/openvpn /srv/copy | sed 's/^/    /'
[ -s /srv/copy/db/openvpn-ui.db ] && [ ! -e /srv/copy/db/openvpn-ui.db-wal ] || fail "the directory backup has no clean database copy"
[ -f /srv/copy/pki/private/ca.key ] && [ -d /srv/copy/guests ] || fail "the directory backup is incomplete"
api summary > /srv/e2e/before.json

say "Lose everything, restore from the archive"
docker compose down 2>&1 | sed 's/^/    /'
rm -rf pki/* clients/* staticclients/* guests db/openvpn-ui.db* config/management.pw .env
restore() { docker run --rm -v /srv:/srv --entrypoint bash openvpn-server:local /srv/openvpn/backup.sh -y -r /srv/openvpn "$1" | sed 's/^/    /'; }
restore /srv/openvpn/no-such-backup && fail "a restore from nothing must not succeed"
restore "/srv/openvpn/$ARCHIVE"
[ -f .env ] && [ -f pki/private/ca.key ] || fail "the restore left files missing"
up
api summary > /srv/e2e/after.json
cmp /srv/e2e/before.json /srv/e2e/after.json || { cat /srv/e2e/before.json /srv/e2e/after.json; fail "clients or history differ after the restore"; }

say "alice's old profile still connects"
client alice-phone $NET.10 alice.ovpn --explicit-exit-notify 1
docker exec alice-phone wget -qO- -T 10 http://10.0.70.1:8080/healthz | grep -q ok || fail "no traffic after the restore"
docker stop -t 10 alice-phone >/dev/null

printf '\nEND-TO-END TEST PASSED\n'
