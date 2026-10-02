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
# turned_away NAME IP PROFILE: the same client, which the server has to refuse
turned_away() {
    docker rm -f "$1" >/dev/null 2>&1 || true
    docker run -d --name "$1" --network e2e --ip "$2" --privileged -v "/srv/e2e/$3:/profile.ovpn:ro" \
        --entrypoint sh openvpn-server:local -c \
        'mkdir -p /dev/net; [ -c /dev/net/tun ] || mknod /dev/net/tun c 10 200; exec openvpn --config /profile.ovpn' >/dev/null
    for _ in $(seq 40); do
        docker exec "$1" ip -4 addr show tun0 2>/dev/null | grep -q 'inet 10\.0\.70\.' && fail "client $1 was let in"
        docker logs "$1" 2>&1 | grep -q AUTH_FAILED && return 0
        sleep 0.5
    done
    docker logs "$1" 2>&1 | tail -20 >&2
    fail "client $1 was neither let in nor refused"
}
vpn_ip()   { docker exec "$1" ip -4 -o addr show tun0 | awk '{print $4}' | cut -d/ -f1; }
reaches()  { docker exec "$1" wget -qO /dev/null -T 4 "http://$2/" 2>/dev/null; }
fw()       { docker exec openvpn iptables "$@"; }

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

say "A guest reaches the internet and nothing else; a full client reaches the home networks"
# Three networks behind the server, each with a web server: the home LAN (HOME_SUB), a network
# server.conf pushes a route to, and a public one that stands for the internet. "nat-unprotected"
# makes Docker route into them like a plain LAN instead of dropping what comes from elsewhere.
for net in home:170.134.51 routed:171.134.51 inet:198.51.100; do
    docker network create -o com.docker.network.bridge.gateway_mode_ipv4=nat-unprotected \
        --subnet "${net#*:}.0/24" "${net%%:*}" >/dev/null
    docker run -d --name "web-${net%%:*}" --network "${net%%:*}" --ip "${net#*:}.10" --entrypoint python \
        openvpn-ui:local -m http.server 8000 >/dev/null
done
iptables -S DOCKER-USER | sed -n 2p | grep -q OVPN-FORWARD || fail "the guest rules do not run first"
api create gina guest
api profile gina > /srv/e2e/gina.ovpn
api static alice 10.0.70.100
client alice-phone $NET.10 alice.ovpn --explicit-exit-notify 1
client gina-phone $NET.30 gina.ovpn --explicit-exit-notify 1
[ "$(vpn_ip alice-phone)" = 10.0.70.100 ] || fail "alice did not get her static address"
vpn_ip gina-phone | grep -qE '^10\.0\.70\.(1[3-9][0-9]|12[89]|2[0-4][0-9]|25[0-4])$' || fail "the guest got $(vpn_ip gina-phone), outside the guest range"
for target in 170.134.51.10:8000 171.134.51.10:8000 198.51.100.10:8000 10.0.70.1:8080 198.51.100.1:8080; do
    reaches alice-phone $target || fail "alice (full access) cannot reach $target"
done
reaches gina-phone 198.51.100.10:8000 || fail "the guest cannot reach the internet"
# ... not the home networks, not the server host (its tunnel address or another one of its
# addresses, reached through the tunnel), not a port the host publishes
for target in 170.134.51.10:8000 171.134.51.10:8000 10.0.70.1:8080 198.51.100.1:8080 "$TARGET:8000"; do
    reaches gina-phone $target && fail "the guest reaches $target"
done
docker exec gina-phone ping -c 1 -W 2 10.0.70.100 >/dev/null 2>&1 && fail "the guest can ping another client"
docker exec openvpn ip6tables -S OVPN-INPUT | grep -q -- '-s fd00:70::/64 -i tun+ -j DROP' || fail "no IPv6 rule for the tunnel"
echo "    guest $(vpn_ip gina-phone): internet only"

say "One certificate on two devices: the second gets an address of its own"
client alice-laptop $NET.11 alice.ovpn --explicit-exit-notify 1
vpn_ip alice-laptop | grep -qE '^10\.0\.70\.([2-9]|[1-9][0-9])$' || fail "the second device got $(vpn_ip alice-laptop), not a pool address"
reaches alice-laptop 198.51.100.10:8000 && reaches alice-phone 198.51.100.10:8000 || fail "two devices of one client do not both work"
api live alice 2

say "A revoked client is cut off and cannot come back"
api create carl
api profile carl > /srv/e2e/carl.ovpn
client carl-pc $NET.40 carl.ovpn
api revoke carl
for _ in $(seq 30); do reaches carl-pc 198.51.100.10:8000 || break; sleep 1; done
reaches carl-pc 198.51.100.10:8000 && fail "the revoked client still has traffic"
docker restart carl-pc >/dev/null        # a fresh attempt with the revoked certificate
api rejected carl "certificate revoked"
docker exec carl-pc ip -4 addr show tun0 2>/dev/null | grep -q 'inet ' && fail "the revoked client was let in"

say "The firewall follows server.conf when OpenVPN is restarted from the UI"
fw -S OVPN-FORWARD | grep -q -- '-d 170.134.51.1/32 .*--dport 53 -j ACCEPT' || fail "no DNS rule for guests"
api dns 170.134.51.1 198.51.100.53
for _ in $(seq 30); do fw -S OVPN-FORWARD | grep -q 198.51.100.53 && break; sleep 1; done    # 2 s pause, then the restart
fw -S OVPN-FORWARD | grep -q -- '-d 198.51.100.53/32 .*--dport 53 -j ACCEPT' || fail "the guest DNS rule did not follow server.conf"
fw -S OVPN-FORWARD | grep -q -- '-d 170.134.51.1/32 .*--dport 53' && fail "the old guest DNS rule is still there"
fw -S OVPN-FORWARD | grep -q -- '-d 171.134.51.0/24 -j DROP' || fail "guests are not blocked from the pushed route"

say "Rules removed behind its back and a lease nobody holds are repaired within a minute"
for _ in $(seq 40); do [ -n "$(docker exec openvpn ls /tmp/openvpn-leases)" ] && break; sleep 1; done    # the clients are back
fw -F OVPN-INPUT
fw -t nat -F OVPN-NAT
docker exec openvpn sh -c 'echo "ghost 192.0.2.1 9" > /tmp/openvpn-leases/10.0.70.200 && touch -d @1000000000 /tmp/openvpn-leases/10.0.70.200'
for _ in $(seq 80); do
    fw -S OVPN-INPUT | grep -q DROP && fw -t nat -S OVPN-NAT | grep -q MASQUERADE \
        && ! docker exec openvpn test -e /tmp/openvpn-leases/10.0.70.200 && break
    sleep 1
done
fw -S OVPN-INPUT | grep -q DROP && fw -t nat -S OVPN-NAT | grep -q MASQUERADE || fail "the firewall was not restored"
docker exec openvpn test -e /tmp/openvpn-leases/10.0.70.200 && fail "the stale lease was not released"
docker exec openvpn test -e /tmp/openvpn-leases/10.0.70.100 || fail "the lease of a connected client was released"
[ "$(docker inspect -f '{{.RestartCount}}' openvpn-ui)" = 0 ] || fail "the UI restarted itself"

say "At most OVPN_MAX_DEVICES connections per certificate"
docker rm -f alice-phone alice-laptop gina-phone carl-pc >/dev/null
sed -i 's/# OVPN_MAX_DEVICES: "10"/OVPN_MAX_DEVICES: "2"/' docker-compose.yml
grep -q '^ *OVPN_MAX_DEVICES: "2"' docker-compose.yml || fail "docker-compose.yml has no OVPN_MAX_DEVICES line to set"
up
client alice-phone $NET.10 alice.ovpn --explicit-exit-notify 1
client alice-laptop $NET.11 alice.ovpn --explicit-exit-notify 1
turned_away alice-tablet $NET.12 alice.ovpn
api rejected alice "too many devices"
docker stop -t 10 alice-phone alice-laptop >/dev/null
sleep 15                                # every session closed and recorded before the backup

say "Backups: the UI's archive and the script's directory copy"
api backup
ARCHIVE=$(ls backups/openvpn-backup-*.tar.gz | tail -1)     # the first one was written by the daily task
[ "$(ls backups | wc -l)" -ge 2 ] || fail "the daily backup task wrote no archive"
docker run --rm -v /srv:/srv --entrypoint bash openvpn-ui:local /srv/openvpn/backup.sh -y -b /srv/openvpn /srv/copy | sed 's/^/    /'
[ -s /srv/copy/db/openvpn-ui.db ] && [ ! -e /srv/copy/db/openvpn-ui.db-wal ] || fail "the directory backup has no clean database copy"
[ -f /srv/copy/pki/private/ca.key ] && [ -d /srv/copy/guests ] || fail "the directory backup is incomplete"
api summary > /srv/e2e/before.json

say "Lose everything, restore from the archive"
docker stop -t 30 openvpn >/dev/null
docker logs --tail 5 openvpn 2>&1 | grep -q 'OpenVPN stopped (exit code 0)' && [ "$(docker inspect -f '{{.State.ExitCode}}' openvpn)" = 0 ] \
    || fail "a stop signal did not shut OpenVPN down cleanly"
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

say "Encrypted backups"
docker run --rm -v /srv/e2e:/k --entrypoint age-keygen openvpn-ui:local -o /k/backup-key.txt 2>/dev/null
echo "OVPN_BACKUP_RECIPIENT=$(grep -o 'age1[a-z0-9]*' /srv/e2e/backup-key.txt)" >> .env
up
api backup
SEALED=$(ls backups/openvpn-backup-*.tar.gz.age | tail -1)
gzip -t "$SEALED" 2>/dev/null && fail "the archive is not encrypted"
restore_to() { docker run --rm -v /srv:/srv --entrypoint bash openvpn-ui:local /srv/openvpn/backup.sh -y "$@" 2>&1 | sed 's/^/    /'; }
restore_to -r /srv/unsealed "/srv/openvpn/$SEALED" && fail "an encrypted archive must not open without the key"
mkdir -p /srv/unsealed
restore_to -i /srv/e2e/backup-key.txt -r /srv/unsealed "/srv/openvpn/$SEALED"
cmp pki/private/ca.key /srv/unsealed/pki/private/ca.key || fail "the decrypted archive does not hold the CA key"
[ -s /srv/unsealed/db/openvpn-ui.db ] || fail "the decrypted archive has no database"

say "A first start that was interrupted after the CA was built"
docker compose down 2>&1 | sed 's/^/    /'
rm -rf pki/* config/management.pw
docker run --rm -v /srv/openvpn:/etc/openvpn -w /etc/openvpn --entrypoint bash openvpn-server:local -c '
    export EASYRSA_BATCH=1
    EASYRSA_PKI=/tmp/pki /usr/share/easy-rsa/easyrsa init-pki >/dev/null && cp -a /tmp/pki/. pki/ && cp config/easy-rsa.vars pki/vars
    EASYRSA_PKI=/etc/openvpn/pki /usr/share/easy-rsa/easyrsa build-ca nopass >/dev/null 2>&1'
[ -f pki/ca.crt ] && [ ! -e pki/issued/server.crt ] || fail "could not prepare a PKI with only a CA"
up
[ -f pki/issued/server.crt ] || fail "the server certificate was not built"

printf '\nEND-TO-END TEST PASSED\n'
