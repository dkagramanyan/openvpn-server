#!/bin/sh
# tests/iphone/run.sh: can an Apple relay profile be bound to ONE iPhone?
# Runs a second relay (ports 8463 tcp+udp) that logs client certificates, and a
# throwaway ACME server (8464 tcp) that gives each profile one certificate.
# The production relay (8443) is not touched. See tests/iphone/README.md.
#
#   tests/iphone/run.sh up                     build and start both test containers
#   tests/iphone/run.sh profile CLIENT VARIANT [both|h2|h3]
#                                              VARIANT: token | p12 | acme | acme-attest
#   tests/iphone/run.sh logs                   what the phone did (certificates, ACME steps)
#   tests/iphone/run.sh report                 tests/iphone/report.tar.gz to send back
#   tests/iphone/run.sh down                   stop and remove the test containers and data
set -eu
cd "$(dirname "$0")/../.."
RELAY=relay-device-test ACME=relay-device-acme VOLUME=relay-device-test
sql() { docker compose exec -T postgres psql -U postgres -d openvpn -tAc "$1"; }
# The host of the relay URL saved in Settings → Apple relay (what the phone already trusts).
host() {
    HOST=${RELAY_TEST_HOST:-$(sql "SELECT value FROM settings WHERE key = 'apple_relay'" 2>/dev/null \
        | python3 -c 'import json,sys,urllib.parse; s=sys.stdin.read().strip(); print(urllib.parse.urlsplit(json.loads(s)["url"]).hostname or "" if s else "")')}
    [ -n "$HOST" ] || { echo "No relay URL in Settings → Apple relay; set RELAY_TEST_HOST=relay.example.com" >&2; exit 1; }
}
# The relay's certificate folder, as docker-compose.yml finds it (.env may move it).
TLS_DIR=${APPLE_RELAY_TLS_DIR:-$(sed -n 's/^APPLE_RELAY_TLS_DIR=//p' .env 2>/dev/null | tail -1 | tr -d '"')}
TLS_DIR=${TLS_DIR:-./relay-tls}
case "$TLS_DIR" in /*) ;; *) TLS_DIR="$PWD/${TLS_DIR#./}" ;; esac

case "${1:-}" in
up)
    host
    docker build -q -f relay/Dockerfile -t openvpn-apple-relay:device-test .
    docker build -q -t openvpn-relay-device-test:local tests/iphone
    docker rm -f "$RELAY" "$ACME" >/dev/null 2>&1 || true
    docker run -d --name "$RELAY" --network host --read-only --tmpfs /tmp --cap-drop ALL \
        --security-opt no-new-privileges:true --no-healthcheck \
        -e RELAY_CLIENT_CERTS=log -e RELAY_TRANSPORT=http2+http3 -e RELAY_TEST_ORIGIN="https://$HOST:8463" \
        -e RELAY_BIND=:8463 -e RELAY_HTTP2_TLS_BIND=:8463 \
        -e RELAY_HTTP2_BIND=127.0.0.1:8465 -e RELAY_ADMIN_BIND=127.0.0.1:8466 \
        -e RELAY_AUTH_URL=http://127.0.0.1:8447/api/relay/authorize \
        -e RELAY_NETWORK_CONFIG=/etc/relay-network/proxies.conf \
        -v "$TLS_DIR:/tls:ro" -v "$PWD/config/network:/etc/relay-network:ro" \
        openvpn-apple-relay:device-test >/dev/null
    docker run -d --name "$ACME" --network host --read-only --tmpfs /tmp --cap-drop ALL \
        --security-opt no-new-privileges:true \
        -v "$TLS_DIR:/tls:ro" -v "$VOLUME:/state" \
        openvpn-relay-device-test:local serve -listen :8464 -base "https://$HOST:8464" >/dev/null
    sleep 3
    for c in "$RELAY" "$ACME"; do
        if [ "$(docker inspect -f '{{.State.Running}}' "$c")" != true ]; then
            docker logs "$c" 2>&1 | tail -5
            echo "$c did not start (a port of 8463-8466 taken?)" >&2; exit 1
        fi
    done
    docker ps --filter "name=relay-device-" --format '{{.Names}}: {{.Status}}'
    docker logs "$RELAY" 2>&1 | tail -3
    echo "Forward on the router: 8463 tcp+udp and 8464 tcp -> this host. Check: https://$HOST:8464/acme/directory"
    ;;
profile)
    client=${2:?client name}; variant=${3:?variant}; transport=${4:-both}
    case "$client" in *[!A-Za-z0-9_.-]*|'') echo "Bad client name: $client" >&2; exit 1 ;; esac
    host
    raw=$(sql "SELECT value FROM settings WHERE key = 'relay_client:$client'")
    secret=$(printf '%s' "$raw" | python3 -c 'import json,sys; s=sys.stdin.read().strip(); print(json.loads(s)["secret"] if s else "")')
    [ -n "$secret" ] || { echo "No relay credential for '$client': download its Apple relay profile once in the UI first." >&2; exit 1; }
    docker exec "$ACME" iphonetest profile -base "https://$HOST:8464" -relay "https://$HOST:8463" \
        -bearer "Bearer $client:$secret" -variant "$variant" -transport "$transport"
    ;;
logs)
    echo "== relay: client certificates per connection"
    docker logs "$RELAY" 2>&1 | grep 'client-cert' | tail -40 || true
    echo "== relay: last flows"
    docker logs "$RELAY" 2>&1 | grep '^.*relay {' | tail -5 | cut -c1-300 || true
    echo "== ACME server"
    docker exec "$ACME" cat /state/log.jsonl | python3 -c '
import json, sys
for line in sys.stdin:
    e = json.loads(line)
    extra = {k: e[k] for k in ("refused", "attestation", "csr", "issued_serial", "signature") if k in e}
    print(e["ts"][11:19], e["method"], e["path"][:40], e.get("status"), e.get("user_agent", "")[:40], json.dumps(extra)[:400])'
    echo "== grants (one per profile)"
    docker exec "$ACME" cat /state/grants.json
    ;;
report)
    tmp=$(mktemp -d)
    docker logs "$RELAY" > "$tmp/relay.log" 2>&1
    docker logs "$ACME" > "$tmp/acme-stdout.log" 2>&1
    docker exec "$ACME" sh -c 'cd /state && tar -c --exclude=ca.key --exclude=profiles .' | tar -x -C "$tmp"
    tar -czf tests/iphone/report.tar.gz -C "$tmp" .
    rm -rf "$tmp"
    echo "tests/iphone/report.tar.gz: logs only (no profiles, which hold the client token; no CA key)"
    ;;
down)
    docker rm -f "$RELAY" "$ACME" >/dev/null 2>&1 || true
    docker volume rm "$VOLUME" >/dev/null 2>&1 || true
    echo "removed"
    ;;
*)
    sed -n '2,15p' "$0"; exit 2 ;;
esac
