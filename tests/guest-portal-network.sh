#!/bin/bash
# Real DNAT/filter/NAT checks in disposable user/network namespaces; no Docker/root.
set -euo pipefail
if [[ ${GUEST_PORTAL_NETNS_TEST:-} != 1 ]]; then
    exec unshare --user --map-root-user --net env GUEST_PORTAL_NETNS_TEST=1 bash "$0"
fi
root=$(cd "$(dirname "$0")/.." && pwd)
scratch=$(mktemp -d)
guest_pid= target_pid= server_pid=
cleanup() {
    for pid in "$server_pid" "$guest_pid" "$target_pid"; do
        [[ -z $pid ]] || kill "$pid" 2>/dev/null || true
    done
    rm -rf "$scratch"
}
trap cleanup EXIT
unshare --net sleep 60 & guest_pid=$!
unshare --net sleep 60 & target_pid=$!
for pid in "$guest_pid" "$target_pid"; do
    for attempt in $(seq 100); do
        [[ $(readlink "/proc/$pid/ns/net") != $(readlink /proc/self/ns/net) ]] && break
        sleep 0.01
    done
done
ip link add tun0 type veth peer name guest0
ip link set guest0 netns "$guest_pid"
ip addr add 10.8.0.1/24 dev tun0
ip link set tun0 up
ip link add lan0 type veth peer name target0
ip link set target0 netns "$target_pid"
ip addr add 192.0.2.30/24 dev lan0
ip link set lan0 up
nsenter -t "$guest_pid" -n ip addr add 10.8.0.129/24 dev guest0
nsenter -t "$guest_pid" -n ip addr add 10.8.0.10/24 dev guest0
nsenter -t "$guest_pid" -n ip link set guest0 up
nsenter -t "$guest_pid" -n ip route add default via 10.8.0.1
nsenter -t "$target_pid" -n ip addr add 192.0.2.13/24 dev target0
nsenter -t "$target_pid" -n ip link set target0 up
# No route to the VPN subnet on the Pi: MASQUERADE must supply the return path.
sysctl -q -w net.ipv4.ip_forward=1
iptables -P FORWARD DROP
iptables -t nat -N OVPN-PORTAL
iptables -t nat -A PREROUTING -j OVPN-PORTAL
iptables -t nat -N OVPN-NAT
iptables -t nat -A POSTROUTING -j OVPN-NAT
iptables -N OVPN-FORWARD
iptables -A FORWARD -j OVPN-FORWARD
source "$root/bin/guest-portal.sh"
GUEST_SUB=10.8.0.128/25
GUEST_PORTAL_TARGET=192.0.2.13:9443
guest_portal_validate
guest_portal_rules -A
guest_portal_rules -C
iptables -A OVPN-FORWARD -s "$GUEST_SUB" -j DROP     # as the entrypoint: nothing else for guests
iptables -A FORWARD -i 'tun+' -j ACCEPT
iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -t nat -A OVPN-NAT -s 10.8.0.0/24 -o lan0 -j MASQUERADE
cat > "$scratch/server.py" <<'PY'
import http.server, socketserver, threading
class Server(http.server.ThreadingHTTPServer):
    def server_bind(self):
        socketserver.TCPServer.server_bind(self)
        self.server_name, self.server_port = self.server_address
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(str(self.server.server_port).encode())
    def log_message(self, *_): pass
for port in (443, 8080, 9443):
    server = Server(('192.0.2.13', port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
threading.Event().wait()
PY
nsenter -t "$target_pid" -n python3 "$scratch/server.py" & server_pid=$!
for attempt in $(seq 100); do
    curl --noproxy '*' -fsS --max-time 0.2 http://192.0.2.13:9443/ >/dev/null 2>&1 && break
    sleep 0.02
done
curl --noproxy '*' -fsS --max-time 1 http://192.0.2.13:9443/ >/dev/null
request() { nsenter -t "$guest_pid" -n curl --noproxy '*' --interface "$1" -fsS --max-time 1 "http://$2/"; }
# Any HTTPS destination of a guest lands on the portal listener.
[[ $(request 10.8.0.129 192.0.2.13:443) == 9443 ]]
[[ $(request 10.8.0.129 198.51.100.4:443) == 9443 ]]
for port in 8080 9443; do
    if request 10.8.0.129 "192.0.2.13:$port" 2>/dev/null; then
        echo "Guest reached forbidden direct port $port" >&2; exit 1
    fi
done
[[ $(request 10.8.0.10 192.0.2.13:443) == 443 ]]
[[ $(request 10.8.0.10 192.0.2.13:8080) == 8080 ]]
echo 'PASS: guest HTTPS goes to the portal listener, nothing else is reachable; full access unchanged'
