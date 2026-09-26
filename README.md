# openvpn-server

OpenVPN server in Docker with a web UI for client management, live status and
per-client traffic statistics.

* **OpenVPN 2.7.7** and **easy-rsa 3.2.7**, built from the signed upstream
  release tarballs on Alpine 3.24 (38 MB image).
* **Web UI** (`ui/`): dashboard with live throughput and connected clients,
  per-client traffic history (minute/hour/day roll-ups), session history,
  certificate lifecycle (create, download, renew, revoke, delete), static IPs,
  TOTP two-factor authentication with QR enrolment, config editors, log viewer,
  audit log. No JavaScript dependencies, works offline, light and dark theme.
* **Security**: containers run unprivileged (`NET_ADMIN` only), the management
  interface stays on the host's `127.0.0.1` behind a generated password, `tls-crypt`,
  TLS 1.2+ with a pinned cipher list, EC (secp384r1) certificates, CRL
  auto-renewal, strict forwarding rules, no Docker socket in any container.

Originally based on [d3vilh/openvpn-server](https://github.com/d3vilh/openvpn-server);
the UI replaces d3vilh/openvpn-ui.

## Quick start

```shell
git clone https://github.com/dkagramanyan/openvpn-server
cd openvpn-server
cp .env.example .env        # set the admin password and your public host name
docker compose up -d --build
```

First start takes a few seconds: the entrypoint creates the CA, the server
certificate, the tls-crypt key and the CRL under `pki/`. Then:

| | Address |
|---|---|
| Web UI, on the server itself | **http://localhost:8080** |
| Web UI, from another machine | `http://<server-ip>:8080` |
| VPN endpoint for clients | `<server-ip>:1197/udp`, falling back to `1196/tcp` (the `local` lines of `server.conf`) |

Sign in as `admin` with the password from `.env`. If you left that empty, a
random one is printed once in `docker compose logs openvpn-ui`.

Reachable on the server but not from another machine? The containers use host
networking, so the host firewall applies to both ports - see
[Host networking](#host-networking).

Open **Settings** and confirm the public address (host and port) that is
written into client profiles, then create clients under **Clients**.

Put the UI behind an HTTPS reverse proxy for anything but a LAN; set
`OVPN_UI_SECURE_COOKIES=true` in `.env` when you do, and
`OVPN_UI_TRUSTED_PROXIES` to the proxy's address if it is not on the server
itself. `OVPN_UI_BIND` limits the UI to one address (e.g. the LAN one).

## Layout

```
server.conf          OpenVPN server configuration (mounted at /etc/openvpn)
config/client.conf   template for client profiles ("remote" line managed by the UI)
config/easy-rsa.vars easy-rsa settings used when a *new* PKI is created
config/management.pw generated management-interface password (git-ignored)
pki/                 easy-rsa PKI (CA, certificates, CRL, tls-crypt key)
clients/             generated .ovpn profiles, 2FA secrets and QR codes
staticclients/       per-client "ifconfig-push" files (static IPs)
db/                  UI database (sessions, traffic, audit log)
log/                 openvpn.log, openvpn-status.log, oath.log
bin/                 CLI scripts (also used by the UI)
ui/                  web UI (Python/FastAPI)
fw-rules.sh          your additional iptables rules, applied at start
backup.sh            backup / restore helper
```

## Host networking

Both containers run in the host's network namespace. Nothing is published, so
there is no port mapping to keep in sync:

| | Where it comes from |
|---|---|
| VPN ports | the `local` lines in `server.conf`, bound directly on the host |
| Web UI | host port `8080` |
| Management interface | `127.0.0.1:2080` on the host, behind a generated password |

Consequences worth knowing:

* **IPv4 forwarding must be enabled on the host.** The kernel rejects
  per-container network sysctls in this mode, so the container cannot set it:
  `sudo sysctl -w net.ipv4.ip_forward=1` (the Docker daemon normally enables it
  already). The entrypoint refuses to start otherwise and says so.
* **The host firewall now applies to incoming connections.** This is the one
  thing that catches people out. A published Docker port is reached through
  DNAT and the `FORWARD` chain, which is why it is famously unaffected by
  `firewalld` or `ufw`. A host-networked service is reached through `INPUT`,
  where those rules do apply, so the VPN port and the UI port have to be
  opened explicitly. With firewalld:

  ```shell
  sudo firewall-cmd --permanent --add-port=1197/udp   # the "local" lines of server.conf
  sudo firewall-cmd --permanent --add-port=1196/tcp
  sudo firewall-cmd --permanent --add-port=8080/tcp   # web UI
  sudo firewall-cmd --permanent --zone=trusted --add-interface=tun0
  sudo firewall-cmd --reload
  ```

  With ufw: `sudo ufw allow 1197/udp`, `sudo ufw allow 1196/tcp` and `sudo ufw allow 8080/tcp`.
* **The other firewall rules are the host's rules.** MASQUERADE, the
  guest-subnet `DROP`s and, with `OVPN_STRICT_FORWARD=1`, the `FORWARD` policy
  `DROP` are applied to the host (that policy is Docker's own default). Set
  `OVPN_STRICT_FORWARD=0` to leave the policy alone.
* `tun0` and the routes appear on the host, and OpenVPN sees real client
  addresses instead of the Docker bridge.
* Ports `8080` and the VPN port must be free on the host, and
  `127.0.0.1:2080` is reachable by anything running there, not only by these
  two containers. The management password file is `config/management.pw`
  (mode 600).

## The public address and the TCP fallback

OpenVPN listens on UDP and TCP at the same time (OpenVPN 2.7 multi-socket):

```
proto udp
local * 1197 udp     # fast, tried first
local * 1196 tcp     # for networks that block or mangle UDP
```

Every profile gets one `remote` line per socket, UDP first, and
`server-poll-timeout 10`: a client that gets no answer over UDP within 10 s
switches to TCP by itself, with the same certificate and the same VPN address.
Both ports must be forwarded by your router. Adding or removing a `local` line
in `server.conf` rewrites the profiles' `remote` lines to match.

| | Set in | Meaning |
|---|---|---|
| `local * <port> <proto>` | `server.conf` | what OpenVPN binds on the host |
| `remote <host> <port> <proto>` | host: **Settings** or `OVPN_PUBLIC_HOST`; port per protocol: **Settings** | what clients dial |

The public port defaults to the listening one; change it under Settings only
when a router forwards a different public port (the dashboard flags the
difference, because it is legal but usually a mistake). The protocols cannot
differ that way, so they always follow `server.conf`. Changes to the `local`
lines take effect on a plain restart: `docker compose restart`.

Environment variables of the `openvpn` service:

| Variable | Default | Purpose |
|---|---|---|
| `TRUST_SUB` | `10.0.70.0/24` | the `server` subnet (NAT) |
| `GUEST_SUB` | `10.0.70.128/25` | static IPs here get internet only (also given to the UI) |
| `HOME_SUB` | `170.134.51.0/24` | your LAN, hidden from guests |
| `GUEST_BLOCK` | RFC 1918, CGNAT, link-local | further ranges hidden from guests |
| `OVPN_EGRESS_IFACE` | default-route interface | interface used for MASQUERADE |
| `OVPN_STRICT_FORWARD` | `1` | only VPN-originated traffic and replies are forwarded |
| `OVPN_LOG_STDOUT` | `1` | mirror openvpn.log to `docker logs` |
| `OVPN_LOG_MAX_BYTES` | 10 MiB | rotate openvpn.log (checked every 5 min) above this size |
| `OVPN_CRL_RENEW_DAYS` | `30` | regenerate the CRL when it expires within this many days |

`.env` (see `.env.example`): `OPENVPN_ADMIN_USERNAME`, `OPENVPN_ADMIN_PASSWORD`,
`OVPN_PUBLIC_HOST`, `OVPN_UI_SECURE_COOKIES`, `OVPN_UI_BIND`,
`OVPN_UI_TRUSTED_PROXIES`.

## Web UI

* **Dashboard** - online clients with live download/upload rates, throughput
  for the last hour, traffic over the selected range (today, 24 h, 7/30/90
  days, all), top clients, warnings (unreachable server, expiring
  certificates/CRL, 2FA enforced without secrets).
* **Clients** - state (online, valid, expiring, expired, revoked), expiry,
  last seen, traffic in the selected range, session count. Create clients with
  optional validity, static IP, key passphrase, note and 2FA. Download the
  `.ovpn` profile (always regenerated from the current template), show the 2FA
  QR code, disconnect, renew, revoke, delete.
* **Sessions** - every connection with duration, source address, VPN IP and
  bytes, filterable by client.
* **Server** - OpenVPN version, management status, PKI expiry dates, CRL
  regeneration, 2FA enforcement switch, editors for `server.conf`,
  `client.conf` and easy-rsa vars (a `.bak` is kept), restart button, log
  viewer (openvpn.log, 2FA log, status file) and audit log.
* **Settings** - public address for profiles (host and a port per protocol;
  the protocols follow `server.conf`), admin password, theme.

Traffic is read every 5 s from the status file OpenVPN writes (`status ... 5`,
`status-version 3`; a management `status` command would be logged on every
poll), falling back to the management interface when there is none. It is stored per minute for two days, per hour for 90 days and per day forever.
Bytes are counted from the client's point of view: *download* is what the
server sent to the client.

Restarting OpenVPN from the UI sends `SIGTERM` through the management
interface; the container entrypoint supervises the process and starts it
again with the current `server.conf`. Revoking a certificate does not need a
restart: OpenVPN re-reads the CRL on every connection and the UI kills the
active session.

## CLI

All scripts live in `bin/` and are available in both containers as
`/opt/app/bin/*`:

```shell
docker exec openvpn /opt/app/bin/genclient.sh <name> [static_ip]   # OVPN_CERT_DAYS, OVPN_KEY_PASSPHRASE via env
docker exec openvpn /opt/app/bin/mkovpn.sh <name>                  # (re)build clients/<name>.ovpn
docker exec openvpn /opt/app/bin/renew.sh <name>                   # new cert, same key; old one stays valid
docker exec openvpn /opt/app/bin/revoke.sh [--renewed] <name> [reason]
docker exec openvpn /opt/app/bin/rmcert.sh <name>                  # remove profile/2FA/static IP of a revoked client
docker exec openvpn /opt/app/bin/oath-sec-gen.sh <name> [issuer]   # enrol 2FA, prints otpauth:// URI
docker exec openvpn /opt/app/bin/oath-sec-rm.sh <name>
```

`rmcert.sh` deliberately never edits `pki/index.txt`: the CRL is generated
from it, and dropping a revoked entry would make that certificate valid again.

## Subnets, static IPs and the firewall

`server 10.0.70.0 255.255.255.0 nopool` is one tunnel subnet: with
`topology subnet` OpenVPN only accepts static IPs inside it. Clients without a
static IP get an address from the pool `10.0.70.2-127` and full access. Choose
**Guest** in the New client dialog (the next free address from `GUEST_SUB`,
`10.0.70.128-254`, is assigned) or give a client a static IP from that range,
and it only gets the internet and the pushed DNS servers: the entrypoint drops its traffic
to `HOME_SUB`, the `GUEST_BLOCK` ranges (which include the other VPN clients),
its pings, and everything addressed to the server host itself. The UI refuses
static IPs outside the subnet, inside the pool or already taken.

The rules live in the chains `OVPN-NAT`, `OVPN-INPUT`, `OVPN-FORWARD` (hooked
into `DOCKER-USER` when Docker manages the firewall, else the top of
`FORWARD`) and `OVPN-ACCEPT` (end of `FORWARD`). They are flushed and rebuilt
on every start. `fw-rules.sh` runs in between; append your own rules to
`OVPN-FORWARD` there.

Note that `duplicate-cn` (in `server.conf`) lets several devices share one
profile, but a static IP can then only be used by one of them at a time, and
OpenVPN ignores `ifconfig-pool-persist` in that mode.

## Two-factor authentication

1. Enable 2FA per client (Clients → client → *Enable 2FA*) and let the user
   scan the QR code. The profile gains `auth-user-pass`.
2. Enforce it on the Server page and restart OpenVPN. This adds
   `auth-user-pass-verify /opt/app/bin/oath.sh via-file` and
   `auth-gen-token 43200` to `server.conf`.

`oath.sh` requires the username to equal the certificate's common name,
rejects clients without an enrolled secret, accepts one time-step of clock
drift and refuses a code that was already used. Attempts are logged to
`log/oath.log`. Secrets live in `clients/oath.secrets` (`name:hex`).

## Configuration notes (OpenVPN 2.7)

`server.conf` is the file you mount; the UI can edit it. Differences from
older setups worth knowing:

* `dh none` - ECDH is used, no DH parameters are generated.
* `tls-crypt pki/ta.key` - profiles embed `<tls-crypt>`; profiles made for a
  `tls-auth` server must be regenerated (download them again).
* `persist-key` is gone (always on in 2.7); `explicit-exit-notify` only
  affects the UDP socket.
* `push "block-outside-dns"` protects Windows clients from DNS leaks; other
  platforms log a harmless "Unrecognized option" line and continue.
* `management 127.0.0.1 2080 /etc/openvpn/config/management.pw` - keep the
  address and port, the UI depends on them. With host networking this is the
  host's loopback.
* The `local` sockets are bound directly on the host. A profile's `remote`
  line may name a different port when one is forwarded to the other, but never
  a different protocol - see [The public address](#the-public-address-and-the-tcp-fallback).
* Data-channel offload (DCO) is compiled in and used automatically when the
  host kernel provides the `ovpn` module (Linux 6.16+).

New PKIs use EC secp384r1 keys (`config/easy-rsa.vars`). An existing RSA PKI
keeps working; `pki/vars` inside the PKI is what easy-rsa reads.

## Backup

```shell
sudo ./backup.sh -b ~/openvpn-server ~/backup/openvpn-$(date +%F)
sudo ./backup.sh -r ~/openvpn-server ~/backup/openvpn-2026-09-05
```

## Development

```shell
cd ui && python -m pytest tests          # unit tests (parsers, DB roll-ups, auth)
docker compose build                     # rebuild both images
```
