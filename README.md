# openvpn-server

OpenVPN server in Docker with a web UI for client management, live status and
per-client traffic statistics.

* **OpenVPN 2.7.7** and **easy-rsa 3.2.6**, built from the signed upstream
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
| VPN endpoint for clients | `<server-ip>:1197/udp`, i.e. the `port` and `proto` set in `server.conf` |

Sign in as `admin` with the password from `.env`. If you left that empty, a
random one is printed once in `docker compose logs openvpn-ui`.

Reachable on the server but not from another machine? The containers use host
networking, so the host firewall applies to both ports - see
[Host networking](#host-networking).

Open **Settings** and confirm the public address (host and port) that is
written into client profiles, then create clients under **Clients**.

Put the UI behind an HTTPS reverse proxy for anything but a LAN; set
`OVPN_UI_SECURE_COOKIES=true` in `.env` when you do.

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

## docker-compose.yml

```yaml
services:
  openvpn:
    build: .
    network_mode: host            # VPN port comes from server.conf
    cap_add: [NET_ADMIN]
    devices: [/dev/net/tun:/dev/net/tun]
    environment:
      TRUST_SUB: "10.0.70.0/24"    # dynamic pool ("server" directive)
      GUEST_SUB: "10.0.71.0/24"    # static IPs from here get internet only
      HOME_SUB: "170.134.51.0/24"  # your LAN, hidden from guests
    volumes: ["./:/etc/openvpn", "./log:/var/log/openvpn"]

  openvpn-ui:
    build: {context: ., dockerfile: ui/Dockerfile}
    network_mode: host            # reaches the management interface on 127.0.0.1
    volumes: ["./:/etc/openvpn", "./log:/var/log/openvpn:ro"]
    cap_drop: [ALL]
    cap_add: [CHOWN, DAC_OVERRIDE, FOWNER]
    read_only: true
```

## Host networking

Both containers run in the host's network namespace. Nothing is published, so
there is no port mapping to keep in sync:

| | Where it comes from |
|---|---|
| VPN port | `port` (and `proto`) in `server.conf`, bound directly on the host |
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
  sudo firewall-cmd --permanent --add-port=1197/udp   # the "port" from server.conf
  sudo firewall-cmd --permanent --add-port=8080/tcp   # web UI
  sudo firewall-cmd --permanent --zone=trusted --add-interface=tun0
  sudo firewall-cmd --reload
  ```

  With ufw: `sudo ufw allow 1197/udp` and `sudo ufw allow 8080/tcp`.
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

## The public address

Three things look like "the port", and they are not the same thing:

| | Set in | Meaning |
|---|---|---|
| `port`, `proto` | `server.conf` | what OpenVPN binds on the host |
| `remote <host> <port>` | **Settings**, or `OVPN_PUBLIC_HOST` / `OVPN_PUBLIC_PORT` | what clients dial |
| the profile's protocol | nowhere: it follows `server.conf` | a forward can remap a port, never the protocol |

Host and port are deliberately separate from the listening address. Behind a
router or a relay, clients dial a public address that differs from the one
OpenVPN binds, and the forward may map one port onto another. The protocol
cannot differ that way, so it is never asked for twice: editing `proto` in
`server.conf` rewrites every profile to match.

Leave `OVPN_PUBLIC_PORT` empty to use the listening port. When the two do
differ, the dashboard says so, because it is legal but usually a mistake.

Changing `port` in `server.conf` takes effect on a plain restart, since no
port mapping is involved: `docker compose restart`.

Environment variables of the `openvpn` service:

| Variable | Default | Purpose |
|---|---|---|
| `TRUST_SUB` / `GUEST_SUB` / `HOME_SUB` | see above | NAT and guest firewall rules |
| `OVPN_EGRESS_IFACE` | default-route interface | interface used for MASQUERADE |
| `OVPN_STRICT_FORWARD` | `1` | only VPN-originated traffic and replies are forwarded |
| `OVPN_LOG_STDOUT` | `1` | mirror openvpn.log to `docker logs` |
| `OVPN_LOG_MAX_BYTES` | 10 MiB | rotate openvpn.log at restart above this size |
| `OVPN_CRL_RENEW_DAYS` | `30` | regenerate the CRL when it expires within this many days |

`.env` (see `.env.example`): `OPENVPN_ADMIN_USERNAME`, `OPENVPN_ADMIN_PASSWORD`,
`OVPN_PUBLIC_HOST`, `OVPN_PUBLIC_PORT`, `OVPN_UI_SECURE_COOKIES`.

`docker-compose-no-ui.yml` runs the server alone; use the scripts in `bin/`
via `docker exec` in that case.

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
* **Settings** - public address for profiles (host and port; the protocol
  follows `server.conf`), admin password, theme.

Traffic is collected every 5 s from the management interface (`status 3`),
stored per minute for two days, per hour for 90 days and per day forever.
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

Clients get an address from `TRUST_SUB` (`server 10.0.70.0 255.255.255.0`)
and full access. Give a client a static IP from `GUEST_SUB`
(`route 10.0.71.0 255.255.255.0`) - in the UI or with
`staticclients/<name>` containing `ifconfig-push 10.0.71.x 255.255.255.0` -
and it only gets internet access: the entrypoint drops ICMP echo from the
guest subnet and everything from it to `HOME_SUB`.

Additional rules go into `fw-rules.sh`; they are applied after the guest
rules and before the accept rules, so `DROP`s work as expected. All rules are
added with a `-C` check first and are therefore idempotent across restarts.

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
* `persist-key` is gone (always on in 2.7), `explicit-exit-notify` is not
  valid with `proto tcp`.
* `push "block-outside-dns"` protects Windows clients from DNS leaks; other
  platforms log a harmless "Unrecognized option" line and continue.
* `management 127.0.0.1 2080 /etc/openvpn/config/management.pw` - keep the
  address and port, the UI depends on them. With host networking this is the
  host's loopback.
* `port` and `proto` are bound directly on the host. A profile's `remote` line
  may name a different port when one is forwarded to the other, but never a
  different protocol - see [The public address](#the-public-address).
* Data-channel offload (DCO) is compiled in and used automatically when the
  host kernel provides the `ovpn` module (Linux 6.16+).

New PKIs use EC secp384r1 keys (`config/easy-rsa.vars`). An existing RSA PKI
keeps working; `pki/vars` inside the PKI is what easy-rsa reads.

## Upgrading from the d3vilh layout

The directory layout is the same, so an existing `pki/`, `clients/`,
`staticclients/` and `clients/oath.secrets` keep working. Extra fields that
the old scripts appended to `pki/index.txt` are tolerated. Replace
`server.conf`/`config/client.conf` with the new ones (or merge your changes),
create `.env`, remove the old `openvpn-ui` container and run
`docker compose up -d --build`. Re-download client profiles if you switched
from `tls-auth` to `tls-crypt`. The old UI database (`db/data.db`) is not
used; the new UI creates `db/openvpn-ui.db`.

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
