# openvpn-server

OpenVPN server and Apple Network Relay in Docker, with a web UI for clients,
live status, traffic statistics and a personal portal for every client.

* **OpenVPN 2.7.7** and **easy-rsa 3.2.7**, built from the signed upstream
  release tarballs on Alpine 3.24.
* **Apple Network Relay** (`relay/`): the relay built into iOS/iPadOS 17+ and
  macOS 14+, as a per-client `.mobileconfig` profile next to the `.ovpn` one.
  Same clients, same roles, same revocation.
* **Web UI** (`ui/`): dashboard with live throughput, per-client traffic
  history, sessions with device, protocol and ending, certificate lifecycle,
  static IPs, TOTP two-factor authentication, relay activity, config editors,
  log viewer, audit log, daily (optionally encrypted) backups. No JavaScript
  dependencies, light and dark theme.
* **Personal portal** (`/portal`): a client signs in to download its own
  profiles and change its password.
* **Guests** reach nothing but that portal: no internet, no LAN.
* **Security**: unprivileged containers (`NET_ADMIN` only for OpenVPN), the
  management interface on `127.0.0.1` behind a generated password, `tls-crypt`,
  TLS 1.2+ with a pinned cipher list, EC certificates, CRL auto-renewal, strict
  forwarding rules, no Docker socket anywhere. See [Security notes](#security-notes).

State lives in PostgreSQL 18 (accounts, settings, sessions, traffic, audit log),
the PKI and profiles in this directory. Originally based on
[d3vilh/openvpn-server](https://github.com/d3vilh/openvpn-server).

## Quick start

```shell
git clone https://github.com/dkagramanyan/openvpn-server
cd openvpn-server
cp .env.example .env        # set the admin password and your public host name
python3 bin/setup-env.py    # generate the PostgreSQL passwords
docker compose up -d --build
```

The first start creates the CA, the server certificate, the tls-crypt key and
the CRL under `pki/`. Then:

| | Address |
|---|---|
| Web UI, on the server | **http://localhost:8080** |
| Web UI, from another machine | `http://<server-ip>:8080` |
| VPN endpoint | `<server-ip>:1197/udp`, falling back to `1196/tcp` (the `local` lines of `server.conf`) |

Sign in as `admin` with the password from `.env` (empty: a random one is
printed once in `docker compose logs openvpn-ui`). Open **Settings → Network**,
check the public addresses, then create clients under **Clients**.

All containers use host networking, so the host firewall applies to these
ports - see [Host networking](#host-networking). Put the UI behind an HTTPS
reverse proxy for anything but a LAN, with `OVPN_UI_SECURE_COOKIES=true`.

## How the pieces fit

```
                         ┌───────────── Traefik gateway (github.com/dkagramanyan/traefik) ─────┐
 browser ── 443 ───────► │ websecure: openvpn.<domain> → web UI        (trusted networks only) │
 iPhone ─── 8443 ──────► │ apple-relay: TLS + HTTP/2 → relay backend :8444                     │
                         │ portal :9443: openvpn.<domain> → personal portal pages only         │
                         └─────────────────────────────┬────────────────────▲──────────────────┘
                                                       │                    │ guests' HTTPS
 VPN client ── 1197/udp, 1196/tcp ──► this server: openvpn · openvpn-ui :8080 · apple-relay :8444
                                                   relay-policy :8447 · postgres :5433 (loopback)
```

* **openvpn** - the VPN and its firewall (`docker-entrypoint.sh`).
* **openvpn-ui** - web UI, API and personal portal (FastAPI, `ui/`).
* **apple-relay** - CONNECT / CONNECT-UDP relay over HTTP/2 (Go, `relay/`).
* **relay-policy** - answers the relay's "may this credential go there?" from
  a read-only database login, so relay access keeps working while the UI restarts.
* **postgres** - the UI's database, on `127.0.0.1:5433` only.

The gateway is a separate machine (a Raspberry Pi in the original setup) that
holds the TLS certificates. Its configuration lives in the
[Traefik repository](https://github.com/dkagramanyan/traefik); this server
hands it a settings file (see [Network settings](#network-settings-and-the-gateway-file)).

## Guests: the personal portal only

A client is either **full access** (internet, LAN, this server) or **guest**.
A guest, over OpenVPN or the Apple relay, reaches exactly one page: its
personal portal at `https://openvpn.<domain>/portal`, to change its password
and download its profiles. No internet, no LAN, no other website, no
administrator page.

| | OpenVPN | Apple relay |
|---|---|---|
| Full access | everything: internet, LAN, this server | everything: internet and LAN |
| Guest | the pushed DNS servers + the portal | the portal |

How it is enforced:

* **OpenVPN guests** (`10.8.0.128/25`): the firewall allows the pushed DNS
  servers and redirects every guest HTTPS connection (TCP 443, any address) to
  the gateway's portal listener (`bin/guest-portal.sh`). Everything else from
  the guest subnet is dropped. So the portal opens whatever address a guest's
  DNS returns for `openvpn.<domain>`, and every other HTTPS site fails.
* **Relay guests**: the relay accepts only `openvpn.<domain>:443` and connects
  it straight to the portal listener; every other destination is refused. A
  guest's relay profile routes only that hostname through the relay, so the
  device keeps its own internet connection while the profile is installed.
* **The portal listener** (Traefik entrypoint `portal`, normally the gateway's
  LAN address, port 9443) serves only the OpenVPN website and adds
  `X-OpenVPN-Portal-Only: 1`; with it, the UI answers only `/portal`,
  `/api/portal/*` and `/static/*` (`/` redirects to `/portal`, the rest is 404),
  even for a browser holding an administrator cookie.

Without a portal listener in Settings, guests reach nothing at all (DNS only).
Changing a client between guest and full access applies to OpenVPN on the next
connection and to the relay within seconds; download the relay profile again,
because the two roles route different traffic.

## Network settings and the gateway file

**Settings → Network** is one form:

* **Public addresses** - domain, website hostname (`openvpn.<domain>`), the
  address and ports in VPN profiles, the Apple relay URL and whether relay
  profiles are offered. Empty fields use the value shown in grey.
* **Guests** - the gateway's portal listener (`<gateway LAN IP>:9443`).
* **Gateway** - this server's web and relay addresses as the gateway reaches
  them, and the gateway's own source addresses (trusted for `X-Forwarded-For`).
  **Detect addresses** suggests them from this server's interfaces, the proxy
  connection and DNS; it only fills empty fields.
* **VPN network** - VPN subnet, guest subnet, client pool, DNS servers, pushed routes.
* **Advanced** - replace the gateway's list of trusted networks or its
  additional websites (off: the gateway keeps its own).

**Save** writes `config/network/settings.conf` (mode 0600, not in Git) and the
network lines of `server.conf`; **Save and restart VPN** applies them.
**Save and download gateway file** saves and downloads `network.private.json`
for the gateway:

```sh
# on the gateway, in the Traefik folder
./manage setup --network-file ./network.private.json
sudo docker compose up -d
```

The file holds addresses and hostnames, no credentials; keep it private anyway.
After a change of the guest portal listener, apply the gateway file first, then
restart the VPN.

A checkout from before 1.8 tracked its live `server.conf` and
`config/client.conf`. Copy them to `config/network/` (mode 0600) **before**
pulling: the entrypoint restores them from there when the runtime files are
missing, and only a new install starts from the `.example` templates.

## Apple Network Relay

Every client has an **Apple relay** download next to its OpenVPN one (client
list, client page, personal portal). The `.mobileconfig` holds the
`com.apple.relay.managed` payload (iOS/iPadOS 17+, macOS 14+) with the relay
URL and a personal bearer credential. Install it in Settings →
General → VPN & Device Management (iOS) or System Settings → Device
Management (macOS); see [Apple's guide](https://support.apple.com/102400).
Apple marks the payload deprecated from OS 27 on in favour of declarative device management.

Setup:

1. On the gateway, the `apple-relay` TCP router terminates TLS with ALPN `h2`
   and forwards HTTP/2 to this server's port 8444 (in the gateway file).
2. In **Settings → Network**, set the relay URL (e.g. `https://example.com:8443`),
   tick **Offer Apple relay profiles**, fill in the gateway addresses and save.
3. In **Relay → Profile signing**, set the signer URL
   (`https://openvpn.<domain>/internal/relay-sign`) and the gateway's
   `RELAY_PROFILE_SIGNING_TOKEN`. Downloads are signed by default
   (`OVPN_RELAY_REQUIRE_SIGNED=true`); without a working signer they fail
   instead of falling back to unsigned files.

How it behaves:

* **Credentials** - one per client, reused by every download. **Revoke relay
  access** on the client page invalidates installed profiles without touching
  OpenVPN; certificate revocation, expiry and deletion end relay access too.
  A renewal through the UI keeps the credential.
* **Destinations** - full access: everything except loopback, link-local,
  multicast and unspecified addresses. The relay resolves names itself and
  connects to the checked addresses only (no DNS rebinding). Guests: see above.
* **Live checks** - open flows are re-authorized every 5 seconds, so a role
  change, revocation or relay switch-off takes effect within about 9 seconds.
  Authorization results are cached for at most 1 second; when the policy
  service is unreachable, new requests get a retryable 503 and nothing fails open.
* **Limits** - 256 flows in total, 64 per client, 128 HTTP/2 connections with
  256 streams each (`APPLE_RELAY_*` in `.env.example`). HTTP/2 pings an idle
  connection after 10 s and drops it 5 s later without an answer.
* **The relay is a proxy, not an IP VPN**: TCP and UDP to named destinations,
  no ping, no Bonjour, no VPN address. OpenVPN statistics do not include relay traffic.

The **Relay** page lists sessions (connections from one profile, merged until
five minutes pass without one), live connections per client and recent events
with the reason of every refusal or failure (policy, DNS, refused, timeout).
Session totals are saved every 5 seconds and kept for a year. The relay's own
status endpoint (`127.0.0.1:8446`: `/readyz`, `/metrics`, `/status`) stays on
loopback; never publish it.

If a profile installs but nothing connects:

```shell
docker compose ps apple-relay relay-policy
docker compose logs --tail=50 apple-relay relay-policy
docker compose exec -T apple-relay wget -qO- http://127.0.0.1:8446/readyz
```

**Direct HTTP/3** (optional): `APPLE_RELAY_TRANSPORT=http3`, a certificate in
`relay-tls/` (`fullchain.pem`, `privkey.pem`, readable by UID 65532; see
`bin/export-relay-cert.py`), UDP 8443 forwarded to this server, then
`docker compose up -d --build` and new profiles.

## Personal portal

Give a client a portal login under **Clients → client → Portal access**. The
client signs in at `https://openvpn.<domain>/portal` and sees step-by-step
instructions for Apple relay and OpenVPN, its own relay activity, and a
password form. It cannot see other clients, settings or logs; every
administrator API refuses a portal session, and the admin login refuses portal
accounts. A login stays bound to the client's current certificate:
revocation, expiry or deletion ends it, a renewal through the UI keeps it.
Portal passwords are separate from profile passphrases and TOTP codes.

Who reaches the portal: guests through the portal listener (above); full-access
clients and trusted LAN networks through the gateway's regular HTTPS listener.
From the open internet it is not reachable, so a first profile has to be handed
over privately or on the LAN.

## Upgrading to 2.0

2.0 moves the UI's state from SQLite to PostgreSQL, adds the Apple relay and
makes guests portal-only. From 1.x:

```shell
cd ~/openvpn-server &&
git pull --ff-only &&
bin/upgrade-relay.sh --sudo-docker &&      # PostgreSQL, UI, relay; OpenVPN keeps running
sudo docker compose up -d --build          # new OpenVPN image: guest firewall (clients reconnect)
```

`bin/upgrade-relay.sh` generates the PostgreSQL passwords in `.env`, builds the
images, stops the UI and relay, imports `db/openvpn-ui.db` in one verified
transaction (row counts checked, nothing merged into a non-empty database) and
starts the new services. On failure it rolls back and restarts the previous
containers; the SQLite file is never changed and stays as a recovery copy. Keep
`.env` together with the `postgres-data` volume and never run
`docker compose down -v`.

Then, in **Settings → Network**, set the guest portal listener, download the
gateway file, update and apply it on the gateway (see its README), and use
**Save and restart VPN**. Download the Apple relay profiles of guest clients again.

If `git pull` failed half-way on permission errors, `bin/recover-checkout.py`
repairs the checkout without touching keys, databases or `.env`:

```shell
cd ~/openvpn-server &&
helper=$(mktemp /tmp/ovpn-recover.XXXXXX) &&
curl -fsSL https://raw.githubusercontent.com/dkagramanyan/openvpn-server/main/bin/recover-checkout.py -o "$helper" &&
python3 "$helper" --repo "$PWD" --repair-permissions
```

It fixes ownership of code and Git metadata with sudo, stashes only the
conflicting code changes and fast-forwards `main`; its records stay under
`.git/openvpn-recovery/`.

## Layout

```
server.conf          OpenVPN server configuration (mounted at /etc/openvpn)
config/client.conf   template for client profiles ("remote" line managed by the UI)
config/easy-rsa.vars easy-rsa settings used when a *new* PKI is created
config/management.pw generated management-interface password (git-ignored)
config/network/      private network settings from the UI (git-ignored)
pki/                 easy-rsa PKI (CA, certificates, CRL, tls-crypt keys)
clients/             generated .ovpn profiles, 2FA secrets and QR codes
staticclients/       per-client "ifconfig-push" files (static IPs)
guests/              one empty file per guest client
db/                  retained legacy SQLite source / restored PostgreSQL dumps
backups/             daily backup archives written by the UI (git-ignored)
log/                 openvpn.log, openvpn-status.log, oath.log
bin/                 CLI scripts (also used by the UI)
ui/                  web UI (Python/FastAPI) and the relay-policy service
relay/               Apple Network Relay (Go)
signer/              profile signer, built and run on the Traefik gateway
postgres/            database role setup (application and read-only policy logins)
fw-rules.sh          your additional iptables rules, applied at start
backup.sh            backup / restore helper
tests/               end-to-end, relay stack, browser and firewall tests
```

## Host networking

All three containers run in the host's network namespace. Nothing is published, so
there is no port mapping to keep in sync:

| | Where it comes from |
|---|---|
| VPN ports | the `local` lines in `server.conf`, bound directly on the host |
| Web UI | host port `8080` |
| Apple relay backend | host TCP port `8444`, reachable by the trusted proxy |
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
| VPN and guest subnet, portal listener | From `server.conf` (guests: its upper half) | set in Settings → Network |
| `OVPN_EGRESS_IFACE` | default-route interface | interface used for MASQUERADE |
| `OVPN_STRICT_FORWARD` | `1` | only VPN-originated traffic and replies are forwarded |
| `OVPN_MSS` | `1400` | TCP MSS clamp for tunnel traffic; `0` = off |
| `OVPN_MAX_DEVICES` | `10` | connections one certificate may have at the same time; `0` = no limit |
| `OVPN_LOG_STDOUT` | `1` | mirror openvpn.log to `docker logs` |
| `OVPN_LOG_MAX_BYTES` | 10 MiB | rotate openvpn.log (checked every minute) above this size |
| `OVPN_CRL_RENEW_DAYS` | `30` | regenerate the CRL when it expires within this many days |

`.env` (see `.env.example`): `OPENVPN_ADMIN_USERNAME`, `OPENVPN_ADMIN_PASSWORD`,
`OVPN_PUBLIC_HOST`, `OVPN_PROFILE_BASE_URL`, `OVPN_BACKUP_RECIPIENT`,
`OVPN_UI_SECURE_COOKIES`, `OVPN_UI_BIND`, `OVPN_UI_TRUSTED_PROXIES`.

Environment variables of the `openvpn-ui` service for backups:
`OVPN_BACKUP_KEEP` (14 archives; `0` = no backups), `OVPN_BACKUP_DIR`
(`/etc/openvpn/backups`) and `OVPN_BACKUP_RECIPIENT` (see [Backup](#backup)).

## Web UI

* **Dashboard** - online clients with live download/upload rates, throughput
  for the last hour, traffic over the selected range (today, 24 h, 7/30/90
  days, all), top clients, rejected connection attempts of the last 24 h,
  warnings (unreachable server, expiring certificates/CRL, 2FA enforced
  without secrets).
* **Clients** - state (online, valid, expiring, expired, revoked), expiry,
  last seen, traffic in the selected range, session count. Create clients with
  full access or guest, optional validity, static IP, key passphrase, note and
  2FA. Download the `.ovpn` profile (always regenerated from the current
  template) or share it with a one-time link and QR code, switch between full
  access and guest, show the 2FA QR code and rejected connection attempts,
  disconnect, renew, revoke, delete.
* **Sessions** - every connection with duration, source address, protocol
  (UDP or the TCP fallback), device (platform and client version), VPN IP,
  bytes and how it ended: *left* (the client said goodbye), *timed out* (it
  vanished), *closed* (a TCP connection ended). Reconnects of one client from
  one address at most 15 minutes apart are shown as one *visit*; untick
  **Merge reconnects** to see every connection. **Connection quality** sums it
  up per client for the selected range: sessions, median length, share under a
  minute, endings, share over TCP. See [Phones](#phones-many-short-sessions).
* **Server** - OpenVPN version, management status, PKI expiry dates, CRL
  regeneration, 2FA enforcement switch, control channel key (shared or per
  client), editors for `server.conf`,
  `client.conf` and easy-rsa vars (a `.bak` is kept), restart button, log
  viewer (openvpn.log, 2FA log, status file), backup status with a **Back up
  now** button, and the audit log (what admins did; VPN connections are
  sessions, not audit events).
* **Settings** - public address for profiles (host and a port per protocol;
  the protocols follow `server.conf`), admin password, theme.

Traffic is read every 5 s from the status file OpenVPN writes (`status ... 5`,
`status-version 3`; a management `status` command would be logged on every
poll), falling back to the management interface when there is none. It is stored per minute for two days, per hour for 90 days and per day forever.
Bytes are counted from the client's point of view: *download* is what the
server sent to the client.

Restarting OpenVPN from the UI sends `SIGTERM` through the management
interface; the container entrypoint supervises the process and starts it
again with the current `server.conf`, after rebuilding the firewall rules
from it (a changed DNS server or pushed route reaches the guest rules that
way). Revoking a certificate does not need a restart: OpenVPN re-reads the
CRL on every connection and the UI kills the active session.

Both containers repair themselves, because Docker only marks a container
unhealthy and leaves it running. The UI asks its own `/healthz` every 30 s and
exits after four failures in a row, and `restart: unless-stopped` starts a
fresh one; `/healthz` also fails when the thread that records sessions and
traffic has stopped. The entrypoint restarts an OpenVPN that stays alive but
no longer writes its status file.

History belongs to a certificate, not to a name: creating a client under the
name of an earlier one starts a new history, and the old sessions stay listed
as "name (earlier)". Renewing keeps the history (same key). Connection
attempts OpenVPN rejects (revoked or expired certificate, unknown control
channel key, wrong 2FA code, too many devices on one certificate) are read
from `log/openvpn.log` and `log/oath.log` and counted per day, client, reason
and source address.

The device, protocol and ending of a session come from `log/openvpn.log` too
(`peer info: IV_PLAT`, `IV_GUI_VER`, and the `SIGTERM[...]` / `SIGUSR1[...]`
line that ends a client instance). A connection shorter than the 5 s between
two status files is recorded from the log alone, without traffic.

### Phones: many short sessions

OpenVPN Connect on iOS and Android drops the tunnel whenever the phone sleeps
and connects again when it wakes, also for the brief wake-ups a locked phone
makes on its own. A phone therefore shows hundreds of sessions a day, most of
them under a minute, ending with *left*. That is the app's behaviour, not a
fault of the server. Two settings in the app change it (OpenVPN Connect >
Settings):

| Setting | Effect |
|---|---|
| **Battery Saver** on | the app does not reconnect while the phone is locked: far fewer sessions, but a locked phone's traffic goes around the VPN |
| **Seamless Tunnel** on | the internet is blocked while the VPN is paused or reconnecting: nothing goes around the VPN, but with Battery Saver on a locked phone is offline |

*Timed out* sessions and sessions over TCP are the ones worth a look: the
first means the client lost the network without saying so, the second that
UDP did not get through on the client's network within 10 s.

### One-time profile links

**Share link** on a client page makes a link that hands out the profile once
and expires (1 h to 7 days). The link itself (`https://.../p/<token>`) opens a
small page with two buttons, *Open in OpenVPN Connect* and *Download*; looking
at the page does not use the link up, so it can be sent through a messenger
that fetches links for a preview. The profile is behind
`/p/<token>/download`, once. The QR code holds the
`openvpn://import-profile/https://.../p/<token>/download` form: scanning it on
a phone opens OpenVPN Connect and imports the profile. A link is spent only
when the profile was really delivered. Only the path `/p/` needs to be
public. Set `OVPN_PROFILE_BASE_URL` to the public address and let your proxy
forward just that path to the UI, e.g. with Traefik:

```yaml
http:
  routers:
    ovpn-profiles:
      rule: Host(`vpn.example.com`) && PathPrefix(`/p/`)
      service: ovpn-ui
      tls: { certResolver: letsencrypt }
  services:
    ovpn-ui:
      loadBalancer: { servers: [{ url: "http://192.0.2.30:8080" }] }
```

With another reverse proxy, forward the `/p/` path to the UI backend. Set the
trusted proxy CIDRs in Settings to the
proxy's address so failed attempts are rate limited per visitor, not per proxy.

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

## Subnets, guests, devices and the firewall

`server 10.8.0.0 255.255.255.0 nopool` is one tunnel subnet (with
`topology subnet` OpenVPN only accepts addresses inside it):

| Addresses | For |
|---|---|
| `10.8.0.2-99` | dynamic pool (full access) |
| `10.8.0.100-127` | static IPs (full access) |
| `10.8.0.128/25` (`GUEST_SUB`) | guests: the pushed DNS servers and the personal portal only |

One certificate may be used on several devices at once (`duplicate-cn`).
`bin/client-access.sh` (`client-connect`) gives every device its own address:
each device of a guest gets a free address from the guest range, and a static
IP goes to the first device that connects while the others get a dynamic one.
Choose **Guest** in the New client dialog or on the client page; it applies the
next time a device connects. One certificate gets at most `OVPN_MAX_DEVICES`
(10) connections at a time, so a copied profile cannot fill the server; a
device over the limit is refused and listed under *Rejected connection
attempts*. Its OpenVPN client takes the refusal as final and stops trying, so
it has to be connected again by hand; raise the limit if one certificate
really serves that many devices. A device that changes network (Wi-Fi to mobile) keeps its old
connection for up to two minutes, and for that time counts twice and gets a
second address.

For guests the entrypoint allows the pushed DNS servers and the portal
redirect (see [Guests](#guests-the-personal-portal-only)) and drops everything
else, including traffic to other VPN clients and to the server host itself.
The rules live in the chains `OVPN-NAT`, `OVPN-INPUT`, `OVPN-FORWARD` (hooked
into `DOCKER-USER` when Docker manages the firewall, else the top of
`FORWARD`) and `OVPN-ACCEPT` (end of `FORWARD`). They are flushed and rebuilt
every time OpenVPN starts, also on a restart from the UI, and checked once a
minute: if a firewall reload on the host removed them, they are installed
again. `fw-rules.sh` runs in between; append your own rules to `OVPN-FORWARD`
there.

`OVPN-MSS` (table `mangle`) lowers the TCP segment size of connections through
the tunnel to `OVPN_MSS` (1400), so that an encrypted packet fits networks
with an MTU below 1500. OpenVPN's own `mssfix` does this only without kernel
offload: with DCO on Linux the data packets never pass through OpenVPN.
OpenVPN Connect and the Windows client clamp on their side as well; the rule
covers the clients that do not. `OVPN_MSS=0` turns it off.

Clients get the DNS server both as `dns server` (OpenVPN 2.6+, Connect 3) and
as `dhcp-option DNS` (older clients). IPv6 is routed into the tunnel as well
(a private `fd00:8::/64` exists only for that) and answered there with "no
route" (`block-ipv6`), so it cannot bypass the tunnel. With kernel offload
OpenVPN never sees those packets, so `ip6tables` chains of the same names drop
everything that arrives from that network: without them a client that ignores
the pushed `block-ipv6` could reach the server host over IPv6, guests
included.

## Control channel key

By default every profile carries the same `tls-crypt` key. The Server page can
switch to `tls-crypt-v2`: one key per client, generated into `pki/tc2/`, so a
leaked profile no longer exposes a key all clients share, and the server
drops packets from unknown clients before any TLS work. Switching changes every
profile, and after restarting OpenVPN only the new profiles connect, so hand
them out again (Share link) right after the switch. Switching back is the same
button.

## Two-factor authentication

1. Enable 2FA per client (Clients → client → *Enable 2FA*) and let the user
   scan the QR code. The profile gains `auth-user-pass`.
2. Enforce it on the Server page and restart OpenVPN. This adds
   `auth-user-pass-verify /opt/app/bin/oath.sh via-file` and
   `auth-gen-token 43200` to `server.conf`.

`oath.sh` requires the username to equal the certificate's common name,
rejects clients without an enrolled secret, accepts one time-step of clock
drift, refuses a code that was already used, and makes a client wait five
minutes after five wrong codes in a row. Attempts are logged to
`log/oath.log`. Secrets live in `clients/oath.secrets` (`name:hex`), readable
only by the unprivileged user OpenVPN runs as.

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
  host kernel provides the `ovpn` module (Linux 6.16+). It is what makes
  OpenVPN fast (several Gbit/s instead of several hundred Mbit/s), and it is
  the newer code: OpenVPN 2.7.7 has an open bug in which the whole server
  exits when the kernel drops a client at the wrong moment
  ([OpenVPN issue 1111](https://github.com/OpenVPN/openvpn/issues/1111); the
  entrypoint restarts it within 5 s and clients reconnect). If
  `docker logs openvpn | grep "exited with code"` shows such exits and a home
  line does not need the speed, add `disable-dco` to `server.conf` and
  restart. The tests in this repository run without DCO.

New PKIs use EC secp384r1 keys (`config/easy-rsa.vars`). An existing RSA PKI
keeps working; `pki/vars` inside the PKI is what easy-rsa reads.

## Backup

The UI writes an archive once a day to `backups/openvpn-backup-<time>.tar.gz`
and keeps the newest 14: `server.conf`, `config/`, the PKI, the profiles and
2FA secrets, static IPs, guests, `fw-rules.sh`, `docker-compose.yml`, `.env`
and a consistent PostgreSQL custom-format dump (`db/openvpn-ui.pgdump`). The Server page shows the last one
and has **Back up now**; the dashboard warns when there has been none for
three days.

An archive contains the CA key, so it is readable by root only, and it sits
on the same disk as the server. Keep a copy on another machine: mount one
there (`- /mnt/nas/openvpn-backups:/etc/openvpn/backups` in
`docker-compose.yml`), or copy the directory with `rsync` from cron.

Whoever reads a copy can issue certificates for your VPN, so encrypt the
archives before they leave the server. Make a key pair with
[age](https://github.com/FiloSottile/age) on your own computer, put the
public key into `.env` and keep the private key file off the server:

```shell
age-keygen -o backup-key.txt          # prints "Public key: age1..."
echo 'OVPN_BACKUP_RECIPIENT=age1...' >> .env && docker compose up -d
```

The archives are then written as `.tar.gz.age`, and the Server page says
*encrypted*. If the key in `.env` is not a valid one, backups fail with an
error instead of being written unencrypted.

```shell
sudo ./backup.sh -b ~/openvpn-server ~/backup/openvpn-$(date +%F)     # a copy by hand (-y: no question)
docker compose down
sudo ./backup.sh -r ~/openvpn-server ~/backup/openvpn-2026-09-05      # restore that copy
sudo ./backup.sh -r ~/openvpn-server backups/openvpn-backup-20261002-080139.tar.gz   # or an archive
sudo ./backup.sh -i backup-key.txt -r ~/openvpn-server backups/openvpn-backup-20261002-080139.tar.gz.age   # an encrypted one (needs age)
bin/upgrade-relay.sh --sudo-docker
```

Restore database data into an **empty** PostgreSQL application database. The
helper refuses to overwrite an existing one. For disaster recovery on a new
host, clone the current repository, restore the archive, then run the helper;
it imports either the PostgreSQL dump or an older archive’s SQLite file.
Keep the old host/volume intact until recovery is verified.

## Security notes

* **The admin login** is throttled per user name and per address: after five
  wrong passwords for one name, or twenty from one address, each further
  attempt has to wait (2 s, doubling up to 5 min). The UI has no HTTPS of its
  own; keep it on the LAN or behind a reverse proxy.
* **The configuration editors** refuse to add or change a line that makes
  OpenVPN run a program, load a plugin or write to another file (`up`,
  `plugin`, `client-connect`, `script-security`, `log-append`, `status` and the
  like), in `server.conf` and in the client template, and in the easy-rsa
  variables anything but `set_var` lines for the certificate fields, the key
  type and the lifetimes. Lines already in the file stay. This keeps a stolen admin session from becoming root on the
  server or on the clients; make such changes in the files on the server.
* **What the UI container can still do**: it runs as root with only the
  capabilities to manage file ownership and permissions and with a read-only
  root filesystem, but it mounts this directory read-write (it owns the PKI, the profiles, the
  configuration and the database). `fw-rules.sh` in the same directory is run
  as root by the OpenVPN container. The UI offers no way to write it, but a
  code-execution bug in the UI would reach it.
* **Audit log**: entries older than a year are removed; sessions and daily
  traffic are kept.
* **Dependencies**: the OpenVPN and easy-rsa tarballs are pinned by SHA-256,
  the Python packages by version and file hash (`ui/requirements.txt`). The
  base images are pinned by tag and `apk upgrade` runs at build time, so two
  builds of one release can differ in Alpine packages.

## Development

```shell
python3 tests/run-ui.py                  # UI/migration tests with isolated PostgreSQL in Docker
docker compose build                     # rebuild application images
tests/e2e/run.sh                         # end-to-end test (needs Docker)
```

The end-to-end test builds the images and runs the whole service with real
OpenVPN clients inside one Docker-in-Docker container, so its networks, tun
devices and firewall rules never touch the machine it runs on. It covers UDP
and the TCP fallback, the SQLite import, portal-only guests, two devices on one
certificate, the device limit, revocation, the MSS clamp and backups (plain and
encrypted) with a restore. It runs without kernel offload. `E2E_KEEP=1` keeps
the container for a look at the UI.

More checks:

```shell
cd relay && GODEBUG=http2xconnect=1 go test -race ./...   # relay; TRAEFIK_BIN=<traefik> adds TLS-termination tests
python tests/relay-stack.py           # UI + policy + relay + signer + Traefik containers, guest portal routing
python tests/browser-settings.py      # Settings and portal pages in Chrome with a mocked API (Playwright)
bash tests/guest-portal-network.sh    # the guest firewall rules in throwaway network namespaces
```

`relay-stack.py` creates Docker networks; run it inside Docker-in-Docker on a
machine whose own networks must stay untouched.

GitHub Actions runs both on every push (`.github/workflows/ci.yml`). A weekly
job (`upstream.yml`) compares the OpenVPN, easy-rsa and Alpine versions
pinned in the Dockerfiles with the newest releases and opens an issue when
one is behind.
