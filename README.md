# openvpn-server

An access server in Docker: OpenVPN, Apple Network Relay and Xray (3x-ui),
with a web UI for clients, live status, traffic statistics, a personal portal
for every client and a Telegram bot through which clients get their own
access.

* **OpenVPN 2.7.9** and **easy-rsa 3.2.7**, built from the signed upstream
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
* **Guests** get the internet (through your network and its filtering) and that
  portal, but no LAN.
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

## Guests: internet, the personal portal, no LAN

A client is either **full access** (internet, LAN, this server) or **guest**.
A guest, over OpenVPN or the Apple relay, gets the internet through this
server, so whatever your LAN router does to this server's traffic (podkop or
other filtering, its DNS) applies to guests too. Of your own network a guest
reaches only its personal portal at `https://openvpn.<domain>/portal`
(password, profile downloads) and the **guest links** you allow: no LAN, no
other website of yours, no administrator page.

| | OpenVPN | Apple relay |
|---|---|---|
| Full access | everything: internet, LAN, this server | everything: internet and LAN |
| Guest | internet, the pushed DNS servers, the portal and guest links | internet, the portal and guest links |

How it is enforced (`bin/guest-portal.sh`):

* **OpenVPN guests** (`10.8.0.128/25`): the firewall allows the pushed DNS
  servers, redirects a guest's HTTPS connection to the gateway (TCP 443 to the
  portal listener's address) to the portal listener, and drops everything
  local: private ranges (`10/8`, `172.16/12`, `192.168/16`, `100.64/10`,
  link-local), the networks of this host's interfaces, the routes pushed in
  `server.conf`, other VPN clients, ping, and this host itself. The rest goes
  out to the internet. Your LAN DNS should answer `openvpn.<domain>` (and the
  guest links' hostnames) with the gateway's LAN address, as for full clients.
* **Relay guests**: the relay connects `openvpn.<domain>:443` and the guest
  links' hostnames on 443 straight to the portal listener. Any other
  destination is resolved with this host's DNS and allowed unless it is local:
  private ranges, `100.64/10`, the relay host's own networks and the routes in
  Settings → Network.
* **Your public address**: a guest who opens your public IP reaches the gateway
  through your router (hairpin NAT). Keep the address your router uses for that
  out of the gateway's trusted networks, or guests count as trusted there.
* **The portal listener** (Traefik entrypoint `portal`, normally the gateway's
  LAN address, port 9443) serves only the OpenVPN website and adds
  `X-OpenVPN-Portal-Only: 1`; with it, the UI answers only `/portal`,
  `/api/portal/*` and `/static/*` (`/` redirects to `/portal`, the rest is 404),
  even for a browser holding an administrator cookie.

**Guest links** (Settings → Network → Guests) are pages on websites under your
domain that the gateway already serves, e.g. `https://files.<domain>/share/abc`.
Each link allows either *this page and below* (`/share/abc`, `/share/abc/...`)
or *the whole website*. The gateway adds a route for each link on the portal
listener, using the backend of its existing route for that hostname; guests see
the links on their portal page. Add a link, download the gateway file and apply
it on the gateway; the relay picks it up within seconds, guest relay profiles
does not need a new profile. A page that loads scripts or images from elsewhere on its
website may need the whole website.

Below the links, the section shows the `portal_listener` and `guest_links`
entries of the gateway file, to paste over the same entries in the gateway's
`network.private.json`. **Check guest access** opens the saved portal and each
saved link from this server through the portal listener, as a guest's
connection goes, and asks the pushed DNS servers whether the hostname points at
the listener's address. A 404 there means the gateway file is not applied yet.

Without a portal listener in Settings, guests get the internet but not their
portal.

Access is one rule per client, set in this UI, and it holds for OpenVPN and
the relay alike: a guest reaches the same things either way, a revoked or
expired certificate closes both. Changing a client between guest and full
access applies at once: connected OpenVPN devices are reconnected (they get
an address from the other range) and the relay follows within seconds;
neither profile has to be issued again. Two rules exist for OpenVPN only,
because the relay has no place for them: the 2FA code and custom rules in
`fw-rules.sh`.

## Network settings and the gateway file

**Settings → Network** is one form:

* **Public addresses** - domain, website hostname (`openvpn.<domain>`), the
  address and ports in VPN profiles, the Apple relay URL and whether relay
  profiles are offered. Empty fields use the value shown in grey.
* **Guests** - the gateway's portal listener (`<gateway LAN IP>:9443`) and the guest links.
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
* **Limits** - 2048 flows in total, 512 per client (a profile sends every
  connection of the device through the relay, and a client's devices share the
  limit), 128 HTTP/2 connections with 512 streams each (`APPLE_RELAY_*` in
  `.env.example`; a value set in your `.env` wins over a new default). HTTP/2
  pings an idle connection after 10 s and drops it 5 s later without an answer.
* **Names** are resolved by the relay with this server's DNS; one answer is
  shared by the connections that ask for it at once and reused for 20 seconds.
* **The relay is a proxy, not an IP VPN**: TCP and UDP to named destinations,
  no ping, no Bonjour, no VPN address.

Relay sessions (connections from one profile, merged until five minutes pass
without one), relay traffic and the relay's connection log are on the
**Clients** and **Sessions** pages, next to the OpenVPN ones (see *Web UI*).
The **Relay** page shows the service: state, open listeners, limits, live
connections with the reason of every refusal or failure, and profile signing.
The relay's own status endpoint (`127.0.0.1:8446`: `/readyz`, `/metrics`,
`/status`) stays on loopback; never publish it.

If a profile installs but nothing connects:

```shell
docker compose ps apple-relay relay-policy
docker compose logs --tail=50 apple-relay relay-policy
docker compose exec -T apple-relay wget -qO- http://127.0.0.1:8446/readyz
```

### HTTP/3 and HTTP/2 straight to this server

The relay serves both transports itself, with its own certificate, on one port
number: HTTP/3 on UDP 8443, HTTP/2 over TLS on TCP 8443. Every relay profile
lists HTTP/3 first and HTTP/2 as the fallback, at the same address with the
same credential, so a device uses HTTP/3 and falls back to HTTP/2 when UDP does
not get through. Profiles installed before keep working (same address); a
device gets HTTP/3 when its profile is downloaded again. The gateway's Traefik
is no longer in the relay's path (its plain backend on 8444 stays open, for a
gateway still forwarding TCP 8443).

1. **The certificate**, issued and renewed by the `relay-cert` service: lego,
   the ACME client inside Traefik, with the DNS challenge at your DNS provider
   and the same service account as the gateway's Traefik. Put in `.env` (the
   values of the gateway's `.env`):

   ```shell
   RELAY_CERT_DOMAIN=relay.example.com      # the relay URL's hostname
   ACME_EMAIL=you@example.com
   ACME_DNS_PROVIDER=selectelv2
   SELECTELV2_ACCOUNT_ID=...
   SELECTELV2_PROJECT_ID=...
   SELECTELV2_USERNAME=...
   SELECTELV2_PASSWORD=...
   ```

   then `sudo docker compose up -d relay-cert` and watch
   `sudo docker compose logs -f relay-cert` until it says "handed to the
   relay". It checks twice a day and renews when a third of the lifetime is
   left; the relay loads the new pair within 30 seconds, without a restart.
   lego's account and certificates live in `config/acme/` (part of backups).
   Another DNS provider: set `ACME_DNS_PROVIDER` to its lego code and add its
   variables to the `relay-cert` service in `docker-compose.yml`. Without
   `RELAY_CERT_DOMAIN` the service stays idle and `relay-tls/` can be filled
   by hand (`fullchain.pem`, `privkey.pem`, owned by UID 65532, mode 0600).
2. **The router**: forward **TCP and UDP 8443** to this server. The relay URL
   does not change.
3. **This host**: QUIC wants larger socket buffers than Linux allows by
   default: `sudo sysctl -w net.core.rmem_max=7500000 net.core.wmem_max=7500000`
   (and the same two lines in `/etc/sysctl.d/`). A host firewall must let in
   TCP and UDP 8443.

The **Relay** page shows which listeners are open (HTTP/2 direct or through the
gateway), the certificate's names and days left, and every relay session shows
`h3` or `h2`. `APPLE_RELAY_HTTP2_TLS_BIND=off` sends HTTP/2 through the gateway
again (TCP 8443 forwarded to the gateway, as before 2.5);
`APPLE_RELAY_TRANSPORT=http2` or `http3` alone still work as before.

## Traffic by podkop section

If the LAN router runs [podkop](https://github.com/itdoginfo/podkop) with
`podkop-agent` 0.27 or newer, the UI counts each client's traffic per podkop
section (youtube, meta, main, ...), for OpenVPN and the Apple relay alike:
**Traffic by section** on the dashboard, on a client's page and in the client's
own portal, for the chosen period.

How it works. podkop sends a section's names to FakeIP addresses
(`198.18.0.0/15`) and its address lists to sing-box; everything else leaves
directly. This server knows who opened each connection and how many bytes it
carried; the router knows which section a destination belongs to:

* OpenVPN: the container writes the end of every VPN client's connection with
  its bytes to `log/flows.log` (conntrack). The client is the one that had that
  VPN address at the time.
* Apple relay: every finished relay connection is saved with the name the
  device asked for and the address the relay connected to.
* Every 30 s the UI asks the router about the new destinations, over SSH with
  its own key, which may run nothing but `podkop-agent sections`. The router
  answers only about the names and addresses it is asked about.

Setup:

1. On this server's host, turn on connection accounting (a host setting in
   host network mode, like IPv4 forwarding):
   `sudo sysctl -w net.netfilter.nf_conntrack_acct=1 net.netfilter.nf_conntrack_timestamp=1`,
   and put `net.netfilter.nf_conntrack_acct = 1` and
   `net.netfilter.nf_conntrack_timestamp = 1` into
   `/etc/sysctl.d/99-openvpn.conf`. The first gives the byte counts; the second
   says when each connection began, which tells apart two clients that had the
   same VPN address one after the other.
   The OpenVPN container warns in its log while it is off.
2. **Settings → Router**: enter the router's SSH address (`root@192.168.1.1`)
   and **Save**. The card then shows one command: paste it into the router's
   terminal (SSH as root), once. It adds this server's key to
   `/etc/dropbear/authorized_keys` as
   `restrict,command="/usr/bin/podkop-agent --sections-only" ssh-ed25519 AAAA... openvpn-server-sections`,
   a key that can run nothing but the section lookup. **Test** shows how many
   sections and address ranges the router reports.
   The key lives in `config/router/` (not in git, included in backups).
   From then on the server asks the router by itself, at least every 5
   minutes: the card shows whether it answers and the agent's version, and
   the event log records when the router stops answering and when it is back.
   The key lives in `config/router/` (not in git, included in backups).

What the numbers mean:

* **Direct**: traffic that did not go through podkop.
* **Through podkop, section unknown**: through podkop, but the router had not
  seen the name (a connection too short for its 15-second look at sing-box,
  to a name nobody else used), or the router was rebooted before the answer
  (FakeIP addresses are handed out again after a reboot), or it did not answer
  for an hour. The card shows the share of such traffic.
* Totals per section are kept for good (per hour for 90 days, then per day).
  The domains behind them are kept for **7 days**.
* Not counted: connections that started before accounting was switched on,
  IPv6, and podkop's separate Discord voice ports (they count as direct).
  LAN destinations of full-access OpenVPN clients count as direct.

Leave the router address empty to switch the counting off.

## Sign-in and the personal portal

Administrators and clients use the same sign-in form, at `/` or `/portal`;
each lands on its own page. A client gets its login (username = client name)
and every new password from the Telegram bot (below); without Telegram, **New
password** under **Clients → client → Telegram & portal** generates one and
shows it once. Clients cannot choose their own password. The client signs in
and sees step-by-step instructions for Apple relay and OpenVPN and its own
relay activity. It cannot see other clients, settings or logs; every
administrator API refuses a portal session. On the guest portal listener
administrator accounts cannot sign in at all. A login stays bound to the client's current certificate:
revocation, expiry or deletion ends it, a renewal through the UI keeps it.
Portal passwords are separate from profile passphrases and TOTP codes.

Who reaches the portal: guests through the portal listener (above); full-access
clients and trusted LAN networks through the gateway's regular HTTPS listener.
From the open internet it is not reachable; a first profile goes out as a
one-time link (from the bot or **Share link**).

## Xray (3x-ui)

The `xui` service runs [3x-ui](https://github.com/MHSanaei/3x-ui) (Xray with a
panel) next to OpenVPN and the relay, for networks where OpenVPN is blocked.
The UI gives every client its own Xray key on one inbound and takes it away
with the certificate.

1. `sudo docker compose up -d xui`, then `sudo docker compose logs xui`: the
   first start prints the panel login and its random path once. Download the
   gateway file (Settings → Gateway) and apply it on the gateway (traefik 1.3.0
   or later): the panel then opens at `https://<OpenVPN hostname>/<panel path>/`
   from trusted networks, and as **3x-ui ↗** in the sidebar. It listens on
   `XUI_LISTEN` (default every address, port `XUI_PORT=2053`); set
   `127.0.0.1` to keep it off the LAN and use `ssh -L 2053:127.0.0.1:2053`.
   Its subscription server is switched off at the first start.
2. In the panel, add an inbound: VLESS, TCP, security REALITY (pick a target
   with *Scan*, generate the keys), on a free port such as 8445. Forward that
   TCP port on the router to this server.
3. In this UI, **Settings → Xray**: tick *Offer Xray keys*, choose the inbound,
   Save.

Clients then get a key from **Share link** (profile *Xray*) or the bot's
**Xray** button. The one-time page shows the `vless://` key and its QR code
once; it goes into v2RayTun, Streisand, v2rayNG or Hiddify. The key carries
the public host of profiles (Settings) and the inbound's port.

* Clients made by this UI have the comment `openvpn-ui` in 3x-ui; clients you
  add in the panel yourself are left alone.
* A key ends with the certificate: revoking, deleting or creating a client
  again under its name removes its 3x-ui client at once, and an hourly check
  removes what is left and moves end dates after renewals.
* Xray gives internet only, for full-access clients and guests alike: a
  routing rule (`ruleTag` `openvpn-ui-no-lan`, kept right after 3x-ui's own
  `api` rule) sends private ranges, the pushed routes and every network of this
  host to `blocked`. Use OpenVPN for the LAN.
* Traffic per client is in the 3x-ui panel; the charts of this UI count
  OpenVPN and the relay.
* `xui/` holds 3x-ui's database and the UI's API token (`openvpn-ui.json`); it
  is in the backups. Delete `xui/openvpn-ui.json` to have a new panel login
  and token made at the next start.

## Telegram bot

Clients get access themselves from a Telegram bot: a one-time link to their
OpenVPN profile, to their Apple relay profile (when relay profiles are on), a
new portal password, and their status.

1. Create a bot with [@BotFather](https://t.me/BotFather) (`/newbot`) and
   paste its token in **Settings → Telegram** (or set `OVPN_TELEGRAM_BOT_TOKEN`
   in `.env`; a token saved in the UI wins). Send `/start` to the bot from your
   own account: it answers with your Telegram ID; enter it there as *Your chat
   ID* and press *Send test message*. Access requests from people the bot does
   not know, and newly linked accounts, are sent to that chat. The server needs
   outgoing HTTPS to `api.telegram.org` (`curl -sI https://api.telegram.org`).
   The bot polls; no port is opened. One token = one running UI: a second copy
   polling the same token makes both fail with "Conflict".
2. On a client page, **Telegram & portal**: enter the person's Telegram
   username and tell them to open `t.me/<your bot>` and press Start.
3. The first message from that username links its Telegram account to the
   client. From then on only that account gets answers, even if the username is
   later changed or taken by someone else. A new username from the admin
   unlinks the old account.

The bot answers only private chats and only linked accounts, at most 20 links or
passwords an hour per account. Links work once and for one hour; they need the
website hostname in Settings → Network and traefik 1.2.0 or later (see
[One-time profile links](#one-time-profile-links)). A new password ends the
client's earlier portal sign-ins. Everything the bot does is in the event log
with the actor `telegram`.

## Upgrading to 2.5

```shell
cd ~/openvpn-server && git pull --ff-only
# .env: RELAY_CERT_DOMAIN, ACME_EMAIL and the DNS provider's credentials (see below)
sudo docker compose up -d --build
sudo docker compose logs -f relay-cert     # until "handed to the relay"
```

In this order: deploy 2.5 first, check that the Relay page shows HTTP/2
"direct" and the certificate, and only then forward TCP 8443 from the router
to this server (UDP 8443 already comes here for HTTP/3). Forwarding TCP 8443
here before 2.5 runs cuts off every HTTP/2 profile. The DNS provider's values
are the ones in the gateway's `.env`: copy those lines over as they are. Profile
signing stays on the gateway (its signer reads the gateway's certificate); the
gateway is out of the relay's data path, not out of the picture. See
[HTTP/3 and HTTP/2 straight to this server](#http3-and-http2-straight-to-this-server).

## Upgrading to 2.4

```shell
cd ~/openvpn-server &&
sudo ./backup.sh &&                        # the new database layout cannot go back to 2.3
git checkout main && git pull --ff-only &&
sudo sysctl -w net.netfilter.nf_conntrack_acct=1 net.netfilter.nf_conntrack_timestamp=1 &&
printf 'net.netfilter.nf_conntrack_acct = 1\nnet.netfilter.nf_conntrack_timestamp = 1\n' |
  sudo tee /etc/sysctl.d/99-openvpn.conf &&
sudo docker compose up -d --build          # OpenVPN clients reconnect once
```

The database is upgraded on the first start; installed OpenVPN and relay
profiles keep working. `git checkout main` is needed once, only on a checkout
that was switched to a test branch. The two host settings are for
[Traffic by podkop section](#traffic-by-podkop-section), which also needs
podkop-agent 0.27 on the router and **Settings → Router** here.

## Upgrading to 2.3

```shell
cd ~/openvpn-server &&
git pull --ff-only &&
sudo docker compose up -d --build          # all images change; OpenVPN clients reconnect once
```

The database is upgraded on the first start (traffic gets a source, relay
sessions recorded so far are added to the traffic charts). Installed OpenVPN
and relay profiles keep working. If your `.env` was copied from an older
`.env.example`, delete its `APPLE_RELAY_MAX_FLOWS`, `..._PER_CLIENT`,
`..._MAX_H2_STREAMS` and `APPLE_RELAY_TRANSPORT` lines to get the new defaults.
The gateway needs no change. HTTP/3 is optional, see
[HTTP/3 and HTTP/2 straight to this server](#http3-and-http2-straight-to-this-server).

## Upgrading to 2.0

2.0 moves the UI's state from SQLite to PostgreSQL and adds the Apple relay
and the guests' portal. From 1.x (or 2.x):

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
| `OVPN_MSS` | `1320` | TCP MSS clamp for tunnel traffic; `0` = off |
| `OVPN_TCP_CONGESTION` | `bbr` | TCP congestion control the host should use (relay over HTTP/2, OpenVPN over TCP); empty = leave the host's. If the container cannot set it, the log gives the host command |
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

OpenVPN and the Apple relay are two ways in for the same clients, and the
pages count them together: traffic, sessions, "online" and "last seen" cover
both, with the split shown next to each number.

* **Periods** - today, yesterday, this week (from Monday), this month, last
  month, all, or two dates of your choice, in the browser's time zone. The
  exact start and end are printed under the buttons.
* **Dashboard** - *online now*: clients (not connections) with an OpenVPN
  connection or an open relay connection; *active users*: clients with
  traffic in the period over either; download, upload, throughput for the
  last hour, traffic over the period and top clients, for both or one of the
  two; the connected clients of both; rejected connection attempts of the
  last 24 h; warnings (unreachable server, expiring certificates/CRL, 2FA
  enforced without secrets).
* **Clients** - state (online and over what, valid, expiring, expired,
  revoked), expiry, last seen, traffic in the period, session count. A client's
  page has its traffic, one list of its OpenVPN visits and relay sessions, and
  **Relay connections**: every finished relay connection of the last 7 days
  with time, destination, result, duration and bytes, with a destination
  filter. Create clients with
  full access or guest, optional validity, static IP, key passphrase, note and
  2FA. Download the `.ovpn` profile (always regenerated from the current
  template) or share it with a one-time link and QR code, switch between full
  access and guest, show the 2FA QR code and rejected connection attempts,
  disconnect, renew, revoke, delete.
* **Sessions** - OpenVPN and relay sessions in one list (filter by either);
  for OpenVPN every connection with duration, source address, protocol
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
poll), falling back to the management interface when there is none. Relay
traffic is read every 5 s from the relay's status. Both are stored per client
and source, per minute for two days, per hour for 90 days and per day forever.
The relay's connection log names the destinations a client opened (host and
port, never content) and is deleted after 7 days; tell your users.
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

**Share link** on a client page makes a link that hands out one profile once
and expires (1 h to 7 days): the OpenVPN profile, or, when Apple relay profiles
are offered, the relay profile. The link itself (`https://.../p/<token>`)
opens a small page: *Open in OpenVPN Connect* and *Download* for OpenVPN,
*Install the profile* for the relay (open it in Safari on the device). Looking
at the page does not use the link up, so it can be sent through a messenger
that fetches links for a preview. The profile is behind
`/p/<token>/download`, once. For OpenVPN the QR code holds the
`openvpn://import-profile/https://.../p/<token>/download` form: scanning it on
a phone opens OpenVPN Connect and imports the profile. A link is spent only
when the profile was really delivered.

Links use `https://<website hostname>` from Settings → Network
(`OVPN_PROFILE_BASE_URL` overrides it). The gateway in
[traefik](https://github.com/dkagramanyan/traefik) 1.2 routes `/p/` of that
hostname from anywhere and keeps the rest of the website for trusted networks.
Guests connected to the VPN can open links too. With another reverse proxy,
forward only the `/p/` path to the UI and set the trusted proxy CIDRs in
Settings to the proxy's address, so failed attempts are rate limited per
visitor, not per proxy.

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
| `10.8.0.128/25` (`GUEST_SUB`) | guests: internet, the pushed DNS servers and the personal portal; no LAN |

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
redirect (see [Guests](#guests-internet-the-personal-portal-no-lan)) and drops
everything local, including traffic to other VPN clients and to the server
host itself; the rest goes to the internet.
The rules live in the chains `OVPN-NAT`, `OVPN-INPUT`, `OVPN-FORWARD` (hooked
into `DOCKER-USER` when Docker manages the firewall, else the top of
`FORWARD`) and `OVPN-ACCEPT` (end of `FORWARD`). They are flushed and rebuilt
every time OpenVPN starts, also on a restart from the UI, and checked once a
minute: if a firewall reload on the host removed them, they are installed
again. `fw-rules.sh` runs in between; append your own rules to `OVPN-FORWARD`
there.

`OVPN-MSS` (table `mangle`) lowers the TCP segment size of connections through
the tunnel to `OVPN_MSS` (1320), so that an encrypted packet fits networks
with an MTU down to 1412 (mobile networks often carry less than 1500). OpenVPN's own `mssfix` does this only without kernel
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
and the TCP fallback, the SQLite import, the guest rules, two devices on one
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
