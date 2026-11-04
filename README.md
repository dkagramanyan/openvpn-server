# openvpn-server

OpenVPN server in Docker with a web UI for client management, live status and
per-client traffic statistics.

* **OpenVPN 2.7.7** and **easy-rsa 3.2.7**, built from the signed upstream
  release tarballs on Alpine 3.24 (38 MB image).
* **Web UI** (`ui/`): dashboard with live throughput and connected clients,
  per-client traffic history (minute/hour/day roll-ups), session history with
  the device, protocol and ending of every connection, daily backups,
  certificate lifecycle (create, download, renew, revoke, delete), static IPs,
  TOTP two-factor authentication with QR enrolment, config editors, log viewer,
  audit log. No JavaScript dependencies, works offline, light and dark theme.
* **Security**: containers run unprivileged (`NET_ADMIN` only), the management
  interface stays on the host's `127.0.0.1` behind a generated password, `tls-crypt`,
  TLS 1.2+ with a pinned cipher list, EC (secp384r1) certificates, CRL
  auto-renewal, strict forwarding rules, no Docker socket in any container.
  See [Security notes](#security-notes) for what the web UI can and cannot do.

Originally based on [d3vilh/openvpn-server](https://github.com/d3vilh/openvpn-server);
the UI replaces d3vilh/openvpn-ui.

## Quick start

```shell
git clone https://github.com/dkagramanyan/openvpn-server
cd openvpn-server
cp .env.example .env        # set the admin password and your public host name
python3 bin/setup-env.py    # generate missing PostgreSQL passwords
docker compose up -d --build
```

This starts OpenVPN, the UI and Apple Network Relay together. By default, the
relay is an HTTP/2 backend for Traefik: certificates stay on the proxy machine.
See [Apple Network Relay](#apple-network-relay) for the TCP routing setup.

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

## Upgrade to PostgreSQL (1.8)

The UI now stores accounts, settings, sessions, traffic and audit history in
PostgreSQL. SQLite is used only to read a legacy database during migration.
For an existing deployment, keep your `.env`, PKI and `db/` directory and run:

```shell
cd ~/openvpn-server &&
git pull --ff-only &&
bin/upgrade-relay.sh --sudo-docker
```

Without sudo, omit `--sudo-docker`. The helper generates missing PostgreSQL
passwords in `.env` (mode 0600), builds before stopping the old UI, starts
PostgreSQL, and pauses the UI and relay while importing. It leaves an already
running OpenVPN container running. The legacy `db/openvpn-ui.db`, including
committed WAL data, is read from a consistent read-only snapshot. All known
application tables are imported in one PostgreSQL transaction and their row
counts are checked before commit. Existing password hashes, portal accounts,
relay secrets, share links, notes, traffic and session IDs are preserved;
guest markers and certificates remain in their existing directories.

If an import fails, its writes roll back and the helper starts the previous
UI/relay containers again. A completed import is recorded, so rerunning the
helper does not duplicate data. A nonempty PostgreSQL database without the
migration marker is refused rather than merged or overwritten. Keep the
original SQLite file as a recovery copy; the UI refuses to bootstrap a new
admin account over unimported legacy state. After PostgreSQL has accepted new
writes, reverting to the old SQLite UI would lose those new writes: recover
from a PostgreSQL backup instead.

PostgreSQL 18 runs in the `postgres-data` named volume, exposed only on
`127.0.0.1:5433`. Change `OPENVPN_DB_PORT` if that local port is occupied.
`POSTGRES_PASSWORD`, `OPENVPN_DB_PASSWORD` and `RELAY_POLICY_DB_PASSWORD` are
generated once; preserve `.env` together with the volume. Changing a password
in `.env` alone does not change a role in an already initialized database.
Never use `docker compose down -v` on a deployment whose data you want to keep.

### Recover a permission-interrupted Git update

If `git pull` failed with permission errors and then reported modified code or
untracked incoming files, run the recovery helper as your normal login user:

```shell
cd ~/openvpn-server &&
ovpn_repair=$(mktemp /tmp/ovpn-recover.XXXXXX) &&
curl -fsSL https://raw.githubusercontent.com/dkagramanyan/openvpn-server/main/bin/recover-checkout.py -o "$ovpn_repair" &&
python3 "$ovpn_repair" --repo "$PWD" --repair-permissions &&
bin/upgrade-relay.sh --sudo-docker
```

Downloading the helper separately lets it run even when Git cannot update its
own checkout. It repairs ownership of code and Git metadata using sudo, saves
interrupted code changes and colliding incoming files in a targeted stash, and
fast-forwards `main`. Existing stashes are retained. If a previous stash from
the current commit saved runtime configuration, the helper restores those
specific files in place when they do not conflict with current/upstream edits.
Independent configuration or custom Compose changes stop recovery for review.
Private recovery records are kept under `.git/openvpn-recovery/`.

The helper does not restart containers, reown runtime directories, or stash
guest markers, databases, keys or `.env`. Applying an entire old stash over the
updated application would bring back old code; use the saved records to review
any remaining custom code changes instead.

### Relay reliability and diagnostics

The independent `relay-policy` service reads a restricted PostgreSQL view and
public certificate/access metadata. Its login cannot read admin password
hashes or write settings, and its container does not mount private CA/client
key directories. UI restarts no longer remove the relay's policy endpoint.
After an atomic `server.conf` save, the policy process detects its old file
mount and restarts automatically so Docker mounts the current configuration.
Requests fail closed during that brief refresh.
Successful authorization is cached for at most one second; active flows are
rechecked every five seconds. Missing policy/DB state fails closed, with a
retryable 503 for new requests; explicit credential denials return 403.

The **Relay** page shows policy availability, connection limits and separate
reasons for authorization, capacity, DNS and destination failures. Host-local
endpoints are `http://127.0.0.1:8446/readyz` and `/metrics`; do not publish them.
Readiness checks policy/DB/metadata availability, not reachability of every
internet service. Default limits are 256 total flows, 64 per client, 64 parallel
authorization checks, 128 HTTP/2 connections and 256 streams per connection.
Client limits apply across all devices using that client's credential. See
`.env.example` for overrides.

HTTP/2 sends a PING after 10 seconds without incoming frames and closes a
nonresponsive path after a further 5 seconds. A blackholed-path regression test
checks that abandoned flows release capacity and a new connection using the
same credential succeeds. Existing TCP streams still need to reconnect when a
network path disappears. Recovery on a physical iPhone must be checked after
this update; server-side tests cannot prove how a particular iOS version
retries its connections.

The first stage of the research-PDF recommendations is implemented here:
independent policy evaluation, fair limits, typed failures and diagnostics.
Simultaneous HTTP/3 + HTTP/2 fallback, live QUIC certificate reload and drain,
and measured DNS/MTU tuning remain later work. The current Traefik HTTP/2
forwarding and signing setup can stay as it is. DNS failures do not silently
bypass the relay or relax guest restrictions.

## Apple Network Relay

The existing **Clients** list and client page have adjacent **OpenVPN** and
**Apple relay** downloads. The Apple download is a per-client `.mobileconfig`
profile for Apple's built-in Network Relay. The `apple-relay` service
provides authenticated TCP CONNECT and MASQUE CONNECT-UDP over HTTP/2, with
optional direct HTTP/3 support. It starts alongside OpenVPN and the UI with
the same Compose command. Both guest isolation and full internet/LAN access
are enforced by the relay regardless of transport.

To enable it:

1. Keep `APPLE_RELAY_TRANSPORT=http2` (the default). In **Settings → Network and
   private portal**, enter the gateway's actual source address under **Trusted
   reverse proxy CIDRs**. The initial trust list contains loopback only.
   The backend checks the TCP peer and ignores forwarded headers for trust.
2. Enter the gateway and relay backend details in that same UI, download the
   private Traefik settings and import them on the gateway. Traefik terminates
   TLS with ALPN `h2` and forwards HTTP/2 to the relay's LAN listener. Keep the
   unencrypted backend hop on a trusted network.
3. Start the services:

   ```shell
   docker compose up -d --build
   ```

4. In **Settings → Network and private portal**, enable Apple relay profiles.
   Existing public relay addresses and ports are kept; **Public connection
   addresses** supports another hostname or port. Enter LAN CIDRs (e.g.
   `192.0.2.0/24`) in **LAN networks blocked for guests**, shared by VPN and relay.
   Access follows each client’s
   OpenVPN role: guests have internet only; full-access clients have internet
   and LAN. Save settings. Names such as `nas.home.arpa` must resolve to the intended
   LAN addresses **from the relay container**; configure its DNS in Compose if
   your Docker DNS does not resolve your LAN names.
5. Configure **Relay → Profile signing** using the existing Traefik signing
   endpoint and shared token (see [Automatic signed profiles](#automatic-signed-profiles)).
   Signed downloads are required by default.
6. Under **Clients**, download **Apple relay** beside that client's OpenVPN
   config. Transfer the file privately to the iPhone, iPad or Mac and install it
   in system Settings. On iOS/iPadOS, open the downloaded profile and complete
   installation under **General → VPN & Device Management**; on macOS use
   **Device Management / Profiles** in System Settings.

When upgrading from the earlier HTTP/3 version, **download and reinstall the
profiles** even if the URL is unchanged. Profiles now contain `HTTP2RelayURL`.
Compose sets the same transport for the relay and UI; Settings displays it.
Do not overwrite an existing `.env` with `.env.example` when upgrading.

The profile uses Apple's `com.apple.relay.managed` payload (introduced in
iOS/iPadOS 17 and macOS 14). See the
[Apple payload schema](https://github.com/apple/device-management/blob/release/mdm/profiles/com.apple.relay.managed.yaml)
and [Apple's network relay overview](https://support.apple.com/guide/deployment/dep91a6e427d/web).
Manual installation is supported; Apple marks this payload deprecated starting
with OS 27 in favor of declarative device management. Device interoperability
still needs to be verified on your target Apple OS version.

All new profiles route all domains through the relay. Full-access clients can
reach internet and LAN destinations; guest destinations remain restricted on
the server. Legacy LAN-only settings no longer override the OpenVPN access role.
Download and reinstall old LAN-only profiles once to update their domain selection.
Guest profiles route all domains
through the relay, allowing public IPv4 internet destinations only. IPv6 guest
egress is blocked, consistent with the OpenVPN setup. The relay proxies TCP/UDP
connections. It does not assign a VPN address, carry ping, discover Bonjour
services or install IP subnet routes. Use LAN DNS names with the relay, and the
`.ovpn` profile when you need an IP VPN. Do not use `.local` multicast names for remote
access. OpenVPN statistics show OpenVPN traffic only.

The server checks **resolved destination IPs**, then connects to those exact
addresses to prevent DNS rebinding around the CIDR policy. Loopback, link-local,
unspecified and multicast destinations are always blocked. Full-access clients can reach all other destinations. Guests can download
relay profiles too, but cannot reach private, VPN, configured LAN, directly
attached or special-purpose networks. `HOME_SUB` and `GUEST_BLOCK` are shared
between the OpenVPN and UI services; pushed routes and the relay's allowed LAN
CIDRs are also excluded from guest egress. Include public NAT addresses that
forward to protected LAN services in `GUEST_BLOCK`: otherwise a guest can loop
back through the public address and appear LAN-trusted to a reverse proxy.
Enter your own public ingress addresses under **Other networks blocked for
guests** in Settings → Network. This block applies
to both OpenVPN guests and relay guests, including public services sharing
that address.

An optional [private portal exception](https://github.com/dkagramanyan/traefik#private-portal-for-lan-openvpn-guests-and-apple-relay-guests)
uses a separate Traefik listener serving only portal paths. Enter the portal hostname, target and DNS addresses in Settings → Network after
deploying that listener. This does not remove the guest LAN blocks: OpenVPN
redirects only guest TCP 443 connections to the listed IPv4 destinations, and
the relay pins only the portal hostname/addresses to that listener. Authentication
and live relay revocation checks still apply. Clear the portal enable checkbox to disable it.

| Access type | OpenVPN | Apple relay |
|---|---|---|
| Guest | Internet and configured DNS; no LAN | Public IPv4 internet; no LAN |
| Non-guest (Full access) | Internet and LAN | Internet and LAN |

Each profile contains a separate random bearer credential. It does not use the
OpenVPN key passphrase or TOTP challenge. Repeated downloads reuse the current
credential. **Revoke relay access** on the client page invalidates installed
relay profiles without touching OpenVPN; the next download creates a new
credential. Revocation, expiry and deletion deny relay access. Guest/full-access
changes update the existing credential's permissions automatically. Renewal
through the UI preserves the same client's relay credential; an unexpected
certificate replacement outside the UI still requires a new download. Active flows recheck access every five seconds
(up to about nine seconds including the one-second policy cache and three-second
authorization timeout), and fail closed if the UI becomes unavailable. OpenVPN
access-type changes take effect when devices reconnect.

Concurrent connections share authorization results for at most one second,
without extending stale results on errors. Closing one flow does not cancel
the shared authorization check for other flows. The backend checks only that client's
certificate and caches the PKI index until the file changes. TCP connections try
validated destination addresses with a 200 ms stagger, so an unreachable first
address does not block a reachable alternative. HTTP/2 checks idle connections
with PING after 20 seconds and times them out after 10 more seconds without a
reply. QUIC keepalives run every 20 seconds in direct HTTP/3 mode. Both modes
use a 90-second idle-connection timeout and preserve responses after a client
half-closes its TCP upload. HTTP/2 transports UDP as RFC 9297 datagram capsules;
packet loss can stall its shared TCP connection, while HTTP/3 uses QUIC datagrams.
Short authorization transport failures and HTTP 502/503/504 responses are retried
within the same three-second deadline; explicit access denials are never retried
and expired policy is never reused during an outage.

If quic-go reports a low UDP receive buffer, the host's socket buffer limits can
limit throughput under load. Check the
[upstream buffer guidance](https://github.com/quic-go/quic-go/wiki/UDP-Buffer-Sizes)
before adjusting host settings. The application does not modify host sysctls.

The relay authenticates against `relay-policy` over host loopback on port 8447
and has no direct access to the PKI or database. The independent policy service
uses public identity metadata and its restricted PostgreSQL login. Changing the
transport or public URL requires redistributing profiles; CIDR changes and disabling relay
access take effect on existing connections without redistributing them.

Installing a profile or enabling its download does **not** verify that the relay
service is running. If a profile installs but no services open, check the service:

```shell
docker compose ps -a apple-relay
docker compose logs --tail=50 apple-relay
ss -ltnp 'sport = :8444'
```

An empty container list means it has not been created. Older Compose files put
the relay behind an optional profile; update the checkout, then run
`docker compose up -d --build` to start the services (after the PostgreSQL upgrade helper on an existing installation). You can also start
only the relay without restarting OpenVPN:

```shell
docker compose up -d --build --no-deps apple-relay
```

Installed profiles keep their credentials and identifiers across container
restarts and server reboots. Keep the same Compose project, `.env`, PKI and
PostgreSQL volume. HTTP/2 accepts connections only after policy/database readiness;
on a planned stop it sends GOAWAY before closing old tunnels. Existing TCP
connections reconnect after a restart; restarting services does not require
downloading another profile. Docker must start at boot, and containers explicitly
stopped with `docker compose stop` need `docker compose up -d` to start again.
Automatic recovery on a particular Apple OS/device still needs deployment testing.

For HTTP/2, verify WAN TCP 8443 reaches Traefik, its TCP router forwards to the
backend's TCP 8444, and the trusted proxy CIDRs in Settings match the gateway source address.
An ordinary Traefik HTTP router rejects CONNECT; use a TCP router with TLS termination.
A successful profile download in the UI logs only confirms profile generation;
Relay activity in the UI and `/readyz` provide the policy/data-path diagnostics;
authorization checks now go to the independent service rather than the UI log.

Run relay checks with `cd relay && GODEBUG=http2xconnect=1 go test -race ./... && go vet ./...`.
Set `TRAEFIK_BIN` to a Traefik executable to include real TLS-termination tests
(CI downloads a checksum-verified binary and runs them). The Docker image sets
`GODEBUG=http2xconnect=1` to enable extended CONNECT in Go's HTTP/2 implementation.
API and profile tests are included in `python -m pytest ui/tests -q`.

### Automatic signed profiles

The UI can return CMS-signed `.mobileconfig` downloads using the certificate
Traefik already manages. The signer runs on the gateway with read-only
access to `letsencrypt/acme.json`; private keys never move to the OpenVPN host.
It selects a valid, publicly trusted identity for the configured hostname,
includes its intermediate chain, and reloads renewed certificates without a
restart. The UI verifies the signature, certificate chain, hostname and exact
profile contents before returning a download. Signed relay downloads are
required by default (`OVPN_RELAY_REQUIRE_SIGNED=true`). Missing signing setup
or an unavailable signer returns 503 and never silently produces unsigned XML.
An administrator can explicitly allow unsigned downloads for development. Installed profiles continue using their relay
credentials independently of the signer.

The gateway deployment lives in the separate
[Traefik repository](https://github.com/dkagramanyan/traefik#automatic-profile-signing).
It owns the gateway's Compose stack, routes, monitoring and certificate paths. Follow
its migration instructions to retain the existing ACME store and Docker volumes.
The optional `profile-signing` Compose profile builds the signer from a pinned
revision of this public application's source; the gateway needs no OpenVPN checkout.

Generate a shared token with `openssl rand -hex 32`. In the gateway's existing `.env`,
set `COMPOSE_PROFILES=profile-signing` and `RELAY_PROFILE_SIGNING_TOKEN` to that
value, then run `sudo docker compose up -d --build` from its deployment folder.
The HTTPS signing route publishes no additional host port and accepts only the
configured OpenVPN backend, authenticated with the shared token.

On the OpenVPN host, open **Relay → Profile signing**. Set the signer URL to
`https://openvpn.example.com/internal/relay-sign` and paste the **existing**
`RELAY_PROFILE_SIGNING_TOKEN` from the Traefik `.env`. Keep **Require signed
relay profiles** checked, save, and check for **Signed downloads enabled**.
The token field is write-only; blank input keeps the existing token. These UI
settings are stored in PostgreSQL and take precedence over environment values.
Use **Use environment settings** to clear the UI override when switching back.
The policy service cannot read them. Keep tokens and downloaded profiles private.

Alternatively, add to the OpenVPN host's existing `.env`:

```dotenv
OVPN_RELAY_SIGNER_URL=https://openvpn.example.com/internal/relay-sign
RELAY_PROFILE_SIGNING_TOKEN=THE_SAME_GENERATED_VALUE
```

For environment changes, run `bin/upgrade-relay.sh --sudo-docker`. Open **Relay**
and check **Signed downloads enabled**. Download a new profile and verify the signer on
your target iPhone before distributing profiles. If iOS says **Not signed**, the installed file is still unsigned: after setup,
download it again and replace the old installed profile. A previously downloaded
file cannot acquire a signature automatically. Apple still asks users to
confirm installation; signing identifies the source rather than hiding what
the profile does. Apple may require removing an older signed profile before
installing a replacement signed with a renewed identity.

All operator credentials belong in `.env` or the UI's existing account settings.
No signing token or private key is returned by diagnostic APIs. Certificates
must chain to a root trusted by both the server and the Apple device; self-signed
identities do not remove the trust warning on unmanaged devices. See
[Apple's profile signing example](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/iPhoneOTAConfiguration/profile-service/profile-service.html)
and [profile replacement rules](https://developer.apple.com/documentation/devicemanagement/configuring-multiple-devices-using-profiles).

### Relay activity and reliability checks

The **Relay** page groups active connections and recent activity by client
across all devices. Expand a client to inspect destinations and individual
results. Summaries show active TCP/UDP counts, accepted flows, denied requests,
failed connections, traffic and the last issue. TCP and HTTP/2 UDP byte counters
update during active transfers. HTTP/3 UDP payload bytes remain uncounted and
are marked as such. Portal users can see their own aggregate activity; another
client's destinations and signing credentials are never returned to that login.

Counters reset on relay restart. History retains up to 2048 inactive clients
plus active clients, and details use a 500-event ring. Container logs emit one
terminal record per flow, with repeated failure records capped at 20 per second;
all failures still update counters/the ring. Suppressed-log and transport-error
counters are available in `/metrics`. Malformed HTTP/2 input is never echoed
into logs.
Credentials and profile contents are never logged. Diagnostic data is exposed
only through authenticated UI endpoints; the relay's internal status server binds
to host loopback at `127.0.0.1:8446`. Keep that port free and do not proxy it.
The Docker health check monitors the relay process through that local endpoint.
Responses and events distinguish policy denials (403) from destination DNS,
connection-refused, unroutable and timeout failures. Error responses include
fixed RFC 9209 `Proxy-Status` codes without raw errors or internal topology.
A refused TCP setup is retried once after 150 ms, inside the existing five-second
budget, using only validated numeric addresses and before sending application
data. This does not replay an established application request.

An iPhone can report a server error while other relayed connections work. In
the reported iOS 26.6.2 logs, Apple gateway TCP destinations sometimes failed
and later succeeded. That confirms partial destination failures; it does not
prove which failed flow caused the Settings label. Inspect `upstream_error` and
HTTP status in the expanded activity, then recheck the physical phone after
updating. The server cannot directly set iOS's displayed status.

HTTP/2 UDP flows with no traffic expire after two minutes to release resources;
the OS can establish a new flow when traffic resumes. TCP sockets use keepalives,
and completed responses release uploads that a peer leaves open.

Real-container integration can be reproduced with the UI's test dependencies
plus `pytest` and `httpx` installed on the host:

```shell
docker build -f signer/Dockerfile -t openvpn-profile-signer:relay-test .
docker build -f relay/Dockerfile -t openvpn-apple-relay:relay-test .
docker build -f ui/Dockerfile -t openvpn-ui:relay-test .
python tests/relay-stack.py
```

It starts isolated UI, signer, relay and Traefik containers with temporary
certificates and credentials, verifies a signed download, sends a real HTTP/2
CONNECT request to a LAN service, tests role changes without replacing the
profile, checks the activity API and denies revoked access. Containers and test
networks are removed afterwards. The Go tests separately exercise UDP capsules,
concurrent transfers, half-closes and revocation through real Traefik with the
race detector enabled. No application can guarantee connectivity during a DNS,
ISP, proxy, authorization-service or server outage.

### Traefik HTTP/2 setup

Gateway configuration is maintained in the separate
[Traefik repository](https://github.com/dkagramanyan/traefik#network-settings-from-the-admin-ui).
Enter its hosts, backend addresses and private-service inventory in the admin UI,
then import the downloaded private settings on the gateway. No deployment
addresses or services are shipped in the routing template.

The relay needs a TCP router that terminates TLS, negotiates ALPN `h2` and
forwards decrypted HTTP/2 to its backend. Set the trusted proxy CIDRs in the UI
to the proxy's actual source addresses. Keep that backend on a trusted LAN.
Website routes stay on port 443.
[Traefik's TCP TLS documentation](https://doc.traefik.io/traefik/reference/routing-configuration/tcp/tls/)
describes termination; its [CONNECT guidance](https://doc.traefik.io/traefik/migrate/v3/#connect-requests)
directs forward-proxy tunnels through TCP routers.

On the OpenVPN host, run `sudo docker compose up -d --build`. The relay log
should report an HTTP/2 backend listening on TCP 8444. In the UI, save the relay
URL and download fresh profiles after changing transport or URL. Traefik
certificate renewals need no relay restart or new profile.

### Direct HTTP/3 mode (optional)

For direct QUIC access, set `APPLE_RELAY_TRANSPORT=http3` in `.env`, supply
`relay-tls/fullchain.pem` and `relay-tls/privkey.pem` readable by UID 65532, and
forward WAN **UDP 8443 directly to the OpenVPN host**. `APPLE_RELAY_BIND` controls
that UDP listener. Rebuild/recreate with `docker compose up -d --build` so both
the UI and relay switch transport, then download and reinstall profiles.
This mode requires a valid certificate on the relay host and a process to
refresh it before expiry. The optional [certificate export helper](bin/export-relay-cert.py)
can export a matching identity from an operator-provided ACME store after
checking the hostname, dates and private-key match. It never modifies that
store. Follow your proxy deployment's certificate-transfer procedure, then
restart `apple-relay` after installing renewed files. Keep private keys local
and out of Git. Installed profiles remain valid when the hostname stays the same.

## Private network configuration

Use **Settings → Network and private portal** for public VPN endpoints, relay,
VPN addressing, DNS, guest blocks, trusted reverse proxies, the portal, and gateway
services. Set the gateway domain once: VPN profiles and relay use that domain,
while the website and portal share `openvpn.<domain>`. Existing profile, signing
and relay URLs prefill the form. The page groups setup into public addresses,
internal addresses, access/guest portal, and save/apply steps. Custom hostnames
are available under **Different hostnames**. The relay backend defaults to the
UI backend host on port 8444. One LAN list supplies VPN and relay guest blocks;
private-service access networks remain a separate allowlist.

**Detect addresses** reads the VPN server's interfaces, route-selected source
address, original reverse-proxy peer and portal DNS answers. It prefills empty
address fields and suggests individual proxy IPs, while preserving entered
values. Every suggestion stays editable and requires saving. It does not probe
or change your port forwarding, infer public NAT mappings, or automatically
grant a detected network access to private services. A separate button allows
the administrator to add the detected LAN to that allowlist explicitly.

For ordinary portal access, enable **Allow guests to use the private portal**
and export the Traefik settings. The guest subnet is added only to the portal's
source allowlist; private/admin service networks are kept separate. The default
portal sources also include the VPN/relay egress IP because Traefik may see that
address after NAT. No dedicated listener or DNS redirect fields are required.

**Advanced: routing through guest LAN blocks** retains optional dedicated portal
routing when guests cannot otherwise reach the gateway. Existing dedicated
settings are preserved. This option can be staged on the gateway before enabling
its VPN/relay exception. The normal allowlist option does not relax guest LAN
blocks or add a relay destination exception. Existing additional gateway services
are preserved unless **Manage and replace the gateway's additional services here**
is checked.

**Save settings** applies the combined form. VPN profiles regenerate only when
their endpoint changes. **Save and download Traefik settings** saves current edits
before exporting. VPN/firewall settings are saved in
`config/network/settings.conf` with mode 0600. This
directory is excluded from Git and container build contexts. Network changes also
update your installed `server.conf`; save and restart OpenVPN to apply them.
Runtime `server.conf` and `config/client.conf` are ignored; only generic `.example`
templates are shipped.

Before upgrading a checkout that tracked its live configuration, preserve it:

```sh
mkdir -p config/network
cp server.conf config/network/server.conf
cp config/client.conf config/network/client.conf
chmod 600 config/network/*.conf
```

Do this **before pulling** the update that replaces tracked configs with templates.
The entrypoint restores those private copies if the runtime files are absent.
It keeps existing runtime files and only uses generic templates on a new install.

The initial VPN range is a generic bootstrap network, not a deployment example.
Existing server settings populate the form. Fill in your own LAN and public
loopback destinations before admitting guest clients. Download the gateway export
and import it with `./manage setup --network-file /path/to/network.private.json`
in the Traefik checkout; no hand-edited network environment values are required.
The export contains network information and should remain private. Credentials
remain in local secret storage; they are not included in the export.

## User download portal

The personal portal offers step-by-step Apple relay and OpenVPN installation
instructions, with connection activity and password changes in expandable
sections. Apple relay uses a native, session-protected HTTP form download so
Safari can hand the profile to Settings. JSON and plain-text gateway errors are
handled without exposing browser parsing errors. A blocked route is reported
with useful retry/contact instructions; gateway access restrictions remain in
effect. Use [Apple's profile installation guide](https://support.apple.com/102400)
for the installation steps on Apple devices.

Administrators can create or reset a personal website login from
**Clients → client → Portal access** and disable it from the same dialog.
Passwords are hashed with scrypt, never returned by the API, and existing sessions
are invalidated on an admin reset. Each account is bound to one current client
identity. The same certificate validity and guest/full-access role apply to its
OpenVPN and relay downloads. Revocation, expiry, deletion or an unexpected
certificate replacement denies portal access; renewal through the UI preserves it.
These website passwords are separate from OpenVPN key passphrases and TOTP.

Users sign in at **`https://openvpn.example.com/portal`** to download their
own OpenVPN config and automatically signed Apple relay profile, and change
their own password. They have no access to other clients, server settings,
relay logs, credentials or administrator endpoints. The backend enforces this
for every administrative API, including direct requests outside the frontend.
Admin credentials are rejected by the user portal login endpoint.

Deploy [the portal route from the Traefik repository](https://github.com/dkagramanyan/traefik/blob/main/dynamic/portal.yml)
to serve `/portal`, `/api/portal` and static assets to explicitly allowed source
networks. Configure its dedicated private listener and the guest portal exception
above for remote OpenVPN/relay guests; the portal stays unavailable from the public
internet. First-time users need their initial profile delivered privately or LAN
access. The administrative website and APIs retain the existing `trusted-only`
rule. Sign-in throttling, CSRF checks and secure cookie settings
apply to both interfaces. Keep the existing `OVPN_UI_SECURE_COOKIES` and trusted
proxy settings appropriate for your HTTPS reverse proxy.
Enter your gateway source address in **Trusted reverse proxy CIDRs** and serve
cookies securely over HTTPS. Correct proxy trust also gives each user's real source IP
to the login limiter instead of combining all users under the proxy's IP.

## Layout

```
server.conf          OpenVPN server configuration (mounted at /etc/openvpn)
config/client.conf   template for client profiles ("remote" line managed by the UI)
config/easy-rsa.vars easy-rsa settings used when a *new* PKI is created
config/management.pw generated management-interface password (git-ignored)
pki/                 easy-rsa PKI (CA, certificates, CRL, tls-crypt keys)
clients/             generated .ovpn profiles, 2FA secrets and QR codes
staticclients/       per-client "ifconfig-push" files (static IPs)
guests/              one empty file per guest client
db/                  retained legacy SQLite source / restored PostgreSQL dumps
backups/             daily backup archives written by the UI (git-ignored)
log/                 openvpn.log, openvpn-status.log, oath.log
bin/                 CLI scripts (also used by the UI)
ui/                  web UI (Python/FastAPI)
fw-rules.sh          your additional iptables rules, applied at start
backup.sh            backup / restore helper
tests/e2e/           end-to-end test in Docker-in-Docker
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
| VPN subnet | From `server.conf` | Configure in Settings → Network |
| Guest subnet | Upper half of the bootstrap VPN network | Configure in Settings → Network |
| LAN networks | Empty | Enter your own LANs in Settings → Network |
| `GUEST_BLOCK` | RFC 1918, CGNAT, link-local | further ranges hidden from guests, next to every network `server.conf` pushes a route to |
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
| `10.8.0.128/25` (`GUEST_SUB`) | guests: internet and the pushed DNS servers only |

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

The entrypoint drops guest traffic to `HOME_SUB`, the `GUEST_BLOCK` ranges
(which include the other VPN clients), every network `server.conf` pushes a
route to (default routes aside), guest pings, and everything addressed to the
server host itself.
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

The end-to-end test starts the server, the UI, Apple relay and real OpenVPN clients inside
one Docker-in-Docker container, so it does not touch the network of the
machine it runs on. It covers UDP and the TCP fallback, guests and the
firewall, two devices on one certificate, the device limit, revocation,
backups (plain and encrypted) and restore. It runs without kernel offload.

The end-to-end test builds all three images and runs them inside one
Docker-in-Docker container, so its networks, tun devices and firewall rules
never touch the machine it runs on. Real clients connect over UDP and TCP,
leave, vanish and reconnect; the test then compares the UI with the log,
checks the MSS clamp, and restores the server from a backup archive.
`E2E_KEEP=1` keeps the container for a look at the UI.

GitHub Actions runs both on every push (`.github/workflows/ci.yml`). A weekly
job (`upstream.yml`) compares the OpenVPN, easy-rsa and Alpine versions
pinned in the Dockerfiles with the newest releases and opens an issue when
one is behind.
