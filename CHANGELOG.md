# Changelog

## 1.5.0 - 2026-10-02

### Added
* **How every session went.** A session now records the device (platform and
  client version), the protocol (UDP or the TCP fallback) and how it ended:
  *left* (the client said goodbye), *timed out* (it vanished), *closed* (a TCP
  connection ended). The UI reads this from `openvpn.log`; a connection shorter
  than the 5 s between two status files, which was not recorded at all before,
  is recorded from the log.
* **Connection quality** on the Sessions page: per client and time range, the
  number of sessions, their median length, the share under a minute, the
  endings and the share over TCP.
* **Visits.** A phone reconnects hundreds of times a day, so 100 sessions
  covered only a few hours. Reconnects of one client from one address at most
  15 minutes apart are now shown as one visit, on the Sessions page (**Merge
  reconnects**, on by default) and on the client page; **Every session** shows
  them one by one.
* **Daily backups.** The UI writes `backups/openvpn-backup-<time>.tar.gz` once
  a day and keeps 14 (`OVPN_BACKUP_KEEP`): configuration, PKI, profiles, 2FA
  secrets, static IPs, guests, `.env` and a consistent snapshot of the
  database. The Server page shows the last one and has **Back up now**; the
  dashboard warns after three days without one.
* **TCP segment size clamp** (`OVPN_MSS`, default 1400, `0` = off) in the
  firewall. With kernel offload (DCO) on Linux the data packets never pass
  through OpenVPN, so its `mssfix` did nothing on the server side.
* README: why phones make many short sessions, and the two OpenVPN Connect
  settings that change it.
* An end-to-end test (`tests/e2e/run.sh`) that runs the server, the UI and real
  clients inside one Docker-in-Docker container; GitHub Actions runs it and
  the unit tests on every push. A weekly job opens an issue when a newer
  OpenVPN, easy-rsa or Alpine release exists.

### Changed
* VPN connections are no longer written to the audit log, where they buried
  what admins did (about 2,000 lines a day against 100 shown). They are
  sessions. The connection lines already in the audit log are removed on the
  first start.
* `backup.sh`: `-y` skips the question (for cron), `-r` also restores from an
  archive written by the UI, and refuses to run while the service is up or
  when the backup does not exist.

### Fixed
* `backup.sh` left out `guests/`: after a restore every guest had full access.
* `backup.sh` copied the database as files while the UI was writing to it; such
  a copy can be torn. It now takes a snapshot.
* After an upgrade a browser could keep running the previous release's script
  against the new API for hours. The page now asks for the script and styles
  of its own version.
* Phone-width layout: the sign-out and theme buttons were missing, chart labels
  overlapped, the range buttons broke into two lines, the navigation showed a
  scrollbar and cut off its last icon, and table cells wrapped into columns of
  single words. On the dashboard the throughput tile was shorter than its
  neighbours.
* `server.conf` said the OpenVPN defaults size TCP segments to fit the path;
  with DCO they do not (comment corrected, see the clamp above).

### Upgrade notes
* `git pull && docker compose up -d --build`. The database is upgraded on the
  first start. Sessions recorded before this release have no device or ending.
* `server.conf` changed in a comment only.
* `backups/` appears next to `server.conf`, the first archive a minute after
  the start. The archives contain the CA key (readable by root only) and sit
  on the same disk as the server: keep a copy on another machine, see the
  README.
* The MSS clamp is on. OpenVPN Connect and the Windows client already lower
  the segment size on their side, so for them nothing changes.

## 1.4.2 - 2026-09-27

### Changed
* Clients get DNS `170.134.51.1` again, as on the old server: it answers the
  home domains with LAN addresses, so clients reach home services directly
  instead of looping through the public IP (Traefik saw every VPN client as
  `171.134.51.1`). The pushed route is `171.134.51.0/24` again, like before,
  instead of `170.134.51.0/24`.

## 1.4.1 - 2026-09-27

### Fixed
* **The UI stopped answering after some hours** and Docker marked it
  unhealthy. Every open live stream (`/api/stream`, one per browser tab or
  reverse-proxy connection) held one of the 40 worker threads, so about 40
  streams stalled every page and `/healthz` for up to 15 s; closed streams also
  stayed subscribed. The stream now runs on the event loop and holds no
  thread: 200 open streams leave `/healthz` at under 10 ms.
* **Duplicate IPv6 addresses.** A pushed IPv4 address (guests, static IPs)
  left OpenVPN's IPv6 pool out of step, so two devices could get the same
  `fd00:70::` address ("MULTI_sva: WARNING: if --ifconfig-push is used for
  IPv4 ..."). `client-access.sh` now pushes an IPv6 address derived from the
  IPv4 one (`10.0.70.129` -> `fd00:70::a00:4681`).

## 1.4.0 - 2026-09-27

### Added
* **One certificate on several devices**, each with its own address:
  `bin/client-access.sh` (client-connect) gives every device of a guest a free
  address from the guest range, and a static IP to the first device only.
  Guests are now a marker (`guests/<name>`) instead of a static IP; 1.3 guests
  are converted on start. Pool `10.0.70.2-99`, static IPs `10.0.70.100-127`.
* **Full access / Guest switch** on the client page.
* **One-time profile links** (Share link): a link valid once, for 1 h to 7 days,
  with a QR code of its `openvpn://import-profile/` form for OpenVPN Connect.
  Only `/p/` has to be public (`OVPN_PROFILE_BASE_URL`).
* **Rejected connection attempts** (revoked or expired certificate, unknown
  control channel key, wrong 2FA code) read from the logs, on the dashboard
  (24 h) and the client page (30 days).
* **Control channel key per client** (`tls-crypt-v2`), switched on the Server
  page. Off by default: the shared key and all current profiles keep working
  until you switch.
* DNS is also pushed as `dns server` (OpenVPN 2.6+, Connect 3).
* IPv6 no longer leaks around the tunnel: it is routed into it (private
  `fd00:70::/64`) and answered there with "no route" (`block-ipv6`). Verified
  with a client that has IPv6: before, public IPv6 left through its own link.

### Fixed
* Sessions named `UNDEF`: OpenVPN lists connections still in the TLS
  handshake without a name; they are no longer recorded, and old rows are
  removed.
* A client created again under an earlier name inherited that name's history.
  History now belongs to a certificate: a new certificate starts a new one, the
  old one stays as "name (earlier)", and renewals keep it. Data merged by
  earlier releases is split once, by the certificates' public keys.
* A client created again under an earlier name also inherited its static IP,
  guest access and 2FA secret.
* The "`duplicate-cn` and `client-config-dir`" warning: static IPs are applied
  by the connect script now.

### Upgrade notes
* Existing certificates and profiles keep working; nothing has to be handed
  out again unless you switch to per-client keys on the Server page.
* `server.conf` changed (`client-connect`, pool `10.0.70.2-99`, IPv6 lines,
  `dns` push). If you edited it on the server: `git stash && git pull &&
  git stash pop`, then `docker compose up -d --build`.
* A static IP inside the new pool (`10.0.70.2-99`) is listed on the dashboard;
  move it to `10.0.70.100-127`.

## 1.3.1 - 2026-09-26

### Fixed
* **Connected clients had no traffic after a restart with kernel offload
  (DCO).** An ovpn interface outlives an OpenVPN that did not exit cleanly;
  under host networking the next start found `tun0` taken, opened `tun1`, and
  replies to clients were routed into the dead `tun0`. The entrypoint now
  removes its own leftover ovpn interfaces (no IPv4 address, or the server's
  tunnel address) before every start.
* Client profiles fell back to the template's `127.0.0.1` when
  `config/client.conf` was reset (e.g. by a git checkout) while
  `OVPN_PUBLIC_HOST` was unchanged; the public host is now applied again.

### Changed
* Pushed DNS server: `171.134.51.1`.

## 1.3.0 - 2026-09-26

### Added
* **UDP with a TCP fallback in one profile.** OpenVPN listens on 1197/udp and
  1196/tcp at once (2.7 multi-socket `local` lines). Profiles carry a `remote`
  line per socket, UDP first, and `server-poll-timeout 10`, so a client whose
  UDP is blocked switches to TCP within about 10 s (verified end to end).
  Settings has a public port per protocol; editing the `local` lines rewrites
  the profiles. `OVPN_PUBLIC_PORT` is gone (ports default to the listening ones).
* **Full access / Guest switch** in the New client dialog. A guest gets the
  next free address from `GUEST_SUB` automatically; a full-access client may not
  take a guest address.

### Fixed
* The LAN is `170.134.51.0/24` (the server is 170.134.51.30): 1.2.0 set
  `HOME_SUB`, the pushed route and the pushed DNS to 171.134.51.0/24.

### Updated
* easy-rsa 3.2.7 (signature checked with the pinned maintainer key), Alpine
  3.24.2, Python 3.14 for the UI, uvicorn 0.54.0. OpenVPN 2.7.7, FastAPI and
  segno were already current.

### Upgrade notes
* Forward 1196/tcp to the server as well (and open it in the host firewall),
  then hand out the profiles again so clients learn the TCP fallback.

## 1.2.0 - 2026-09-26

### Upgrade notes
* Guests now use static IPs from `10.0.70.128/25`, inside the tunnel subnet:
  give existing guest clients a new static IP in the UI (the dashboard lists
  the ones OpenVPN cannot hand out). No new profiles are needed.
* Rules from earlier releases were appended straight to `FORWARD`/`POSTROUTING`
  and stay until the host reboots or its firewall reloads; they are harmless.

### Fixed
* Guest static IPs from the separate `10.0.71.0/24` never worked with
  `topology subnet`: OpenVPN only accepts addresses inside the `server`
  network, and clients got a gateway outside their own subnet. The subnet is
  now split: pool `10.0.70.2-127`, guests `10.0.70.128/25` (`nopool` +
  `ifconfig-pool`). The UI rejects static IPs outside the subnet, inside the
  pool or already taken.
* Guests could reach the server host itself (SSH, the web UI, ...), other VPN
  clients and private networks; they are now limited to the internet and the
  pushed DNS servers, which were blocked before because they sit in `HOME_SUB`.
* The LAN is `171.134.51.0/24` again (`HOME_SUB`, pushed route and DNS); 1.1.0
  changed it by mistake.
* The UI believed `X-Forwarded-For` from any client, so the login rate limit
  could be bypassed and logged IPs forged. Only `OVPN_UI_TRUSTED_PROXIES`
  (default `127.0.0.1`) is trusted now.
* `openvpn.log` only rotated when OpenVPN restarted; it now rotates while it
  runs, and the Docker logs of both containers are capped.
* An expired client can be renewed from its page; creating it again explains
  that instead of failing with "already exists".

### Changed
* The UI reads the client list from the status file (`status ... 5`,
  `status-version 3`) instead of polling `status 3`, which OpenVPN logged every
  5 s (~17 000 lines a day). Rates use the file's own timestamp.
* Firewall rules live in the chains `OVPN-NAT`, `OVPN-INPUT`, `OVPN-FORWARD`
  (via `DOCKER-USER` when present) and `OVPN-ACCEPT`, rebuilt on every start.
* `tun-mtu 1400` / `mssfix 1300` removed: the OpenVPN 2.7 defaults size
  packets to the path and the server no longer disagrees with its clients.
* New settings `OVPN_UI_BIND`, `OVPN_UI_TRUSTED_PROXIES`, `GUEST_BLOCK`.
* Removed `docker-compose-no-ui.yml` and `build-image.sh` (use
  `docker compose build`).

## 1.1.0 - 2026-09-12

### Changed
* **The protocol of client profiles is no longer configured separately.** It
  follows `proto` in `server.conf`, because a port forward can remap a port but
  can never turn UDP into TCP, so there was nothing to gain from setting it in
  two places and a connection to lose from setting it in one. `OVPN_PUBLIC_PROTO`
  is gone, the Settings page shows the protocol rather than offering a choice,
  and saving `server.conf` with a different `proto` rewrites every profile.
* `OVPN_PUBLIC_PORT` defaults to the port from `server.conf` instead of 1195.
  Set it only when a router or relay forwards a different public port, which is
  the one case where the two may legitimately differ.
* The dashboard warns when the profile's port or protocol disagrees with the
  listening one, and the Server page shows both addresses side by side.
* `server.conf` listens on 1197/udp, which is the forwarded port here, with
  `explicit-exit-notify` enabled and the TCP-only `tcp-nodelay` commented out.

### Fixed
* The guest-isolation rules guarded a network that does not exist here:
  `HOME_SUB` still named `192.168.88.0/24` and `server.conf` pushed a route for
  `171.134.51.0/24`, one digit away from the server's own LAN. Both now name
  `170.134.51.0/24`.

## 1.0.2 - 2026-09-12

### Fixed
* The sign-in screen sat against the left edge of the window instead of being
  centred: the login view is the only child of the flex app shell, so it
  shrank to the width of its card. It now fills the shell, and the card fits
  viewports narrower than 400 px instead of overflowing them.

### Changed
* Both containers now run with `network_mode: host`. OpenVPN binds the `port`
  from `server.conf` directly on the host and sees the real client addresses;
  the web UI is served on host port 8080 and reaches the management interface
  on the host's `127.0.0.1:2080`. Nothing is published any more, so a changed
  `port` no longer has to be mirrored in a port mapping - a mismatch there
  silently swallowed every connection attempt before OpenVPN ever saw it.
* `sysctls: {net.ipv4.ip_forward: 1}` removed: the kernel rejects per-container
  network sysctls in host network mode ("sysctl ... not allowed in host network
  namespace"). IPv4 forwarding now has to be enabled on the host, which the
  Docker daemon normally does; the entrypoint says exactly that when it is off.
* The entrypoint documents that its iptables rules - MASQUERADE, the guest
  `DROP`s and the `FORWARD` policy under `OVPN_STRICT_FORWARD=1` - apply to the
  host firewall in this mode. `OVPN_STRICT_FORWARD=0` leaves the policy alone.
* `docker-compose-no-ui.yml` switched the same way.

## 1.0.1 - 2026-09-12

### Fixed
* Traffic statistics were counted twice for clients that were already
  connected when the UI (re)started: the collector now reopens the existing
  session row and only adds the bytes transferred since it was last seen.
* Deleting an *expired* client removed its profile but left the certificate
  in `pki/issued`, so the client stayed in the list forever. Delete is now
  only offered for revoked clients (revoke the expired certificate first).
* The "All" range built its time series from 1970, sending tens of thousands
  of empty points to the browser; it now starts at the first recorded traffic.
* The live status stream was not reopened after a session expiry and a new
  login, so the dashboard stopped updating until the page was reloaded.
* The Server page rebuilt the configuration editor, log viewer and audit log
  whenever the management connection changed state, discarding unsaved edits
  and accumulating refresh timers.
* Sign-out is completed even when the logout request fails; a non-numeric
  `OVPN_PUBLIC_PORT` no longer crashes the UI at startup.
* `mkovpn.sh`, `oath-sec-gen.sh` and `oath-sec-rm.sh` used the client name as
  an unescaped regular expression, so a name containing a dot could match
  another client's 2FA secret.
* Chart axes no longer repeat the same label on all-zero data.

### Internal
* Traffic queries are fully parameterised; unused helper removed.
* New tests: API end-to-end against a throwaway openssl PKI, collector
  restart behaviour (`cd ui && python -m pytest tests`).

## 1.0.0 - 2026-09-05

### Server image
* OpenVPN 2.7.7 and easy-rsa 3.2.6 compiled from the upstream release tarballs
  (signatures verified, SHA-256 pinned in the Dockerfile) on Alpine 3.24.1;
  DCO support compiled in.
* Runs unprivileged: `cap_add: [NET_ADMIN]`, `/dev/net/tun` device and the
  `net.ipv4.ip_forward` sysctl replace `privileged: true`.
* Entrypoint rewritten: PKI init without DH generation (`dh none`), EC
  certificates, generated management password, CRL auto-renewal, idempotent
  iptables rules (`-C` before `-A`), egress interface auto-detection, strict
  forwarding policy, log rotation, and a supervisor loop that restarts OpenVPN
  when the UI asks for it (no Docker socket needed).
* Health check based on the process and the status file.

### server.conf (from the user's configuration)
* `dh none`, `tls-ciphersuites`/`tls-cipher` pinned, `tls-cert-profile
  preferred`, CHACHA20-POLY1305 added to `data-ciphers`, `persist-key`
  removed (deprecated), `ifconfig-pool-persist` removed (ignored with
  `duplicate-cn`), `log-append` instead of `log`, status interval 10 s,
  `push "block-outside-dns"`, password-protected management interface,
  2FA block ready to enable.

### Client profiles
* `config/client.conf` fixed for TCP servers and non-Linux clients:
  `explicit-exit-notify` (UDP only), `user/group nobody` (Linux only),
  `key-direction` and `<tls-auth>` (server uses `tls-crypt`), deprecated
  `cipher`/`tls-client`/`tls-cipher` removed; `data-ciphers` and
  `verify-x509-name <server CN>` added.

### Scripts (`bin/`)
* All scripts take paths from `OPENVPN_DIR`/`EASYRSA_DIR` instead of parsing
  `../openvpn-ui/conf/app.conf`; certificates get `--req-cn=<name>`
  explicitly (easy-rsa 3.2 otherwise applies the `EASYRSA_REQ_CN` from vars
  to every certificate).
* `genclient.sh` no longer appends `/name=/LocalIP=/2FAName=` to
  `pki/index.txt`; static IPs go to `staticclients/`, 2FA to
  `clients/oath.secrets`.
* `revoke.sh` also revokes a pending renewed certificate (easy-rsa leaves it
  valid otherwise) and regenerates a world-readable CRL.
* `rmcert.sh` no longer deletes lines from `pki/index.txt` (that made revoked
  certificates valid again) and refuses to remove a valid certificate.
* New `renew.sh` (easy-rsa `renew` + profile) and `mkovpn.sh`.
* `oath.sh` (2FA verify) fixed: an unknown user or empty secret no longer
  yields a computable one-time code (fail closed), the username must match
  the certificate CN, TOTP is verified with `oathtool -w 1`, codes cannot be
  replayed, malformed input is rejected and the log file is writable by the
  unprivileged OpenVPN user.
* `oath-sec-gen.sh` replaces existing entries instead of appending
  duplicates; new `oath-sec-rm.sh`.

### Web UI (new, `ui/`)
* Replaces d3vilh/openvpn-ui. FastAPI + SQLite, no external JS.
* Live status via the management interface (5 s polling, SSE to the browser),
  per-client and global traffic statistics with minute/hour/day roll-ups,
  session history, audit log.
* Client lifecycle: create (validity, static IP, passphrase, note, 2FA),
  download, renew, revoke (with reason), revoke previous, delete, disconnect.
* TOTP enrolment with QR code, 2FA enforcement switch.
* Config editors with backup, restart, log viewer, PKI status and CRL
  regeneration, public-address setting that rewrites `client.conf`.
* Security: scrypt password hashes, HttpOnly/SameSite=Strict cookies, CSRF
  header and Origin checks, login back-off, CSP and other security headers,
  container with `cap_drop: ALL`, read-only root filesystem, no Docker socket.

### Removed
* `openssl-easyrsa.cnf` (easy-rsa 3.2 ships its own), `config/old-server.conf`,
  `checkpsw.sh` placeholder, the `openvpn-ui` dependency on `docker.sock`.
