# Changelog

## 1.0.2 - 2026-09-12

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
