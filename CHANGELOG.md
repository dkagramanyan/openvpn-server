# Changelog

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
