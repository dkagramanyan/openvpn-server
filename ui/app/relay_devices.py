"""Apple relay profiles bound to one device.

A bound profile carries an ACME payload (RFC 8555, Apple's com.apple.security.acme) with a
one-time code (ClientIdentifier) and a relay payload that logs in with the identity the
phone makes from it. The phone generates the key in its Secure Enclave (HardwareBound) and
fetches a certificate here; the relay sees that certificate in every TLS handshake and the
policy service accepts the profile's "device:<id>" credential only together with it.

Observed on iOS 18.7 (tests/iphone): HTTP/1.1, ES256 with kid, newOrder with one
permanent-identifier (the code), device-attest-01 answered with an empty object when
Attest is off, a POST-as-GET of the order after finalize, a P-256 CSR with key usage and
extended key usage extensions. A second phone installing a copy is refused at newOrder,
and iOS then installs nothing of the profile.

Crypto goes through the openssl command line, as everywhere else in the UI image.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import subprocess
import tempfile
import threading
import time
import uuid
from pathlib import Path

from .pki import PkiError

ENROL_SECONDS = 7 * 86400       # a downloaded profile can be installed within a week
CERT_DAYS = 3650                # long-lived: iOS does not renew a hand-installed identity; revoke in the database
CA_SETTING = "relay_device_ca"
ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,32}$")


class DeviceLimit(PkiError):
    """The client has as many bound devices as allowed."""


def now() -> int:
    return int(time.time())


def code_hash(code: str) -> str:
    return hashlib.sha256(code.encode()).hexdigest()


def openssl(*args, data: bytes | None = None) -> bytes:
    try:
        return subprocess.run(["openssl", *args], input=data, capture_output=True, check=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise PkiError("Device certificate operation failed") from exc


# -- the device CA ---------------------------------------------------------------------------

_ca_lock = threading.Lock()


def authority(db) -> dict:
    """{"key": PEM, "cert": PEM}: made on first use, kept in the settings table (not in the
    policy service's view)."""
    raw = db.get_setting(CA_SETTING)
    if raw:
        return json.loads(raw)
    with _ca_lock:
        raw = db.get_setting(CA_SETTING)
        if raw:
            return json.loads(raw)
        key = openssl("ecparam", "-name", "prime256v1", "-genkey", "-noout")
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "ca.key"
            path.write_bytes(key)
            path.chmod(0o600)
            cert = openssl("req", "-x509", "-new", "-key", str(path), "-sha256", "-days", "7300",
                           "-subj", "/CN=Apple relay devices " + uuid.uuid4().hex[:8],
                           "-addext", "basicConstraints=critical,CA:TRUE,pathlen:0",
                           "-addext", "keyUsage=critical,keyCertSign,cRLSign")
        pkcs8 = openssl("pkey", data=key)
        ca = {"key": pkcs8.decode(), "cert": cert.decode()}
        db.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING",
                   (CA_SETTING, json.dumps(ca)))
        return json.loads(db.get_setting(CA_SETTING))


# -- devices ---------------------------------------------------------------------------------

def active_count(db, client: str) -> int:
    return db.one("SELECT COUNT(*) AS n FROM relay_devices WHERE client_name = ? AND enrolled_at IS NOT NULL "
                  "AND revoked_at IS NULL", (client,))["n"]


def create(db, client: str, limit: int) -> tuple[str, str]:
    """(device id, one-time code) for a new bound profile of a client."""
    if active_count(db, client) >= limit:
        raise DeviceLimit(f"{client} already has {limit} relay devices: remove one first")
    t = now()
    device, code = secrets.token_urlsafe(12), secrets.token_urlsafe(24)
    with db.tx() as conn:
        # Profiles that were never installed in time are of no use to anyone.
        conn.execute("DELETE FROM relay_devices WHERE enrolled_at IS NULL AND expires_at < ?", (t,))
        conn.execute("INSERT INTO relay_devices (id, client_name, code_hash, created_at, expires_at) VALUES (?, ?, ?, ?, ?)",
                     (device, client, code_hash(code), t, t + ENROL_SECONDS))
    return device, code


def listing(db, client: str) -> list[dict]:
    """A client's devices, newest first, with when each was last seen on the relay."""
    rows = db.query("""SELECT d.id, d.created_at, d.expires_at, d.enrolled_at, d.revoked_at, d.serial,
                              (SELECT MAX(s.last_seen) FROM relay_sessions s
                               WHERE s.client_name = d.client_name AND s.credential_id = 'device:' || d.id) AS last_seen
                       FROM relay_devices d WHERE d.client_name = ? ORDER BY d.created_at DESC""", (client,))
    t = now()
    for row in rows:
        row["state"] = ("revoked" if row["revoked_at"] else "active" if row["enrolled_at"]
                        else "expired" if row["expires_at"] < t else "waiting")
    return rows


def revoke(db, client: str, device: str | None = None) -> int:
    """Revoke one device of a client, or all of them. Waiting profiles are deleted."""
    with db.tx() as conn:
        where, args = ("client_name = ?", [client]) if device is None else ("client_name = ? AND id = ?", [client, device])
        conn.execute(f"DELETE FROM relay_devices WHERE {where} AND enrolled_at IS NULL", args)
        return conn.execute(f"UPDATE relay_devices SET revoked_at = ? WHERE {where} AND revoked_at IS NULL",
                            [now(), *args]).rowcount


def forget(db, client: str) -> None:
    db.execute("DELETE FROM relay_devices WHERE client_name = ?", (client,))


def credential_ids(db, client: str) -> list[str]:
    return ["device:" + row["id"] for row in db.query(
        "SELECT id FROM relay_devices WHERE client_name = ? AND enrolled_at IS NOT NULL", (client,))]


# -- JWS (RFC 7515/8555) with ES256/ES384 ------------------------------------------------------

def b64d(text: str) -> bytes:
    if not isinstance(text, str) or not re.fullmatch(r"[A-Za-z0-9_-]*", text):
        raise ValueError("not base64url")
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def b64e(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


CURVES = {"P-256": ("ES256", "sha256", 32, bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200")),
          "P-384": ("ES384", "sha384", 48, bytes.fromhex("3076301006072a8648ce3d020106052b81040022036200"))}


def jwk_key(jwk: dict) -> tuple[str, str, int, bytes]:
    """(alg, digest, coordinate size, SubjectPublicKeyInfo DER) of an EC JWK."""
    if not isinstance(jwk, dict) or jwk.get("kty") != "EC" or jwk.get("crv") not in CURVES:
        raise ValueError("unsupported account key")
    alg, digest, size, prefix = CURVES[jwk["crv"]]
    x, y = b64d(jwk.get("x", "")), b64d(jwk.get("y", ""))
    if len(x) != size or len(y) != size:
        raise ValueError("bad account key")
    return alg, digest, size, prefix + b"\x04" + x + y


def thumbprint(jwk: dict) -> str:
    canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
    return b64e(hashlib.sha256(canonical.encode()).digest())


def der_int(value: bytes) -> bytes:
    value = value.lstrip(b"\x00") or b"\x00"
    if value[0] & 0x80:
        value = b"\x00" + value
    return b"\x02" + der_len(len(value)) + value


def der_len(n: int) -> bytes:
    return bytes([n]) if n < 128 else bytes([0x81, n]) if n < 256 else bytes([0x82, n >> 8, n & 255])


def verify_signature(jwk: dict, alg: str, signed: bytes, signature: bytes) -> None:
    key_alg, digest, size, spki = jwk_key(jwk)
    if alg != key_alg or len(signature) != 2 * size:
        raise ValueError("bad signature algorithm")
    body = der_int(signature[:size]) + der_int(signature[size:])
    sig = b"\x30" + der_len(len(body)) + body
    pem = b"-----BEGIN PUBLIC KEY-----\n" + base64.encodebytes(spki) + b"-----END PUBLIC KEY-----\n"
    with tempfile.TemporaryDirectory() as temp:
        (Path(temp) / "key.pem").write_bytes(pem)
        (Path(temp) / "sig").write_bytes(sig)
        try:
            subprocess.run(["openssl", "dgst", "-" + digest, "-verify", str(Path(temp) / "key.pem"),
                            "-signature", str(Path(temp) / "sig")], input=signed, capture_output=True,
                           check=True, timeout=10)
        except subprocess.CalledProcessError:
            raise ValueError("bad signature") from None
        except (OSError, subprocess.SubprocessError) as exc:
            raise PkiError("Signature check failed") from exc


# -- the ACME server -------------------------------------------------------------------------

class AcmeError(Exception):
    def __init__(self, status: int, kind: str, detail: str):
        super().__init__(detail)
        self.status, self.kind, self.detail = status, kind, detail


class Acme:
    """Stateless apart from nonces: an account's URL carries its key, orders are device rows."""
    NONCES = 20000
    NONCE_SECONDS = 600

    def __init__(self, db, base):
        self.db, self.base = db, base      # base(): the public origin, e.g. https://vpn.example.com
        self._nonces: dict[str, float] = {}
        self._lock = threading.Lock()

    def url(self, path: str) -> str:
        return self.base() + "/acme/" + path

    def nonce(self) -> str:
        value = secrets.token_urlsafe(16)
        t = time.monotonic()
        with self._lock:
            if len(self._nonces) >= self.NONCES:
                self._nonces = {k: v for k, v in self._nonces.items() if v > t}
                while len(self._nonces) >= self.NONCES:
                    self._nonces.pop(next(iter(self._nonces)))
            self._nonces[value] = t + self.NONCE_SECONDS
        return value

    def use_nonce(self, value) -> bool:
        with self._lock:
            expires = self._nonces.pop(value, None) if isinstance(value, str) else None
        return expires is not None and expires > time.monotonic()

    def directory(self) -> dict:
        return {"newNonce": self.url("new-nonce"), "newAccount": self.url("new-account"),
                "newOrder": self.url("new-order"), "revokeCert": self.url("revoke-cert"),
                "keyChange": self.url("key-change"), "meta": {"externalAccountRequired": False}}

    # A JWS-signed request: returns (payload or None for POST-as-GET, account JWK, account URL).
    def verify(self, body: bytes, path: str, *, new_account: bool = False):
        try:
            jws = json.loads(body)
            protected_raw, payload_raw, signature = (b64d(jws["protected"]), b64d(jws["payload"]),
                                                     b64d(jws["signature"]))
            protected = json.loads(protected_raw)
        except (ValueError, KeyError, TypeError):
            raise AcmeError(400, "malformed", "Request is not a flattened JWS") from None
        if not isinstance(protected, dict):
            raise AcmeError(400, "malformed", "Bad protected header")
        if not self.use_nonce(protected.get("nonce")):
            raise AcmeError(400, "badNonce", "Unknown or expired nonce")
        if protected.get("url") != self.url(path):
            raise AcmeError(401, "unauthorized", "The url in the request does not match")
        jwk, kid = protected.get("jwk"), protected.get("kid")
        if new_account:
            if not isinstance(jwk, dict) or kid is not None:
                raise AcmeError(400, "malformed", "newAccount is signed with its key")
        else:
            if jwk is not None or not isinstance(kid, str) or not kid.startswith(self.url("acct/")):
                raise AcmeError(400, "malformed", "Requests are signed with the account URL")
            try:
                jwk = json.loads(b64d(kid[len(self.url("acct/")):]))
            except ValueError:
                raise AcmeError(400, "accountDoesNotExist", "Unknown account") from None
        try:
            verify_signature(jwk, protected.get("alg"), jws["protected"].encode() + b"." + jws["payload"].encode(), signature)
        except ValueError as exc:
            kind = "badSignatureAlgorithm" if "algorithm" in str(exc) or "account key" in str(exc) else "malformed"
            raise AcmeError(400, kind, "Signature check failed") from None
        if payload_raw == b"":
            payload = None
        else:
            try:
                payload = json.loads(payload_raw)
            except ValueError:
                raise AcmeError(400, "malformed", "Payload is not JSON") from None
        return payload, jwk, self.account_url(jwk)

    def account_url(self, jwk: dict) -> str:
        canonical = json.dumps({k: jwk[k] for k in ("crv", "kty", "x", "y")}, separators=(",", ":"), sort_keys=True)
        return self.url("acct/" + b64e(canonical.encode()))

    # -- resources ---------------------------------------------------------------------------
    def device(self, device_id: str) -> dict:
        row = self.db.one("SELECT * FROM relay_devices WHERE id = ?", (device_id,)) if ID_RE.match(device_id or "") else None
        if row is None:
            raise AcmeError(404, "malformed", "No such order")
        return row

    def owned(self, row: dict, jwk: dict) -> None:
        """After enrolment, an order belongs to the account that finished it."""
        if row["enrolled_at"] and row["account"] != thumbprint(jwk):
            raise AcmeError(403, "unauthorized", "This profile is already installed on another device")

    def status(self, row: dict) -> str:
        if row["revoked_at"]:
            return "invalid"
        if row["enrolled_at"]:
            return "valid"
        if row["expires_at"] < now():
            return "invalid"
        return "ready" if row["validated_at"] else "pending"

    def order(self, row: dict) -> dict:
        out = {"status": self.status(row), "expires": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(row["expires_at"])),
               "identifiers": [{"type": "permanent-identifier", "value": "(one-time code)"}],
               "authorizations": [self.url("authz/" + row["id"])], "finalize": self.url("order/" + row["id"] + "/finalize")}
        if row["enrolled_at"]:
            out["certificate"] = self.url("cert/" + row["id"])
        return out

    def challenge_token(self, row: dict) -> str:
        return b64e(hmac.new(row["code_hash"].encode(), b"device-attest-01", hashlib.sha256).digest())

    def authz(self, row: dict) -> dict:
        state = "valid" if row["validated_at"] or row["enrolled_at"] else "invalid" if self.status(row) == "invalid" else "pending"
        return {"status": state, "expires": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(row["expires_at"])),
                "identifier": {"type": "permanent-identifier", "value": "(one-time code)"},
                "challenges": [{"type": "device-attest-01", "url": self.url("chall/" + row["id"]),
                                "status": state, "token": self.challenge_token(row)}]}

    def new_order(self, payload, jwk, limit: int) -> dict:
        identifiers = payload.get("identifiers") if isinstance(payload, dict) else None
        codes = [i.get("value") for i in identifiers or [] if isinstance(i, dict) and isinstance(i.get("value"), str)]
        if len(codes) != 1:
            raise AcmeError(400, "rejectedIdentifier", "Expected the profile's one-time code")
        row = self.db.one("SELECT * FROM relay_devices WHERE code_hash = ?", (code_hash(codes[0]),))
        if row is None or row["revoked_at"]:
            raise AcmeError(403, "rejectedIdentifier", "This profile is not valid: download a new one")
        if row["enrolled_at"]:
            # Only the phone that installed it may ask again (a dropped connection, say).
            if row["account"] != thumbprint(jwk):
                raise AcmeError(403, "rejectedIdentifier", "This profile is already installed on another device")
        elif row["expires_at"] < now():
            raise AcmeError(403, "rejectedIdentifier", "This profile has expired: download a new one")
        elif active_count(self.db, row["client_name"]) >= limit:
            raise AcmeError(403, "rejectedIdentifier", "Too many devices: ask the administrator to remove one")
        return row

    def answer(self, row: dict, jwk: dict) -> dict:
        """device-attest-01: an empty answer (Attest off) is all the phone sends; the one-time
        code was the proof. An attestation, when sent, is not relied on."""
        self.owned(row, jwk)
        if self.status(row) == "pending":
            self.db.execute("UPDATE relay_devices SET validated_at = ? WHERE id = ? AND validated_at IS NULL",
                            (now(), row["id"]))
            row = self.device(row["id"])
        if self.status(row) == "invalid":
            raise AcmeError(403, "unauthorized", "This profile is no longer valid")
        token = self.challenge_token(row)
        return {"type": "device-attest-01", "url": self.url("chall/" + row["id"]), "status": "valid", "token": token}

    def finalize(self, row: dict, payload, jwk: dict, limit: int) -> dict:
        self.owned(row, jwk)
        try:
            csr = b64d(payload["csr"])
        except (TypeError, KeyError, ValueError):
            raise AcmeError(400, "badCSR", "No CSR") from None
        if len(csr) > 8192:
            raise AcmeError(400, "badCSR", "CSR too large")
        public_key = csr_public_key(csr)
        if row["enrolled_at"]:
            if row["public_key"] != public_key:
                raise AcmeError(403, "unauthorized", "This profile is already installed")
            return row          # the same phone again: the same certificate
        state = self.status(row)
        if state != "ready":
            raise AcmeError(403, "orderNotReady", "The order is not ready")
        cert_pem, serial, fingerprint = issue(self.db, csr, row["id"])
        with self.db.tx() as conn:
            # Spend the code once, and only while the client is below its limit.
            count = conn.execute("SELECT COUNT(*) AS n FROM relay_devices WHERE client_name = ? AND enrolled_at IS NOT NULL "
                                 "AND revoked_at IS NULL", (row["client_name"],)).fetchone()["n"]
            if count >= limit:
                raise AcmeError(403, "rejectedIdentifier", "Too many devices: ask the administrator to remove one")
            done = conn.execute("UPDATE relay_devices SET enrolled_at = ?, account = ?, public_key = ?, cert_pem = ?, "
                                "serial = ?, fingerprint = ? WHERE id = ? AND enrolled_at IS NULL AND revoked_at IS NULL",
                                (now(), thumbprint(jwk), public_key, cert_pem, serial, fingerprint, row["id"])).rowcount
            if done:
                self.db.add_event("relay_device_enrolled", row["client_name"], None, row["id"], conn=conn)
        if not done:
            raise AcmeError(403, "unauthorized", "This profile is already installed")
        return self.device(row["id"])

    def certificate(self, row: dict, jwk: dict) -> bytes:
        self.owned(row, jwk)
        if not row["enrolled_at"] or row["revoked_at"]:
            raise AcmeError(404, "malformed", "No certificate")
        return (row["cert_pem"] + authority(self.db)["cert"]).encode()


def csr_public_key(csr: bytes) -> str:
    """The CSR's EC public key (SubjectPublicKeyInfo, base64) after checking its self-signature."""
    try:
        out = subprocess.run(["openssl", "req", "-inform", "DER", "-verify", "-noout", "-pubkey"], input=csr,
                             capture_output=True, check=True, timeout=10)
    except subprocess.CalledProcessError:
        raise AcmeError(400, "badCSR", "The CSR does not verify") from None
    except (OSError, subprocess.SubprocessError):
        raise AcmeError(500, "serverInternal", "CSR check failed") from None
    pem = out.stdout.decode()
    match = re.search(r"-----BEGIN PUBLIC KEY-----(.*?)-----END PUBLIC KEY-----", pem, re.S)
    if not match:
        raise AcmeError(400, "badCSR", "No public key")
    spki = base64.b64decode("".join(match.group(1).split()))
    if not any(spki.startswith(prefix) for _, _, _, prefix in CURVES.values()):
        raise AcmeError(400, "badCSR", "The key must be EC P-256 or P-384")
    return base64.b64encode(spki).decode()


def issue(db, csr: bytes, device: str) -> tuple[str, str, str]:
    """(certificate PEM, serial hex, SHA-256 fingerprint hex) for a device's CSR. The subject is
    ours, not the CSR's; no CSR extensions are copied."""
    ca = authority(db)
    serial = secrets.randbits(127) | 1
    with tempfile.TemporaryDirectory() as temp:
        root = Path(temp)
        (root / "ca.pem").write_text(ca["cert"])
        (root / "ca.key").write_text(ca["key"])
        (root / "ca.key").chmod(0o600)
        (root / "csr.der").write_bytes(csr)
        (root / "ext.cnf").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                                      "extendedKeyUsage=clientAuth\nsubjectKeyIdentifier=hash\n"
                                      "authorityKeyIdentifier=keyid\n")
        cert = openssl("x509", "-req", "-inform", "DER", "-in", str(root / "csr.der"), "-CA", str(root / "ca.pem"),
                       "-CAkey", str(root / "ca.key"), "-set_serial", str(serial), "-days", str(CERT_DAYS),
                       "-sha256", "-subj", "/CN=relay-device-" + device, "-extfile", str(root / "ext.cnf"))
    der = base64.b64decode("".join(cert.decode().split("-----")[2].split()))
    return cert.decode(), format(serial, "x"), hashlib.sha256(der).hexdigest()
