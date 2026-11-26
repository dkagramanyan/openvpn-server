"""Apple Network Relay profiles and credentials, scoped to current VPN identities."""
from __future__ import annotations

import hashlib
import hmac
import json
import plistlib
import re
import secrets
import time
import uuid
from functools import lru_cache
from pathlib import Path
import ssl
from urllib.error import URLError
from urllib.parse import urlsplit
from urllib.request import HTTPSHandler, ProxyHandler, build_opener

from pydantic import BaseModel, Field

from . import network, pki, relay_devices
from .pki import PkiError
from .settings import settings
from .relay_services import sign_profile


class RelaySettings(BaseModel):
    enabled: bool = False
    url: str = Field(default="", max_length=2048)
    # Kept so that settings saved by 2.3 still load; since 2.4.1 every profile carries HTTP/3
    # whenever the relay serves it (APPLE_RELAY_TRANSPORT), and this value is ignored.
    http3: bool = False
    # 2.10: each new profile works on one device only (its key never leaves the phone).
    # Installed profiles are unaffected.
    devices: bool = False
    # 2.11: configs per client by default, device-bound relay profiles and Xray keys together
    # (configs.py; a client can have its own number).
    device_limit: int = Field(default=2, ge=1, le=100)


def get_settings(db) -> dict:
    config = RelaySettings(**json.loads(db.get_setting("apple_relay", "{}"))).model_dump()
    return {**config, "http3": "http3" in settings.relay_transport, "transport": settings.relay_transport}


def validate_url(url: str) -> str:
    """The relay's public HTTPS origin, e.g. https://relay.example.com:8443."""
    url = url.strip().rstrip("/")
    try:
        parsed = urlsplit(url)
        port = parsed.port
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None or parsed.password is not None
                or parsed.query or parsed.fragment or parsed.path or port == 0 or re.search(r"[\s{}\\]", url)):
            raise ValueError
    except ValueError:
        raise PkiError("Relay URL must be an HTTPS origin, e.g. https://relay.example.com:8443") from None
    return url


def validate_settings(body: RelaySettings) -> dict:
    config = body.model_dump()
    config["url"] = validate_url(body.url) if body.url.strip() else ""
    if body.enabled and not config["url"]:
        raise PkiError("Enabling Apple relay profiles requires the relay's public HTTPS URL")
    return config


def save_settings(db, body: RelaySettings) -> dict:
    # Fields a form does not send keep their saved values (the network form sends only
    # enabled and url).
    saved = RelaySettings(**json.loads(db.get_setting("apple_relay", "{}"))).model_dump()
    config = validate_settings(RelaySettings(**{**saved, **body.model_dump(exclude_unset=True)}))
    db.set_setting("apple_relay", json.dumps(config))
    return {**config, "transport": settings.relay_transport}


@lru_cache(maxsize=8)
def _index(path: str, signature: tuple) -> dict:
    return pki.parse_index(Path(path).read_text())


def eligible(name: str) -> dict | None:
    pki.validate_name(name)
    cert = pki.cert_info(settings.pki_dir / "issued" / f"{name}.crt")
    if not cert or cert.get("cn") != name:
        return None
    try:
        path = settings.pki_dir / "index.txt"
        stat = path.stat()
        entry = _index(str(path), (stat.st_ino, stat.st_mtime_ns, stat.st_ctime_ns, stat.st_size)).get(cert["serial"], {})
    except OSError:
        return None
    now = time.time()
    if (entry.get("status") != "V" or not cert.get("not_after") or cert["not_after"] <= now
            or (cert.get("not_before") or 0) > now):
        return None
    return cert


def is_guest(name: str) -> bool:
    # A single marker lookup avoids scanning all clients on every request.
    return (settings.guests_dir / name).is_file()


def revoke(db, name: str) -> None:
    """Every relay profile of a client stops working: the shared credential and all devices."""
    revoke_shared(db, name)
    relay_devices.revoke(db, name)


def revoke_shared(db, name: str) -> None:
    """Profiles without device binding (one credential in the file) stop working."""
    db.execute("DELETE FROM settings WHERE key = ?", ("relay_client:" + name,))


def has_shared(db, name: str) -> bool:
    return db.get_setting("relay_client:" + name) is not None


def credential_id(db, name):
    raw = db.get_setting("relay_client:" + name)
    return hashlib.sha256(json.loads(raw)["secret"].encode()).hexdigest() if raw else ""


def credential_ids(db, name) -> list[str]:
    """The relay credentials of a client's current profiles: the shared one and each device's."""
    shared = credential_id(db, name)
    return ([shared] if shared else []) + relay_devices.credential_ids(db, name)


def acme_base(db) -> str:
    """The public origin the phones enrol at: where one-time links open (/p/ and /acme/ are
    the website's public paths)."""
    if settings.profile_base_url:
        return settings.profile_base_url.rstrip("/")
    host = network.get_settings(db)["gateway"]["openvpn_host"]
    return "https://" + host if host else ""


def profile(db, name: str) -> bytes:
    config = get_settings(db)
    cert = eligible(name)
    if not config["enabled"]:
        raise PkiError("Configure and enable Apple Network Relay in Settings first")
    if not cert:
        raise PkiError("Relay profiles require a valid client certificate")
    if config["devices"]:
        return sign_profile(bound_profile(db, name, config), urlsplit(config["url"]).hostname, db=db)
    guest = is_guest(name)
    # Unexpected certificate replacement cannot inherit an earlier credential.
    # An explicit UI renewal updates this binding without changing the secret.
    with db.tx() as conn:
        instance_key = "relay_instance"
        instance = conn.execute("SELECT value FROM settings WHERE key = ?", (instance_key,)).fetchone()
        instance_id = instance["value"] if instance else str(uuid.uuid4())
        if not instance:
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?)", (instance_key, instance_id))
        key = "relay_client:" + name
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        grant = json.loads(row["value"]) if row else None
        if not grant or grant["serial"] != cert["serial"]:
            grant = {"serial": cert["serial"], "secret": secrets.token_urlsafe(32)}
            conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         (key, json.dumps(grant)))
    token = name + ":" + grant["secret"]
    # Stable identifiers replace a previous installation of the same profile.
    identity = hashlib.sha256((instance_id + "/" + name).encode()).hexdigest()
    identifier = "org.openvpn.apple-relay." + identity

    def payload(kind, suffix, title):
        return {"PayloadType": kind, "PayloadVersion": 1, "PayloadIdentifier": identifier + suffix,
                "PayloadUUID": str(uuid.uuid5(uuid.NAMESPACE_URL, identifier + suffix)).upper(),
                "PayloadDisplayName": title}

    title = ("Guest Relay · " if guest else "Full Access Relay · ") + name
    relay = payload("com.apple.relay.managed", ".relay", title)
    template = config["url"] + "/.well-known/masque/udp/{target_host}/{target_port}/"
    # HTTP/3 (UDP, straight to this server) whenever the relay serves it, with HTTP/2 (through the
    # gateway) as the fallback; one origin, one credential, so installed profiles keep working.
    if config["transport"] == "http3":
        urls = {"HTTP3RelayURL": template}
    elif "http3" in config["transport"]:
        urls = {"HTTP3RelayURL": template, "HTTP2RelayURL": template}
    else:
        urls = {"HTTP2RelayURL": template}
    relay.update({"Relays": [{**urls, "AdditionalHTTPHeaderFields": {"Authorization": "Bearer " + token}}],
                  "MatchDomains": []})   # everything goes through the relay
    result = payload("Configuration", "", title)
    result.update({"PayloadContent": [relay], "PayloadDescription":
                   ("Internet access through your server, without your local network. " if guest
                    else "Internet and LAN access through your server. ")
                   + "This profile contains a personal access credential."})
    return sign_profile(plistlib.dumps(result, sort_keys=False), urlsplit(config["url"]).hostname, db=db)


def device_self_test(db, config: dict) -> None:
    """Before device binding is switched on: the gateway signs a bound profile and routes /acme/
    here. Raises PkiError with what to fix."""
    base = acme_base(db)
    if not base:
        raise PkiError("Device binding needs the website hostname (Settings → Network → Gateway)")
    sample = bound_profile(db, "selftest", {**config, "transport": settings.relay_transport},
                           device="selftest-device", code="selftest")
    try:
        sign_profile(sample, urlsplit(config["url"]).hostname, db=db)
    except PkiError as exc:
        raise PkiError("The profile signer does not accept device-bound profiles yet (update the gateway's "
                       "Traefik to 1.4.0 or later): " + str(exc)) from exc
    try:
        opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context()))
        with opener.open(base + "/acme/directory", timeout=6) as response:
            directory = json.loads(response.read(65536))
        if directory.get("newOrder") != base + "/acme/new-order":
            raise ValueError
    except (OSError, ValueError, URLError):
        raise PkiError(f"Phones cannot reach {base}/acme/directory: the gateway must route /acme/ to this "
                       "server from anywhere (Traefik 1.4.0 or later)") from None


def instance_id(db) -> str:
    with db.tx() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = 'relay_instance'").fetchone()
        if row:
            return row["value"]
        value = str(uuid.uuid4())
        conn.execute("INSERT INTO settings (key, value) VALUES ('relay_instance', ?) ON CONFLICT (key) DO NOTHING", (value,))
    return db.get_setting("relay_instance")


def relay_urls(config) -> dict:
    template = config["url"] + "/.well-known/masque/udp/{target_host}/{target_port}/"
    if config["transport"] == "http3":
        return {"HTTP3RelayURL": template}
    if "http3" in config["transport"]:
        return {"HTTP3RelayURL": template, "HTTP2RelayURL": template}
    return {"HTTP2RelayURL": template}


def bound_profile(db, name: str, config: dict, *, device: str | None = None, code: str | None = None) -> bytes:
    """A profile for one device: the phone makes its own key (Secure Enclave) and fetches a
    certificate with the one-time code; the relay accepts "device:<id>" only with it."""
    base = acme_base(db)
    if not base:
        raise PkiError("Device-bound relay profiles need the website hostname (Settings → Network)")
    if device is None:
        device, code = relay_devices.create(db, name)
    guest = is_guest(name)
    instance = instance_id(db)
    # The same identifier per client (as unbound profiles), so a new profile on the same phone
    # replaces the old one: a new profile on the same phone replaces the old one.
    identifier = "org.openvpn.apple-relay." + hashlib.sha256((instance + "/" + name).encode()).hexdigest()
    title = ("Guest Relay · " if guest else "Full Access Relay · ") + name

    def payload(kind, suffix, uuid_value):
        return {"PayloadType": kind, "PayloadVersion": 1, "PayloadIdentifier": identifier + suffix,
                "PayloadUUID": uuid_value, "PayloadDisplayName": title}

    acme = payload("com.apple.security.acme", ".acme", str(uuid.uuid5(uuid.NAMESPACE_URL, identifier + "/device/" + device)).upper())
    acme.update({"DirectoryURL": base + "/acme/directory", "ClientIdentifier": code, "KeyType": "ECSECPrimeRandom",
                 "KeySize": 256, "HardwareBound": True, "Attest": False,
                 "Subject": [[["CN", "relay-device-" + device]]], "UsageFlags": 1,
                 "ExtendedKeyUsage": ["1.3.6.1.5.5.7.3.2"]})
    relay = payload("com.apple.relay.managed", ".relay", str(uuid.uuid5(uuid.NAMESPACE_URL, identifier + ".relay")).upper())
    relay.update({"Relays": [{**relay_urls(config), "PayloadCertificateUUID": acme["PayloadUUID"],
                              "AdditionalHTTPHeaderFields": {"Authorization": "Bearer device:" + device}}],
                  "MatchDomains": []})
    result = payload("Configuration", "", str(uuid.uuid5(uuid.NAMESPACE_URL, identifier)).upper())
    result.update({"PayloadContent": [acme, relay], "PayloadDescription":
                   ("Internet access through your server, without your local network. " if guest
                    else "Internet and LAN access through your server. ")
                   + "This profile works on one device only."})
    return plistlib.dumps(result, sort_keys=False)


def renewed(db, name, previous_serial):
    """An explicit UI renewal preserves this client's installed relay credential."""
    cert = eligible(name)
    if not cert:
        return
    with db.tx() as conn:
        key = "relay_client:" + name
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
        if row:
            grant = json.loads(row["value"])
            if grant["serial"] == previous_serial:
                grant["serial"] = cert["serial"]
                conn.execute("UPDATE settings SET value = ? WHERE key = ?", (json.dumps(grant), key))


def guest_routes(db) -> list[str]:
    """The networks the VPN pushes: closed to guests, as in the OpenVPN firewall. From the saved
    network settings, or, while those were never saved, what the UI read from server.conf."""
    network_settings = settings.read_network()
    if "routes" in network_settings:
        return network_settings["routes"]
    return json.loads(db.get_setting("pushed_routes") or "[]")


def device_grant(db, device_id: str, fingerprint: str):
    """(client, credential id) of an enrolled, unrevoked device whose certificate the relay saw
    in this connection's TLS handshake, else None."""
    if not re.fullmatch(r"[0-9a-f]{64}", fingerprint or "") or not relay_devices.ID_RE.match(device_id):
        return None
    getter = getattr(db, "get_device", None)
    row = getter(device_id) if getter else db.one(
        "SELECT id, client_name, fingerprint, revoked_at FROM relay_policy_devices WHERE id = ?", (device_id,))
    if not row or row["revoked_at"] or not row["fingerprint"] or not hmac.compare_digest(row["fingerprint"], fingerprint):
        return None
    return row["client_name"], "device:" + device_id


def authorize(db, authorization: str, *, device: str = "", strict_state: bool = False) -> dict | None:
    """The policy for a relay request. device: the SHA-256 of the client certificate the relay
    saw in the TLS handshake (never a request header of the phone's)."""
    if not authorization.startswith("Bearer ") or len(authorization) > 512:
        return None
    name, sep, secret = authorization[7:].partition(":")
    if not sep:
        return None
    if name == "device" and relay_devices.ID_RE.match(secret):
        found = device_grant(db, secret, device)
        if not found:
            return None
        name, credential = found
        cert = eligible(name)
        config = get_settings(db)
        if not config["enabled"] or not cert:
            return None
    else:
        raw = db.get_setting("relay_client:" + name)
        if not raw:
            return None
        grant = json.loads(raw)
        if not hmac.compare_digest(secret.encode(), grant["secret"].encode()):
            return None
        cert = eligible(name)
        config = get_settings(db)
        if not config["enabled"] or not cert or cert["serial"] != grant["serial"]:
            return None
        credential = hashlib.sha256(grant["secret"].encode()).hexdigest()
    guest = is_guest(name)
    try:
        portal = network.guest_portal() if guest else None
        routes = guest_routes(db) if guest else []
    except (OSError, ValueError):
        if strict_state:
            raise   # the policy service answers 503: state unavailable, not "denied"
        return None
    # Full access: internet and LAN. Guests: the internet without anything local
    # (the relay also refuses private ranges and its host's own networks) and
    # the personal portal, which the relay pins to the gateway's portal listener.
    return {"client": name, "credential_id": credential,
            "guest": guest, "url": config["url"],
            # OpenVPN carries no IPv6 for anyone and the guest rules are IPv4: a guest gets none here either.
            "allowed_cidrs": ["0.0.0.0/0"] if guest else ["0.0.0.0/0", "::/0"],
            "blocked_cidrs": routes, "portal": portal}
