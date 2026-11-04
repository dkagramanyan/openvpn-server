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
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from . import network, pki
from .pki import PkiError
from .settings import settings
from .relay_services import sign_profile


class RelaySettings(BaseModel):
    enabled: bool = False
    url: str = Field(default="", max_length=2048)


def get_settings(db) -> dict:
    config = RelaySettings(**json.loads(db.get_setting("apple_relay", "{}"))).model_dump()
    return {**config, "transport": settings.relay_transport}


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
    config = validate_settings(body)
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
    db.execute("DELETE FROM settings WHERE key = ?", ("relay_client:" + name,))


def credential_id(db, name):
    raw = db.get_setting("relay_client:" + name)
    return hashlib.sha256(json.loads(raw)["secret"].encode()).hexdigest() if raw else ""


def profile(db, name: str) -> bytes:
    config = get_settings(db)
    cert = eligible(name)
    if not config["enabled"]:
        raise PkiError("Configure and enable Apple Network Relay in Settings first")
    if not cert:
        raise PkiError("Relay profiles require a valid client certificate")
    guest = is_guest(name)
    portal = network.guest_portal()
    if guest and not portal:
        raise PkiError("Guest relay profiles open only the personal portal. Set the guest portal listener "
                       "in Settings → Network first")
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

    title = ("Guest Portal Relay · " if guest else "Full Access Relay · ") + name
    relay = payload("com.apple.relay.managed", ".relay", title)
    url_key = "HTTP2RelayURL" if config["transport"] == "http2" else "HTTP3RelayURL"
    relay.update({"Relays": [{url_key: config["url"] + "/.well-known/masque/udp/{target_host}/{target_port}/",
                              "AdditionalHTTPHeaderFields": {"Authorization": "Bearer " + token}}],
                  # Guests send only the portal and their links through the relay; the rest stays
                  # on the device's own connection. Full access routes everything.
                  "MatchDomains": [portal["host"], *portal["hosts"]] if guest else []})
    result = payload("Configuration", "", title)
    result.update({"PayloadContent": [relay], "PayloadDescription":
                   ("Guest access to your personal portal page only. " if guest else "Internet and LAN access through your server. ")
                   + "This profile contains a personal access credential."})
    return sign_profile(plistlib.dumps(result, sort_keys=False), urlsplit(config["url"]).hostname, db=db)


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


def authorize(db, authorization: str, *, strict_state: bool = False) -> dict | None:
    if not authorization.startswith("Bearer ") or len(authorization) > 512:
        return None
    name, sep, secret = authorization[7:].partition(":")
    if not sep:
        return None
    raw = db.get_setting("relay_client:" + name)
    if not raw:
        return None
    grant = json.loads(raw)
    if not hmac.compare_digest(secret.encode(), grant["secret"].encode()):
        return None
    cert = eligible(name)
    config = get_settings(db)
    guest = is_guest(name)
    if not config["enabled"] or not cert or cert["serial"] != grant["serial"]:
        return None
    try:
        portal = network.guest_portal() if guest else None
    except (OSError, ValueError):
        if strict_state:
            raise   # the policy service answers 503: state unavailable, not "denied"
        return None
    # Full access: internet and LAN. Guests: nothing but the personal portal,
    # which the relay pins to the gateway's portal listener.
    return {"client": name, "credential_id": hashlib.sha256(grant["secret"].encode()).hexdigest(),
            "guest": guest, "url": config["url"], "allowed_cidrs": [] if guest else ["0.0.0.0/0", "::/0"],
            "portal": portal}
