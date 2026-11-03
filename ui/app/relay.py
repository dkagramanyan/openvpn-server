"""Apple Network Relay profiles and credentials, scoped to current VPN identities."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import plistlib
import re
import secrets
import shlex
import time
import uuid
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from . import pki
from .pki import PkiError
from .settings import settings
from .relay_services import sign_profile


class RelaySettings(BaseModel):
    enabled: bool = False
    url: str = Field(default="", max_length=2048)
    route_all: bool = True  # Accepted for old API clients; roles now always route all domains.
    match_domains: list[str] = Field(default_factory=lambda: ["home.arpa"], max_length=100)
    allowed_cidrs: list[str] = Field(default_factory=lambda: [settings.home_sub] if settings.home_sub else [], max_length=100)


def get_settings(db) -> dict:
    config = RelaySettings(**json.loads(db.get_setting("apple_relay", "{}"))).model_dump()
    config["route_all"] = True  # Relay access now follows the OpenVPN role for every profile.
    return {**config, "transport": settings.relay_transport}


def save_settings(db, body: RelaySettings) -> dict:
    config = body.model_dump()
    config["route_all"] = True
    url = body.url.strip().rstrip("/")
    try:
        parsed = urlsplit(url)
        port = parsed.port
        if url and (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                    or parsed.password is not None or parsed.query or parsed.fragment
                    or parsed.path or port == 0 or re.search(r"[\s{}\\]", url)):
            raise ValueError()
    except ValueError:
        raise PkiError("Relay URL must be an HTTPS origin, e.g. https://relay.example.com:8443")
    config["url"] = url
    domains = []
    for domain in body.match_domains:
        domain = domain.strip().lower().rstrip(".")
        if len(domain) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
                                        for label in domain.split(".")):
            raise PkiError("Enter LAN domain names without wildcards or URLs")
        domains.append(domain)
    config["match_domains"] = list(dict.fromkeys(domains))
    try:
        config["allowed_cidrs"] = list(dict.fromkeys(str(ipaddress.ip_network(c.strip(), strict=True))
                                                    for c in body.allowed_cidrs))
    except ValueError:
        raise PkiError("Allowed networks must be valid CIDRs, e.g. 192.168.1.0/24")
    if body.enabled and (not url or not config["allowed_cidrs"]):
        raise PkiError("Enabling the relay requires an HTTPS URL and LAN networks to block for guests")
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


def guest_blocks(config: dict) -> list[str]:
    """Mirror LAN/VPN exclusions, including LANs using public address space."""
    network = settings.read_network()
    networks = [settings.guest_sub, *config["allowed_cidrs"]]
    if network:
        networks += network["lan_cidrs"] + network["blocked_cidrs"]
    else:
        networks += ([settings.home_sub] if settings.home_sub else []) + settings.guest_block.split()
    # Read errors or malformed relevant directives fail closed in authorize().
    if settings.server_conf.stat().st_nlink == 0:
        raise OSError("Bound server configuration was replaced; recreate relay-policy")
    for line in settings.server_conf.read_text().splitlines():
        words = shlex.split(line, comments=True)
        if not words:
            continue
        if words[0] == "push" and len(words) > 1:
            words = shlex.split(words[1])
        if words and words[0] in ("server", "route", "route-ipv6", "server-ipv6"):
            network = words[1]
            if words[0] in ("server", "route") and len(words) > 2:
                network += "/" + words[2]
            subnet = ipaddress.ip_network(network, strict=False)
            if subnet.prefixlen:  # a pushed default route is not a LAN
                networks.append(str(subnet))
    return sorted({str(ipaddress.ip_network(n, strict=False)) for n in networks})


def revoke(db, name: str) -> None:
    db.execute("DELETE FROM settings WHERE key = ?", ("relay_client:" + name,))


def profile(db, name: str) -> bytes:
    config = get_settings(db)
    cert = eligible(name)
    if not config["enabled"]:
        raise PkiError("Configure and enable Apple Network Relay in Settings first")
    if not cert:
        raise PkiError("Relay profiles require a valid client certificate")
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
    url_key = "HTTP2RelayURL" if config["transport"] == "http2" else "HTTP3RelayURL"
    relay.update({"Relays": [{url_key: config["url"] + "/.well-known/masque/udp/{target_host}/{target_port}/",
                              "AdditionalHTTPHeaderFields": {"Authorization": "Bearer " + token}}],
                  "MatchDomains": []})
    result = payload("Configuration", "", title)
    result.update({"PayloadContent": [relay], "PayloadDescription":
                   ("Internet-only guest access. " if guest else "Internet and LAN access through your server. ")
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
        blocked = guest_blocks(config) if guest else []
    except (OSError, ValueError, IndexError):
        if strict_state: raise
        return None
    # Full-access users may reach internet and LAN destinations. Keep the
    # configured LAN list separate so guest exclusions never become 0.0.0.0/0.
    allowed = ["0.0.0.0/0"] if guest else ["0.0.0.0/0", "::/0"]
    network = settings.read_network()
    portal = network.get("portal", {})
    return {"client": name, "allowed_cidrs": allowed,
            "blocked_cidrs": blocked, "guest": guest, "url": config["url"],
            "portal": portal if guest and portal.get("enabled") else None}
