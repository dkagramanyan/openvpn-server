"""Private, UI-managed network configuration. Never store deployment data in Git."""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
from urllib.parse import urlsplit

from pydantic import BaseModel, Field

from . import pki
from .pki import PkiError
from .settings import settings


class Portal(BaseModel):
    enabled: bool = False
    host: str = ""
    target: str = ""
    destinations: list[str] = Field(default_factory=list, max_length=100)


class Service(BaseModel):
    name: str
    host: str
    url: str
    public: bool = False
    paths: list[str] = Field(default_factory=list, max_length=100)
    insecure_tls: bool = False


class Gateway(BaseModel):
    domain: str = ""
    openvpn_host: str = ""
    openvpn_backend: str = ""
    relay_host: str = ""
    relay_backend: str = ""
    relay_public_url: str = ""
    trusted_cidrs: list[str] = Field(default_factory=list, max_length=100)
    portal_cidrs: list[str] = Field(default_factory=list, max_length=100)
    services: list[Service] = Field(default_factory=list, max_length=100)
    replace_services: bool = False


class NetworkSettings(BaseModel):
    vpn_subnet: str
    pool_first: str
    pool_last: str
    guest_subnet: str
    dns_servers: list[str] = Field(default_factory=list, max_length=10)
    routes: list[str] = Field(default_factory=list, max_length=100)
    lan_cidrs: list[str] = Field(default_factory=list, max_length=100)
    blocked_cidrs: list[str] = Field(default_factory=list, max_length=100)
    proxy_cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.1/32", "::1/128"], max_length=100)
    portal: Portal = Field(default_factory=Portal)
    gateway: Gateway = Field(default_factory=Gateway)


def hostname(value):
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value):
        raise PkiError("Enter a DNS hostname without a scheme, path or port")
    return value


def cidrs(values, *, ipv4=False):
    try:
        networks = [ipaddress.ip_network(v.strip(), strict=True) for v in values]
        if any(n.prefixlen == 0 or (ipv4 and n.version != 4) for n in networks):
            raise ValueError()
        return list(dict.fromkeys(str(n) for n in networks))
    except ValueError:
        raise PkiError("Enter specific network CIDRs; /0 networks are not allowed")


def endpoint(value, *, portal=False):
    try:
        host, port = value.rsplit(":", 1)
        port = int(port)
        if not 1 <= port <= 65535 or re.search(r"[\s`{}\\/@?#]", host):
            raise ValueError()
        if portal:
            ip = ipaddress.IPv4Address(host)
            if int(ip) < 1 << 24 or int(ip) >= 224 << 24 or ip.is_loopback or ip.is_link_local or port < 1024:
                raise ValueError()
        elif not host:
            raise ValueError()
        return f"{host}:{port}"
    except ValueError:
        raise PkiError("Enter an address:port; the portal target must be an IPv4 dedicated listener on port 1024 or higher")


def backend_url(value):
    try:
        url = urlsplit(value)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or re.search(r"[\s`{}\\]", value):
            raise ValueError()
        _ = url.port
    except ValueError:
        raise PkiError("Enter an HTTP(S) backend URL without credentials")
    return value


def shared_settings(data, db=None):
    """Reuse existing public URLs; explicit gateway settings take precedence."""
    from . import relay, relay_services

    gateway, portal = data["gateway"], data["portal"]
    relay_config = relay.get_settings(db) if db is not None else {}
    if relay_config.get("url"):
        gateway["relay_public_url"] = relay_config["url"]
    signer = relay_services.signing_config(db)

    def dns_host(url):
        try:
            parsed = urlsplit(url)
            return hostname(parsed.hostname) if parsed.hostname else ""
        except (ValueError, TypeError, AttributeError, PkiError):
            return ""

    website = (gateway["openvpn_host"] or portal["host"] or dns_host(settings.profile_base_url)
               or dns_host(signer["url"]))
    relay_host = gateway["relay_host"] or dns_host(relay_config.get("url", ""))
    if not gateway["domain"]:
        # Only remove familiar service prefixes, never guess a registrable domain.
        if relay_host:
            gateway["domain"] = relay_host.removeprefix("relay.")
        elif website.startswith(("openvpn.", "vpn.")):
            gateway["domain"] = website.split(".", 1)[1]
        else:
            try:
                candidate = hostname(pki.get_remote()["host"])
                try:
                    ipaddress.ip_address(candidate)
                except ValueError:
                    if candidate not in ("vpn.example.com", "example.com"):
                        gateway["domain"] = candidate.removeprefix("openvpn.").removeprefix("vpn.")
            except (OSError, PkiError):
                pass
    gateway["openvpn_host"] = website or ("openvpn." + gateway["domain"] if gateway["domain"] else "")
    gateway["relay_host"] = relay_host
    if not portal["host"]:
        portal["host"] = gateway["openvpn_host"]
    if not gateway["relay_backend"] and gateway["openvpn_backend"]:
        backend_host = urlsplit(gateway["openvpn_backend"]).hostname
        if backend_host:
            gateway["relay_backend"] = (f"[{backend_host}]" if ":" in backend_host else backend_host) + ":8444"
    # IPv6 is blocked for VPN guests altogether; preserve relay IPv6 blocks there.
    relay_lans = [value for value in relay_config.get("allowed_cidrs", []) if ipaddress.ip_network(value).version == 4]
    data["lan_cidrs"] = list(dict.fromkeys([*data["lan_cidrs"], *relay_lans]))
    return data


def get_settings(db=None):
    saved = settings.read_network()
    if saved:
        return shared_settings(NetworkSettings(**saved).model_dump(), db)
    subnet = pki.vpn_subnet()
    if not subnet:
        raise PkiError("Fix the server subnet and pool in Server → Configuration first")
    net, (first, last) = subnet
    dns, routes = [], []
    for line in settings.server_conf.read_text().splitlines():
        words = shlex.split(line, comments=True)
        if len(words) < 2 or words[0] != "push":
            continue
        words = shlex.split(words[1])
        if words[:2] == ["dhcp-option", "DNS"]:
            dns.append(words[2])
        if words and words[0] == "route":
            routes.append(str(ipaddress.ip_network(words[1] + "/" + (words[2] if len(words) > 2 else "32"), strict=False)))
    return shared_settings(NetworkSettings(vpn_subnet=str(net), pool_first=str(ipaddress.IPv4Address(first)),
        pool_last=str(ipaddress.IPv4Address(last)), guest_subnet=settings.guest_sub,
        dns_servers=list(dict.fromkeys(dns)), routes=routes,
        lan_cidrs=[settings.home_sub] if settings.home_sub else [],
        blocked_cidrs=settings.guest_block.split(),
        proxy_cidrs=cidrs(os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1/32,::1/128").replace(",", " ").split())
    ).model_dump(), db)


def validate(body):
    data = body.model_dump()
    try:
        net = ipaddress.IPv4Network(body.vpn_subnet, strict=True)
        guest = ipaddress.IPv4Network(body.guest_subnet, strict=True)
        first, last = ipaddress.IPv4Address(body.pool_first), ipaddress.IPv4Address(body.pool_last)
        if net.prefixlen > 28 or not guest.subnet_of(net) or guest.prefixlen <= net.prefixlen or guest.prefixlen > 30:
            raise ValueError()
        if not net.network_address + 1 < first <= last < net.broadcast_address:
            raise ValueError()
        if int(first) <= int(guest.broadcast_address) and int(last) >= int(guest.network_address):
            raise ValueError()
        if net.network_address + 1 in guest:
            raise ValueError()
        data.update(vpn_subnet=str(net), guest_subnet=str(guest), pool_first=str(first), pool_last=str(last))
        data["dns_servers"] = list(dict.fromkeys(str(ipaddress.IPv4Address(v)) for v in body.dns_servers))
        for ip in pki.static_ips().values():
            addr = ipaddress.IPv4Address(ip)
            if addr not in net or addr in guest or first <= addr <= last or addr in (net.network_address, net.network_address + 1, net.broadcast_address):
                raise PkiError("Move existing static client addresses before changing these networks")
    except ValueError:
        raise PkiError("Use a valid VPN subnet, a non-overlapping client pool and a guest subnet inside it")
    for key in ("routes", "lan_cidrs", "blocked_cidrs", "proxy_cidrs"):
        data[key] = cidrs(data[key], ipv4=key in ("routes", "lan_cidrs", "blocked_cidrs"))
    if not data["proxy_cidrs"]:
        raise PkiError("Keep at least one trusted proxy address")
    portal = data["portal"]
    gateway = data["gateway"]
    for key in ("domain", "openvpn_host", "relay_host"):
        if gateway[key]: gateway[key] = hostname(gateway[key])
    portal["host"] = hostname(portal["host"]) if portal["host"] else gateway["openvpn_host"]
    if portal["enabled"]:
        portal["host"] = hostname(portal["host"])
    if portal["target"]:
        try:
            portal["target"] = endpoint(portal["target"], portal=True)
        except PkiError:
            raise PkiError("Dedicated portal listener: enter the gateway's LAN IPv4 and port, such as 192.0.2.10:9443") from None
        try:
            portal["destinations"] = list(dict.fromkeys(str(ipaddress.IPv4Address(v)) for v in portal["destinations"]))
            if portal["enabled"] and not portal["destinations"]:
                raise ValueError()
            for value in portal["destinations"]:
                endpoint(value + ":9443", portal=True)
        except (ValueError, PkiError):
            raise PkiError("Portal DNS IPv4 addresses: enter the portal's individual IPv4 DNS answers") from None
    if portal["enabled"] and portal["host"] != gateway["openvpn_host"]:
        raise PkiError("The private portal and OpenVPN website must use the same hostname")
    if gateway["openvpn_backend"]:
        try:
            gateway["openvpn_backend"] = backend_url(gateway["openvpn_backend"])
        except PkiError:
            raise PkiError("VPN server web address: enter an HTTP(S) URL including the web UI port") from None
    if gateway["relay_backend"]:
        try:
            gateway["relay_backend"] = endpoint(gateway["relay_backend"])
        except PkiError:
            raise PkiError("Relay backend: enter the VPN server address and internal relay port, such as 192.0.2.20:8444") from None
    if gateway["relay_public_url"]:
        from . import relay
        gateway["relay_public_url"] = relay.validate_settings(relay.RelaySettings(url=gateway["relay_public_url"]))["url"]
    for key in ("trusted_cidrs", "portal_cidrs"):
        gateway[key] = cidrs(gateway[key])
    names = set()
    for service in gateway["services"]:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", service["name"]) or service["name"] in names:
            raise PkiError("Give each service a unique lowercase name")
        names.add(service["name"])
        service["host"] = hostname(service["host"])
        service["url"] = backend_url(service["url"])
        if service["host"] in (gateway["openvpn_host"], portal["host"], "dashboard." + gateway["domain"]):
            raise PkiError("Additional services cannot replace the portal or dashboard host")
        if any(not p.startswith("/") or re.search(r"[\s`{}\\]", p) for p in service["paths"]):
            raise PkiError("Service paths must start with / and contain no whitespace or template characters")
    if gateway["services"]:
        gateway["replace_services"] = True
    return data


def save_settings(body):
    data = validate(body)
    text = settings.server_conf.read_text()
    lines = []
    for line in text.splitlines():
        words = shlex.split(line, comments=True)
        if words and words[0] in ("server", "ifconfig-pool"):
            continue
        if len(words) > 1 and words[0] == "push":
            pushed = shlex.split(words[1])
            if pushed and (pushed[0] in ("route", "dns") or pushed[:2] == ["dhcp-option", "DNS"]):
                continue
        lines.append(line)
    net = ipaddress.IPv4Network(data["vpn_subnet"])
    lines += [f"server {net.network_address} {net.netmask} nopool", f'ifconfig-pool {data["pool_first"]} {data["pool_last"]}']
    for i, dns in enumerate(data["dns_servers"]):
        lines += [f'push "dns server {i} address {dns}"', f'push "dhcp-option DNS {dns}"']
    for value in data["routes"]:
        route = ipaddress.IPv4Network(value)
        lines.append(f'push "route {route.network_address} {route.netmask}"')
    portal = data["portal"]
    isolated_portal = portal["enabled"] and bool(portal["target"])
    fields = {"TRUST_SUB": data["vpn_subnet"], "GUEST_SUB": data["guest_subnet"],
        "LAN_CIDRS": " ".join(data["lan_cidrs"]), "GUEST_BLOCK": " ".join(data["blocked_cidrs"]),
        "PROXY_CIDRS": " ".join(data["proxy_cidrs"]),
        "GUEST_PORTAL_HOST": portal["host"] if isolated_portal else "",
        "GUEST_PORTAL_TARGET": portal["target"] if isolated_portal else "",
        "GUEST_PORTAL_DESTINATIONS": " ".join(portal["destinations"]) if isolated_portal else "",
        "NETWORK_JSON": json.dumps(data, separators=(",", ":"))}
    path = settings.network_file
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(".tmp")
    with pki.lock:
        fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write("".join(f"{key}={value}\n" for key, value in fields.items()))
        pki.write_config("server", "\n".join(lines) + "\n")
        settings.server_conf.chmod(0o600)
        temp.replace(path)
        # The relay runs as UID 65532. Give it only its own private proxy-trust
        # file, not access to the UI's complete service inventory.
        proxy_path = path.with_name("proxies.conf")
        proxy_temp = proxy_path.with_suffix(".tmp")
        fd = os.open(proxy_temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        os.fchmod(fd, 0o600)
        if os.geteuid() == 0:
            os.fchown(fd, 65532, 65532)
        with os.fdopen(fd, "w") as stream:
            stream.write("PROXY_CIDRS=" + " ".join(data["proxy_cidrs"]) + "\n")
        proxy_temp.replace(proxy_path)
    return {"settings": data, "restart_required": True}


def export_gateway(db=None):
    data = get_settings(db)
    gateway = data["gateway"]
    required = {"domain": "Gateway domain", "openvpn_host": "Website hostname", "openvpn_backend": "OpenVPN UI backend URL",
                "relay_host": "Public relay URL", "relay_backend": "Relay backend", "trusted_cidrs": "Networks allowed into private services"}
    missing = [label for key, label in required.items() if not gateway[key]]
    if missing:
        raise PkiError("Complete these settings before exporting: " + ", ".join(missing))
    if data["portal"]["enabled"] and data["portal"]["host"] != gateway["openvpn_host"]:
        raise PkiError("The private portal and gateway OpenVPN host must match")
    if data["portal"]["enabled"]:
        gateway["portal_cidrs"] = list(dict.fromkeys([*(gateway["portal_cidrs"] or gateway["trusted_cidrs"]), data["guest_subnet"]]))
    return {"version": 1, "gateway": gateway, "portal": data["portal"]}


class NetworkProxyHeaders:
    """Read proxy trust at request time so UI edits apply without a UI restart."""
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        from uvicorn.middleware.proxy_headers import ProxyHeadersMiddleware
        if scope["type"] == "http":
            scope.setdefault("state", {})["network_peer"] = (scope.get("client") or (None,))[0]
        config = settings.read_network()
        trusted = config.get("proxy_cidrs", os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1").split(","))
        await ProxyHeadersMiddleware(self.app, trusted_hosts=trusted)(scope, receive, send)
