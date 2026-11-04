"""Network settings edited in Settings → Network, and the gateway export.

The settings are private deployment data. They are saved, mode 0600, in
config/network/settings.conf (ignored by Git), which the OpenVPN entrypoint
reads as data, and they also rewrite the network lines of server.conf.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shlex
from urllib.parse import urlsplit, urlunsplit

from pydantic import BaseModel, Field, model_validator

from . import pki
from .pki import PkiError
from .settings import settings

EXPORT_VERSION = 2
RELAY_BACKEND_PORT = 8444
HOSTNAME = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?")
UNSAFE = re.compile(r"[\s`{}\\]")   # whitespace and template characters, for values used in Traefik templates


class Service(BaseModel):
    """An additional website routed by the gateway."""
    name: str
    host: str
    url: str
    public: bool = False
    paths: list[str] = Field(default_factory=list, max_length=100)
    insecure_tls: bool = False


class GuestLink(BaseModel):
    """A page on one of the gateway's websites that guests may open besides their portal."""
    url: str = Field(max_length=2048)
    whole_site: bool = False      # False: only the link's path and below


class Gateway(BaseModel):
    """What the Traefik gateway needs to know; exported as network.private.json."""
    domain: str = ""
    openvpn_host: str = ""        # website and personal portal, e.g. openvpn.example.com
    openvpn_backend: str = ""     # this server's web UI as the gateway reaches it, e.g. http://192.0.2.20:8080
    relay_host: str = ""
    relay_backend: str = ""       # this server's relay listener, e.g. 192.0.2.20:8444
    relay_public_url: str = ""
    portal_listener: str = ""     # the gateway's guest portal listener, LAN IPv4:port; empty = guests reach nothing
    trusted_cidrs: list[str] = Field(default_factory=list, max_length=100)   # empty keeps the gateway's own list
    guest_links: list[GuestLink] = Field(default_factory=list, max_length=50)
    replace_services: bool = False
    services: list[Service] = Field(default_factory=list, max_length=100)


class NetworkSettings(BaseModel):
    vpn_subnet: str
    pool_first: str
    pool_last: str
    guest_subnet: str
    dns_servers: list[str] = Field(default_factory=list, max_length=10)
    routes: list[str] = Field(default_factory=list, max_length=100)
    proxy_cidrs: list[str] = Field(default_factory=lambda: ["127.0.0.1/32", "::1/128"], max_length=100)
    gateway: Gateway = Field(default_factory=Gateway)

    @model_validator(mode="before")
    @classmethod
    def upgrade(cls, data):
        """Read settings saved by 1.9 development builds ("portal" object, LAN lists)."""
        if isinstance(data, dict) and "portal" in data:
            data = dict(data)
            portal = data.pop("portal") or {}
            gateway = dict(data.get("gateway") or {})
            if portal.get("enabled") and portal.get("target") and not gateway.get("portal_listener"):
                gateway["portal_listener"] = portal["target"]
            data["gateway"] = gateway
        return data


# -- validation helpers -------------------------------------------------------------
def hostname(value: str) -> str:
    value = value.strip().lower().rstrip(".")
    if len(value) > 253 or not HOSTNAME.fullmatch(value):
        raise PkiError("Enter a DNS hostname without a scheme, path or port")
    return value


def cidrs(values: list[str], *, ipv4: bool = False) -> list[str]:
    try:
        networks = [ipaddress.ip_network(value.strip(), strict=True) for value in values]
        if any(net.prefixlen == 0 or (ipv4 and net.version != 4) for net in networks):
            raise ValueError
    except ValueError:
        raise PkiError("Enter network CIDRs such as 192.0.2.0/24; /0 networks are not allowed") from None
    return list(dict.fromkeys(str(net) for net in networks))


def host_port(value: str) -> str:
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit() or not 1 <= int(port) <= 65535 or re.search(r"[\s`{}\\/@?#]", host):
        raise PkiError("Enter an address and port, such as 192.0.2.20:8444")
    return f"{host}:{int(port)}"


def portal_listener(value: str) -> str:
    try:
        host, _, port = value.rpartition(":")
        ip = ipaddress.IPv4Address(host)
        if not port.isdigit() or not 1024 <= int(port) <= 65535 or ip.packed[0] == 0 or ip.is_loopback \
                or ip.is_link_local or ip.is_multicast or ip.is_reserved:
            raise ValueError
    except ValueError:
        raise PkiError("Guest portal listener: enter the gateway's LAN IPv4 address and a port of 1024 or "
                       "higher, such as 192.0.2.10:9443") from None
    return f"{ip}:{int(port)}"


def backend_url(value: str) -> str:
    try:
        url = urlsplit(value)
        if url.scheme not in ("http", "https") or not url.hostname or url.username or url.password or UNSAFE.search(value):
            raise ValueError
        _ = url.port
    except ValueError:
        raise PkiError("Enter an HTTP(S) address without credentials, such as http://192.0.2.20:8080") from None
    return value


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def url_host(url: str) -> str:
    """The DNS name in a URL, or "" for an IP address, a malformed URL or no URL."""
    try:
        host = hostname(urlsplit(url).hostname or "")
    except (ValueError, PkiError):
        return ""
    return "" if is_ip(host) else host


# -- reading -----------------------------------------------------------------------
def with_defaults(data: dict, db=None) -> dict:
    """Fill empty gateway fields from what is already configured elsewhere."""
    from . import relay, relay_services

    gateway = data["gateway"]
    relay_url = relay.get_settings(db)["url"] if db is not None else ""
    if relay_url:
        gateway["relay_public_url"] = relay_url
    gateway["relay_host"] = gateway["relay_host"] or url_host(relay_url)
    gateway["openvpn_host"] = (gateway["openvpn_host"] or url_host(settings.profile_base_url)
                               or url_host(relay_services.signing_config(db)["url"]))
    if not gateway["domain"]:
        # Only drop a familiar service prefix; never guess a registrable domain.
        if gateway["relay_host"]:
            gateway["domain"] = gateway["relay_host"].removeprefix("relay.")
        elif gateway["openvpn_host"].startswith(("openvpn.", "vpn.")):
            gateway["domain"] = gateway["openvpn_host"].split(".", 1)[1]
        else:
            try:
                profile_host = hostname(pki.get_remote()["host"])
                if profile_host not in ("example.com", "vpn.example.com") and not is_ip(profile_host):
                    gateway["domain"] = profile_host.removeprefix("openvpn.").removeprefix("vpn.")
            except (OSError, PkiError):
                pass
    if not gateway["openvpn_host"] and gateway["domain"]:
        gateway["openvpn_host"] = "openvpn." + gateway["domain"]
    if not gateway["relay_backend"] and gateway["openvpn_backend"]:
        backend = urlsplit(gateway["openvpn_backend"]).hostname
        if backend:
            gateway["relay_backend"] = (f"[{backend}]" if ":" in backend else backend) + f":{RELAY_BACKEND_PORT}"
    return data


def from_server_conf() -> dict:
    """First-time settings: what server.conf and the environment say today."""
    subnet = pki.vpn_subnet()
    if not subnet:
        raise PkiError("Fix the server subnet and pool in Server → Configuration first")
    net, (first, last) = subnet
    dns, routes = [], []
    for line in settings.server_conf.read_text().splitlines():
        words = shlex.split(line, comments=True)
        if len(words) < 2 or words[0] != "push":
            continue
        pushed = shlex.split(words[1])
        if pushed[:2] == ["dhcp-option", "DNS"]:
            dns.append(pushed[2])
        elif pushed and pushed[0] == "route":
            mask = pushed[2] if len(pushed) > 2 else "32"
            routes.append(str(ipaddress.ip_network(pushed[1] + "/" + mask, strict=False)))
    proxies = os.environ.get("FORWARDED_ALLOW_IPS", "127.0.0.1/32,::1/128").replace(",", " ").split()
    return NetworkSettings(vpn_subnet=str(net), pool_first=str(ipaddress.IPv4Address(first)),
                           pool_last=str(ipaddress.IPv4Address(last)), guest_subnet=settings.guest_sub,
                           dns_servers=list(dict.fromkeys(dns)), routes=routes, proxy_cidrs=cidrs(proxies)).model_dump()


def get_settings(db=None) -> dict:
    saved = settings.read_network()
    data = NetworkSettings(**saved).model_dump() if saved else from_server_conf()
    return with_defaults(data, db)


def link_rule(link: dict) -> dict:
    """{"host", "path"} a guest link opens on the gateway; path "/" is the whole site."""
    url = urlsplit(link["url"])
    return {"host": url.hostname, "path": "/" if link["whole_site"] else url.path or "/"}


def guest_portal() -> dict | None:
    """What guests may reach, or None when no portal listener is set.

    {"host": the portal hostname, "target": the gateway's portal listener,
     "hosts": hostnames of the guest links}; all of them go to the listener.
    """
    saved = settings.read_network()
    if not saved:
        return None
    gateway = NetworkSettings(**saved).gateway
    if not gateway.openvpn_host or not gateway.portal_listener:
        return None
    hosts = sorted({link_rule(link.model_dump())["host"] for link in gateway.guest_links})
    return {"host": gateway.openvpn_host, "target": gateway.portal_listener, "hosts": hosts}


def guest_links() -> list[str]:
    """The guest links' URLs, for the guests' portal page."""
    saved = settings.read_network()
    return [link.url for link in NetworkSettings(**saved).gateway.guest_links] if saved else []


# -- validation and saving ------------------------------------------------------------
def validate_addressing(data: dict) -> None:
    try:
        net = ipaddress.IPv4Network(data["vpn_subnet"], strict=True)
        guest = ipaddress.IPv4Network(data["guest_subnet"], strict=True)
        first, last = ipaddress.IPv4Address(data["pool_first"]), ipaddress.IPv4Address(data["pool_last"])
        if net.prefixlen > 28 or not guest.subnet_of(net) or not net.prefixlen < guest.prefixlen <= 30:
            raise ValueError
        if not net.network_address + 1 < first <= last < net.broadcast_address:
            raise ValueError
        if first <= guest.broadcast_address and last >= guest.network_address:   # pool overlaps the guest range
            raise ValueError
        if net.network_address + 1 in guest:                                    # the server's own address
            raise ValueError
        data.update(vpn_subnet=str(net), guest_subnet=str(guest), pool_first=str(first), pool_last=str(last))
        data["dns_servers"] = list(dict.fromkeys(str(ipaddress.IPv4Address(v)) for v in data["dns_servers"]))
    except ValueError:
        raise PkiError("Use a valid VPN subnet, a client pool inside it and a separate guest subnet inside it") from None
    reserved = (net.network_address, net.network_address + 1, net.broadcast_address)
    for ip in pki.static_ips().values():
        addr = ipaddress.IPv4Address(ip)
        if addr not in net or addr in guest or first <= addr <= last or addr in reserved:
            raise PkiError("Move existing static client addresses before changing these networks")
    data["routes"] = cidrs(data["routes"], ipv4=True)
    data["proxy_cidrs"] = cidrs(data["proxy_cidrs"])
    if not data["proxy_cidrs"]:
        raise PkiError("Keep at least one trusted proxy address")


def validate_gateway(gateway: dict) -> None:
    for key in ("domain", "openvpn_host", "relay_host"):
        if gateway[key]:
            gateway[key] = hostname(gateway[key])
    if gateway["openvpn_backend"]:
        try:
            gateway["openvpn_backend"] = backend_url(gateway["openvpn_backend"])
        except PkiError:
            raise PkiError("VPN server web address: enter an HTTP(S) URL with the web UI port, "
                           "such as http://192.0.2.20:8080") from None
    if gateway["relay_backend"]:
        try:
            gateway["relay_backend"] = host_port(gateway["relay_backend"])
        except PkiError:
            raise PkiError("Relay backend: enter this server's address and relay port, such as 192.0.2.20:8444") from None
    if gateway["relay_public_url"]:
        from . import relay
        gateway["relay_public_url"] = relay.validate_url(gateway["relay_public_url"])
    if gateway["portal_listener"]:
        gateway["portal_listener"] = portal_listener(gateway["portal_listener"])
        if not gateway["openvpn_host"]:
            raise PkiError("Set the website hostname before the guest portal listener")
    gateway["trusted_cidrs"] = cidrs(gateway["trusted_cidrs"])
    reserved = {gateway["openvpn_host"], "dashboard." + gateway["domain"]}
    for link in gateway["guest_links"]:
        validate_guest_link(link, gateway["domain"], reserved | {gateway["relay_host"]})
    names = set()
    for service in gateway["services"]:
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,39}", service["name"]) or service["name"] in names:
            raise PkiError("Give each service a unique lowercase name")
        names.add(service["name"])
        service["host"] = hostname(service["host"])
        service["url"] = backend_url(service["url"])
        if service["host"] in reserved:
            raise PkiError("Additional services cannot use the OpenVPN website or dashboard hostname")
        if any(not path.startswith("/") or UNSAFE.search(path) for path in service["paths"]):
            raise PkiError("Service paths must start with / and contain no whitespace or template characters")
    if gateway["services"]:
        gateway["replace_services"] = True


def validate_guest_link(link: dict, domain: str, reserved: set[str]) -> None:
    raw = link["url"].strip()
    try:
        url = urlsplit(raw)
        host = hostname(url.hostname or "")
        if url.scheme != "https" or url.port not in (None, 443) or url.username or url.password or UNSAFE.search(raw):
            raise ValueError
    except (ValueError, PkiError):
        raise PkiError(f"Guest link {raw!r}: enter an https:// address without a port or credentials") from None
    if not domain or not host.endswith("." + domain):
        raise PkiError(f"Guest link {raw!r}: only websites under your domain ({domain or 'not set'}) can be opened by guests")
    if host in reserved:
        raise PkiError(f"Guest link {raw!r}: this hostname cannot be a guest link")
    link["url"] = urlunsplit(("https", host, url.path or "/", url.query, url.fragment))


def validate(body: NetworkSettings) -> dict:
    data = body.model_dump()
    validate_addressing(data)
    validate_gateway(data["gateway"])
    return data


def server_conf_lines(data: dict) -> list[str]:
    """server.conf with the subnet, pool, DNS and route lines replaced."""
    lines = []
    for line in settings.server_conf.read_text().splitlines():
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
    return lines


def write_private(path, text: str, owner: int | None = None) -> None:
    temp = path.with_suffix(".tmp")
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    if owner is not None and os.geteuid() == 0:
        os.fchown(fd, owner, owner)
    with os.fdopen(fd, "w") as stream:
        stream.write(text)
    temp.replace(path)


def save_settings(body: NetworkSettings) -> dict:
    data = validate(body)
    # Read by bin/network-settings.sh as KEY=value data, never executed.
    fields = {"TRUST_SUB": data["vpn_subnet"], "GUEST_SUB": data["guest_subnet"],
              "PROXY_CIDRS": " ".join(data["proxy_cidrs"]),
              "GUEST_PORTAL_TARGET": data["gateway"]["portal_listener"],
              "NETWORK_JSON": json.dumps(data, separators=(",", ":"))}
    path = settings.network_file
    path.parent.mkdir(parents=True, exist_ok=True)
    with pki.lock:
        pki.write_config("server", "\n".join(server_conf_lines(data)) + "\n")
        settings.server_conf.chmod(0o600)
        write_private(path, "".join(f"{key}={value}\n" for key, value in fields.items()))
        # The relay runs as UID 65532 and gets only the proxy trust, not the service inventory.
        write_private(path.with_name("proxies.conf"), "PROXY_CIDRS=" + " ".join(data["proxy_cidrs"]) + "\n", owner=65532)
    return {"settings": data, "restart_required": True}


# -- gateway export -----------------------------------------------------------------
def export_gateway(db=None) -> dict:
    """network.private.json for `./manage setup --network-file` on the Traefik gateway."""
    gateway = get_settings(db)["gateway"]
    required = {"domain": "Domain", "openvpn_host": "Website hostname", "openvpn_backend": "VPN server web address"}
    missing = [label for key, label in required.items() if not gateway[key]]
    if missing:
        raise PkiError("Complete these settings before downloading the gateway file: " + ", ".join(missing))
    return {"version": EXPORT_VERSION,
            **{key: gateway[key] for key in ("domain", "openvpn_host", "openvpn_backend", "relay_host",
                                             "relay_backend", "relay_public_url", "portal_listener", "trusted_cidrs")},
            "guest_links": [link_rule(link) for link in gateway["guest_links"]],
            # None keeps the gateway's existing additional services.
            "services": gateway["services"] if gateway["replace_services"] else None}


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
