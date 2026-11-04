"""Read-only address suggestions for Settings → Network; they never change settings."""
from __future__ import annotations

import fcntl
import ipaddress
import socket
import struct

SIOCGIFADDR, SIOCGIFNETMASK = 0x8915, 0x891B
PORTAL_PORT = 9443
UI_PORT = 8080


def usable_ipv4(value) -> str | None:
    try:
        ip = ipaddress.IPv4Address(value)
    except (ValueError, TypeError):
        return None
    return None if ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast or ip.is_reserved else str(ip)


def interfaces() -> list[dict]:
    """This host's IPv4 addresses, without loopback, container and tunnel interfaces."""
    result = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _, name in socket.if_nameindex():
            if name.startswith(("lo", "docker", "br-", "veth", "tun", "ovpn", "wg")):
                continue
            try:
                request = struct.pack("256s", name.encode()[:15])
                address = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), SIOCGIFADDR, request)[20:24])
                mask = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), SIOCGIFNETMASK, request)[20:24])
            except OSError:
                continue
            if usable_ipv4(address):
                result.append({"name": name, "address": address,
                               "network": str(ipaddress.IPv4Network(f"{address}/{mask}", strict=False))})
    return result


def dns_ipv4(host: str) -> list[str]:
    if not host:
        return []
    try:
        answers = socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM)
    except OSError:
        return []
    return sorted({row[4][0] for row in answers if usable_ipv4(row[4][0])})


def source_ipv4(target: str) -> str | None:
    """The local address the kernel would use to reach target (no packet is sent)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((target, 443))
            return usable_ipv4(sock.getsockname()[0])
    except OSError:
        return None


def discover(data: dict, *, peer: str | None = None, proxied: bool = False) -> dict:
    """Guess the gateway's and this server's LAN addresses.

    The gateway is the reverse proxy this request came through, or else the one
    LAN address the website's hostname resolves to. This server is the
    interface that routes to the gateway.
    """
    local = interfaces()
    website = dns_ipv4(data["gateway"]["openvpn_host"])
    gateway_ip = usable_ipv4(peer) if proxied else None
    if not gateway_ip:
        on_lan = [ip for ip in website
                  if any(ipaddress.IPv4Address(ip) in ipaddress.IPv4Network(row["network"]) for row in local)]
        gateway_ip = on_lan[0] if len(on_lan) == 1 else None
    probe = gateway_ip or (website[0] if website else None)
    server_ip = source_ipv4(probe) if probe else None
    if not server_ip and len(local) == 1:
        server_ip = local[0]["address"]

    suggestions = {}
    if server_ip:
        suggestions["gateway.openvpn_backend"] = {"value": f"http://{server_ip}:{UI_PORT}",
                                                  "source": "This server's address on the route to the gateway"}
    if gateway_ip and gateway_ip != server_ip:
        suggestions["gateway.portal_listener"] = {"value": f"{gateway_ip}:{PORTAL_PORT}",
                                                  "source": "The gateway's address with the portal port"}
        suggestions["proxy_cidrs"] = {"value": [gateway_ip + "/32"], "source": "The gateway's connection address"}
    return {"interfaces": local, "website_ipv4s": website, "gateway_ipv4": gateway_ip,
            "server_ipv4": server_ip, "suggestions": suggestions}
