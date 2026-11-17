"""Read-only check of what guests reach: Settings → Network → Guests → Check guest access.

Each saved target (the personal portal and every guest link) is checked the
way a guest's connection travels:

* DNS: the pushed DNS servers must return the portal listener's address for
  the hostname, or OpenVPN guests' connections are not redirected to the
  listener (relay guests do not need this: the relay pins these hostnames).
* HTTPS: this server opens the page through the gateway's portal listener.
  Guest connections reach the gateway from this server's address too, so the
  gateway answers as it answers a guest.
"""
from __future__ import annotations

import secrets
import socket
import ssl
import struct
from urllib.parse import urlsplit

from . import network

TIMEOUT = 4.0


def _skip_name(data: bytes, pos: int) -> int:
    while True:
        length = data[pos]
        if length >= 0xC0:          # compression pointer ends the name
            return pos + 2
        if length == 0:
            return pos + 1
        pos += 1 + length


def resolve_a(name: str, server: str, timeout: float = TIMEOUT, port: int = 53) -> list[str]:
    """IPv4 addresses for `name` from one DNS server (plain UDP query)."""
    qid = secrets.randbits(16)
    question = b"".join(bytes([len(part)]) + part.encode() for part in name.split(".")) + b"\0" + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        sock.connect((server, port))
        sock.send(struct.pack("!HHHHHH", qid, 0x0100, 1, 0, 0, 0) + question)
        reply = sock.recv(4096)
    rid, flags, _, answers = struct.unpack("!HHHH", reply[:8])
    if rid != qid:
        raise OSError("the DNS reply does not match the query")
    if flags & 0xF:                 # NXDOMAIN and other errors: no address
        return []
    pos, addresses = 12 + len(question), []
    try:
        for _ in range(answers):
            pos = _skip_name(reply, pos)
            rtype, _, _, length = struct.unpack("!HHIH", reply[pos:pos + 10])
            pos += 10
            if rtype == 1 and length == 4:
                addresses.append(socket.inet_ntoa(reply[pos:pos + 4]))
            pos += length
    except (IndexError, struct.error, OSError):
        raise OSError("malformed DNS reply") from None
    return addresses


def fetch_status(listener: str, host: str, path: str, timeout: float = TIMEOUT) -> int:
    """HTTP status of https://host/path, connecting to `listener` (IPv4:port) instead of the host's address."""
    ip, _, port = listener.rpartition(":")
    context = ssl.create_default_context()
    context.check_hostname = False       # this checks routing, not the certificate
    context.verify_mode = ssl.CERT_NONE
    with socket.create_connection((ip, int(port)), timeout=timeout) as raw, \
            context.wrap_socket(raw, server_hostname=host) as tls:
        tls.sendall(f"GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: openvpn-ui-guest-check\r\n"
                    "Connection: close\r\n\r\n".encode())
        head = b""
        while b"\r\n" not in head and len(head) < 1024:
            chunk = tls.recv(1024)
            if not chunk:
                break
            head += chunk
    try:
        return int(head.split(b" ", 2)[1])
    except (IndexError, ValueError):
        raise OSError("the gateway did not answer with HTTP") from None


def check_dns(host: str, portal_ip: str, servers: list[str]) -> dict:
    for server in servers:
        try:
            addresses = resolve_a(host, server)
        except OSError:
            continue
        if portal_ip in addresses:
            return {"ok": True, "message": f"DNS {server} returns {portal_ip}, so OpenVPN guests are sent to the portal listener."}
        if not addresses:
            return {"ok": False, "message": f"DNS {server} does not know {host}."}
        return {"ok": False, "message": f"DNS {server} returns {', '.join(addresses)}, not the gateway address {portal_ip}: "
                                        "OpenVPN guests are not sent to the portal listener (relay guests are)."}
    if not servers:
        return {"ok": True, "message": "No pushed DNS servers; the DNS step was not checked."}
    return {"ok": False, "message": "No pushed DNS server answered (" + ", ".join(servers) + ")."}


def check_http(listener: str, host: str, path: str, is_portal: bool) -> dict:
    try:
        status = fetch_status(listener, host, path)
    except (OSError, ssl.SSLError) as exc:
        return {"ok": False, "status": None,
                "message": f"The portal listener {listener} did not answer ({exc}). Is the gateway file applied and Traefik running?"}
    if status == 404:
        what = "the portal hostname" if is_portal else "this link"
        return {"ok": False, "status": status,
                "message": f"The gateway has no route for {what} on the portal listener (404). Apply the gateway file on the gateway."}
    if status == 403:
        return {"ok": False, "status": status,
                "message": "Refused (403): the gateway does not accept this server as the guest source (PORTAL_CIDRS), "
                           "or the website itself refuses the page."}
    if status >= 500:
        return {"ok": False, "status": status, "message": f"The gateway has a route, but the website answered {status}."}
    note = " The website asks for its own sign-in." if status == 401 else ""
    return {"ok": True, "status": status, "message": f"Guests reach it (HTTP {status}).{note}"}


def check(db=None) -> dict:
    """{"targets": [{"url", "portal", "dns", "http", "ok"}]} for the saved settings."""
    saved = network.get_settings(db)
    gateway = saved["gateway"]
    if not gateway["openvpn_host"] or not gateway["portal_listener"]:
        raise network.PkiError("Save the website hostname and the guest portal listener first")
    listener = gateway["portal_listener"]
    portal_ip = listener.rpartition(":")[0]
    targets = [(f"https://{gateway['openvpn_host']}/portal", True)] + [(link["url"], False) for link in gateway["guest_links"]]
    results = []
    for url, is_portal in targets:
        parts = urlsplit(url)
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        dns = check_dns(parts.hostname, portal_ip, saved["dns_servers"])
        http = check_http(listener, parts.hostname, path, is_portal)
        results.append({"url": url, "portal": is_portal, "dns": dns, "http": http, "ok": dns["ok"] and http["ok"]})
    return {"listener": listener, "targets": results}
