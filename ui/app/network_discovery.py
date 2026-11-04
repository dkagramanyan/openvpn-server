"""Read-only network suggestions for an administrator; never change access policy."""
from __future__ import annotations

import fcntl
import ipaddress
import socket
import struct
from urllib.parse import urlsplit


def usable_ipv4(value):
    try:
        ip = ipaddress.IPv4Address(value)
        return str(ip) if not (ip.is_loopback or ip.is_unspecified or ip.is_link_local or ip.is_multicast or ip.is_reserved) else None
    except (ValueError, TypeError):
        return None


def interfaces():
    result = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _, name in socket.if_nameindex():
            if name.startswith(('lo', 'docker', 'br-', 'veth', 'tun', 'ovpn', 'wg')):
                continue
            try:
                request = struct.pack('256s', name.encode()[:15])
                address = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x8915, request)[20:24])
                mask = socket.inet_ntoa(fcntl.ioctl(sock.fileno(), 0x891b, request)[20:24])
                if usable_ipv4(address):
                    result.append({'name': name, 'address': address, 'network': str(ipaddress.IPv4Network(address + '/' + mask, strict=False))})
            except OSError:
                continue
    return result


def dns_ipv4(host):
    if not host:
        return []
    try:
        return sorted({row[4][0] for row in socket.getaddrinfo(host, None, socket.AF_INET, socket.SOCK_STREAM) if usable_ipv4(row[4][0])})
    except OSError:
        return []


def route_ipv4(target):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            # UDP connect asks the kernel for its route; no datagram is sent.
            sock.connect((target, 443))
            return usable_ipv4(sock.getsockname()[0])
    except OSError:
        return None


def discover(data, *, peer=None, proxied=False):
    gateway, portal = data['gateway'], data['portal']
    local = interfaces()
    website_addresses = dns_ipv4(gateway['openvpn_host'])
    peer_ip = usable_ipv4(peer)
    # An actual proxy peer is more useful than a public/hairpin DNS address.
    gateway_ip = peer_ip if proxied else None
    if not gateway_ip:
        same_lan = [address for address in website_addresses if any(ipaddress.IPv4Address(address) in ipaddress.IPv4Network(row['network']) for row in local)]
        gateway_ip = same_lan[0] if len(same_lan) == 1 else None
    target = gateway_ip or (website_addresses[0] if website_addresses else None)
    server_ip = route_ipv4(target) if target else None
    if not server_ip and len(local) == 1:
        server_ip = local[0]['address']
    suggestions = {}
    def suggest(key, value, source):
        if value:
            suggestions[key] = {'value': value, 'source': source}
    suggest('gateway.openvpn_backend', f'http://{server_ip}:8080' if server_ip else None, 'VPN server interface selected by its route to the gateway')
    if gateway_ip and gateway_ip != server_ip:
        suggest('portal.target', gateway_ip + ':9443', 'Gateway address seen by this service; dedicated portal port 9443')
        suggest('proxy_cidrs', [gateway_ip + '/32'], 'Exact gateway connection address')
    suggest('portal.destinations', website_addresses, 'Current IPv4 DNS answers visible from this server; add any split-DNS answers used by clients')
    if server_ip:
        suggest('gateway.portal_cidrs', list(dict.fromkeys([*gateway['trusted_cidrs'], server_ip + '/32'])), 'Existing portal access plus the VPN/relay egress address')
        lan = next((row['network'] for row in local if row['address'] == server_ip), None)
        suggest('lan_cidrs', [lan] if lan else None, 'VPN server LAN; used only to block guest destinations')
    return {'interfaces': local, 'website_ipv4s': website_addresses, 'gateway_ipv4': gateway_ip,
            'server_ipv4': server_ip, 'suggestions': suggestions,
            'notes': ['Existing public VPN and relay ports are preserved.',
                      'Suggestions do not change settings until you save. Private-service allowlists are never inferred automatically.']}
