import socket
import ssl
import struct
import subprocess
import threading

import pytest

from app import guest_check, network


def dns_server(reply_for):
    """A one-shot UDP DNS server on 127.0.0.1; reply_for(query) -> reply bytes."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))

    def serve():
        query, peer = sock.recvfrom(512)
        sock.sendto(reply_for(query), peer)
        sock.close()
    threading.Thread(target=serve, daemon=True).start()
    return sock.getsockname()[1]


def test_resolve_a_follows_cname_answers():
    def reply(query):
        header = struct.pack("!HHHHHH", struct.unpack("!H", query[:2])[0], 0x8180, 1, 2, 0, 0)
        cname = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, 5) + b"\x02gw\xc0\x0c"
        a = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton("192.0.2.10")
        return header + query[12:] + cname + a
    assert guest_check.resolve_a("app.example.test", "127.0.0.1", port=dns_server(reply)) == ["192.0.2.10"]


def test_resolve_a_malformed_reply():
    def reply(query):   # claims one answer but carries none
        return struct.pack("!HHHHHH", struct.unpack("!H", query[:2])[0], 0x8180, 1, 1, 0, 0) + query[12:]
    with pytest.raises(OSError):
        guest_check.resolve_a("app.example.test", "127.0.0.1", port=dns_server(reply))


def test_resolve_a_unknown_name():
    def reply(query):
        return struct.pack("!HHHHHH", struct.unpack("!H", query[:2])[0], 0x8183, 1, 0, 0, 0) + query[12:]
    assert guest_check.resolve_a("nosuch.example.test", "127.0.0.1", port=dns_server(reply)) == []


@pytest.fixture
def portal_listener(tmp_path):
    """A TLS listener answering like the gateway's portal entrypoint: 200 for the portal, 401 for one link, else 404."""
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-subj", "/CN=gateway",
                    "-keyout", str(key), "-out", str(cert)], check=True, capture_output=True)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    sni = []
    context.sni_callback = lambda sock, name, ctx: sni.append(name)
    server = socket.create_server(("127.0.0.1", 0))
    seen = []

    def serve():
        while True:
            try:
                raw, _ = server.accept()
            except OSError:
                return
            with context.wrap_socket(raw, server_side=True) as tls:
                request = tls.recv(4096).decode()
                host = next(line.split(": ", 1)[1] for line in request.split("\r\n") if line.startswith("Host: "))
                seen.append((sni[-1], host, request.split(" ")[1]))
                status = {"vpn.example.test": 200, "app.example.test": 401}.get(host, 404)
                tls.sendall(f"HTTP/1.1 {status} X\r\nContent-Length: 0\r\n\r\n".encode())
    threading.Thread(target=serve, daemon=True).start()
    yield f"127.0.0.1:{server.getsockname()[1]}", seen
    server.close()


def test_check_reports_each_target(portal_listener, monkeypatch):
    listener, seen = portal_listener
    monkeypatch.setattr(network, "get_settings", lambda db=None: {"dns_servers": ["192.0.2.53"], "gateway": {
        "openvpn_host": "vpn.example.test", "portal_listener": listener, "guest_links": [
            {"url": "https://app.example.test/share/abc?x=1", "whole_site": False},
            {"url": "https://files.example.test/", "whole_site": True}]}})
    answers = {"vpn.example.test": ["127.0.0.1"], "app.example.test": ["127.0.0.1"], "files.example.test": ["192.0.2.99"]}
    monkeypatch.setattr(guest_check, "resolve_a", lambda name, server: answers[name])
    portal, app, files = guest_check.check()["targets"]
    assert portal["ok"] and portal["portal"] and portal["http"]["status"] == 200
    assert app["ok"] and app["http"]["status"] == 401 and "sign-in" in app["http"]["message"]
    assert not files["ok"] and files["http"]["status"] == 404 and "no route" in files["http"]["message"]
    assert "192.0.2.99" in files["dns"]["message"] and not files["dns"]["ok"]
    # SNI and Host carry the link's hostname; the path and query are the link's.
    assert seen[1] == ("app.example.test", "app.example.test", "/share/abc?x=1")


def test_check_unreachable_listener_and_dns(monkeypatch):
    with socket.create_server(("127.0.0.1", 0)) as closed:
        port = closed.getsockname()[1]
    monkeypatch.setattr(network, "get_settings", lambda db=None: {"dns_servers": ["192.0.2.53"], "gateway": {
        "openvpn_host": "vpn.example.test", "portal_listener": f"127.0.0.1:{port}", "guest_links": []}})
    def no_answer(name, server):
        raise OSError("timed out")
    monkeypatch.setattr(guest_check, "resolve_a", no_answer)
    (portal,) = guest_check.check()["targets"]
    assert not portal["ok"] and portal["http"]["status"] is None and "did not answer" in portal["http"]["message"]
    assert "No pushed DNS server answered" in portal["dns"]["message"]


def test_check_needs_a_saved_listener(monkeypatch):
    monkeypatch.setattr(network, "get_settings", lambda db=None: {"dns_servers": [], "gateway": {
        "openvpn_host": "vpn.example.test", "portal_listener": "", "guest_links": []}})
    with pytest.raises(network.PkiError):
        guest_check.check()
