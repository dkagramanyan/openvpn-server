"""End-to-end API tests against a throwaway PKI built with openssl (no easy-rsa needed)."""
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ui"))

# settings is a module-level singleton: the environment must be in place before app.main is imported.
TMP = Path(tempfile.mkdtemp(prefix="ovpn-ui-test-"))
os.environ.update({
    "OPENVPN_DIR": str(TMP), "OVPN_BIN_DIR": str(ROOT / "bin"), "OVPN_LOG_DIR": str(TMP / "log"),
    "EASYRSA_DIR": "/nonexistent", "MGMT_PORT": "1", "OPENVPN_ADMIN_PASSWORD": "test-password",
    "OVPN_UI_POLL_INTERVAL": "60",
})

CA_CNF = """
[ca]
default_ca = easyrsa
[easyrsa]
dir = {pki}
database = $dir/index.txt
new_certs_dir = $dir/certs_by_serial
serial = $dir/serial
certificate = $dir/ca.crt
private_key = $dir/private/ca.key
default_md = sha256
policy = pol
x509_extensions = client
[pol]
commonName = supplied
[client]
basicConstraints = CA:FALSE
extendedKeyUsage = clientAuth
[server]
basicConstraints = CA:FALSE
extendedKeyUsage = serverAuth
"""


def ossl(*args):
    subprocess.run(["openssl", *args], check=True, capture_output=True)


def issue(pki, name, ext, start, end):
    ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(pki / "private" / f"{name}.key"))
    ossl("req", "-new", "-key", str(pki / "private" / f"{name}.key"), "-subj", f"/CN={name}",
         "-out", str(pki / "reqs" / f"{name}.req"))
    ossl("ca", "-batch", "-config", str(pki / "ca.cnf"), "-extensions", ext, "-startdate", start, "-enddate", end,
         "-in", str(pki / "reqs" / f"{name}.req"), "-out", str(pki / "issued" / f"{name}.crt"), "-notext")


def build_env():
    pki = TMP / "pki"
    for d in ("private", "reqs", "issued", "certs_by_serial", "revoked/certs_by_serial"):
        (pki / d).mkdir(parents=True)
    for d in ("config", "clients", "staticclients", "db", "log"):
        (TMP / d).mkdir()
    (pki / "ca.cnf").write_text(CA_CNF.format(pki=pki))
    (pki / "index.txt").write_text("")
    (pki / "serial").write_text("1000\n")
    ossl("ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(pki / "private" / "ca.key"))
    ossl("req", "-x509", "-new", "-key", str(pki / "private" / "ca.key"), "-subj", "/CN=Test CA", "-days", "3650",
         "-out", str(pki / "ca.crt"))
    issue(pki, "server", "server", "20260101000000Z", "20360101000000Z")
    issue(pki, "alice", "client", "20260101000000Z", "20360101000000Z")
    issue(pki, "old", "client", "20200101000000Z", "20210101000000Z")
    issue(pki, "bob", "client", "20260101000000Z", "20360101000000Z")
    # revoke bob the way easy-rsa does: index entry -> R, certificate moved under revoked/
    ossl("ca", "-batch", "-config", str(pki / "ca.cnf"), "-revoke", str(pki / "issued" / "bob.crt"),
         "-crl_reason", "keyCompromise")
    serial = subprocess.run(["openssl", "x509", "-in", str(pki / "issued" / "bob.crt"), "-noout", "-serial"],
                            check=True, capture_output=True, text=True).stdout.strip().split("=")[1]
    shutil.move(pki / "issued" / "bob.crt", pki / "revoked" / "certs_by_serial" / f"{serial}.crt")
    ossl("ca", "-batch", "-config", str(pki / "ca.cnf"), "-gencrl", "-crldays", "180", "-out", str(pki / "crl.pem"))
    (pki / "ta.key").write_text("#\n# 2048 bit OpenVPN static key\n#\n-----BEGIN OpenVPN Static key V1-----\n"
                                "00\n-----END OpenVPN Static key V1-----\n")
    # Pin the listening sockets so the tests do not depend on the
    # deployment-specific values in the repository's server.conf.
    conf = re.sub(r"(?m)^\s*local\s+.*\n", "", (ROOT / "server.conf").read_text())
    conf = conf.replace("proto udp\n", "proto udp\nlocal * 1197 udp\nlocal * 1196 tcp\n", 1)
    (TMP / "server.conf").write_text(conf)
    shutil.copy(ROOT / "config" / "client.conf", TMP / "config" / "client.conf")
    (TMP / "clients" / "oath.secrets").write_text("alice:3132333435363738393031323334353637383930\n")


build_env()

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

H = {"X-Requested-With": "fetch"}


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as c:
        r = c.post("/api/login", json={"username": "admin", "password": "test-password"}, headers=H)
        assert r.status_code == 200, r.text
        yield c
    shutil.rmtree(TMP, ignore_errors=True)


def test_login_requires_csrf_header_and_password(client):
    cookies = dict(client.cookies)
    client.cookies.clear()
    try:
        assert client.get("/api/me").status_code == 401
        assert client.post("/api/login", json={"username": "admin", "password": "test-password"}).status_code == 403
        assert client.post("/api/login", json={"username": "admin", "password": "wrong"}, headers=H).status_code == 401
        assert client.get("/api/clients").status_code == 401
    finally:
        client.cookies.update(cookies)
    assert client.get("/api/me").json()["username"] == "admin"


def test_clients_listing(client):
    rows = {r["name"]: r for r in client.get("/api/clients").json()["clients"]}
    assert rows["alice"]["state"] == "valid" and rows["alice"]["tfa"] is True
    assert rows["old"]["state"] == "expired" and rows["old"]["days_left"] < 0
    assert rows["bob"]["state"] == "revoked" and rows["bob"]["cert"]["reason"] == "keyCompromise"
    assert "server" not in rows
    d = client.get("/api/clients/alice?tz=3600").json()
    assert d["tfa_uri"].startswith("otpauth://totp/OpenVPN:alice?") and d["sessions"] == []
    assert len(d["daily"]) in (30, 31)
    assert client.get("/api/clients/alice/tfa/qr.svg").headers["content-type"].startswith("image/svg+xml")
    assert client.get("/api/clients/nobody").status_code == 404
    assert client.get("/api/clients/bad%20name").status_code == 400


def test_overview_all_range_is_short(client):
    r = client.get("/api/overview?range=all&tz=0")
    assert r.status_code == 200, r.text
    data = r.json()
    assert len(data["series"]) <= 3
    assert data["counts"] == {"valid": 1, "expiring": 0, "expired": 1, "revoked": 1}
    assert any("unreachable" in w for w in data["warnings"])
    assert client.get("/api/overview?range=bogus").status_code == 400


UDP, TCP = {"port": "1197", "proto": "udp"}, {"port": "1196", "proto": "tcp"}


def test_profile_download_and_remote(client):
    r = client.get("/api/clients/alice/ovpn")
    assert r.status_code == 200
    assert "<cert>" in r.text and "verify-x509-name server name" in r.text and "auth-user-pass" in r.text
    assert client.get("/api/clients/old/ovpn").status_code == 200   # expired but still issued
    assert client.get("/api/clients/bob/ovpn").status_code == 404
    # one remote per listening socket, UDP first; ports default to the listening ones
    r = client.put("/api/settings", json={"host": "vpn.example.org"}, headers=H)
    assert r.status_code == 200, r.text
    assert r.json()["remote"] == {"host": "vpn.example.org", "remotes": [UDP, TCP]}
    assert r.json()["listen"] == [UDP, TCP]
    profile = client.get("/api/clients/alice/ovpn").text
    assert "remote vpn.example.org 1197 udp\nremote vpn.example.org 1196 tcp\n" in profile
    assert "\nproto " not in profile and "server-poll-timeout 10" in profile
    # a forwarded public port per protocol; protocols can not be added from here
    r = client.put("/api/settings", json={"host": "vpn.example.org", "ports": {"tcp": 443, "sctp": 9}}, headers=H)
    assert r.json()["remote"]["remotes"] == [UDP, {"port": "443", "proto": "tcp"}]
    assert client.put("/api/settings", json={"host": "bad host"}, headers=H).status_code == 400
    assert client.put("/api/settings", json={"host": "h", "ports": {"udp": 70000}}, headers=H).status_code == 400


def test_port_mismatch_warns_and_protocols_follow_server_conf(client):
    # profiles dial 443/tcp while OpenVPN listens on 1196/tcp
    warns = client.get("/api/overview?range=today").json()["warnings"]
    assert any("443/tcp" in w and "1196/tcp" in w for w in warns), warns

    # dropping the TCP socket from server.conf drops the TCP remote from every profile
    conf = client.get("/api/server/config/server").json()["content"]
    r = client.put("/api/server/config/server", json={"content": conf.replace("local * 1196 tcp\n", "")}, headers=H)
    assert r.status_code == 200 and r.json()["restart_required"] is True
    assert client.get("/api/settings").json()["remote"]["remotes"] == [UDP]
    assert "1196 tcp" not in client.get("/api/clients/alice/ovpn").text and "443" not in client.get("/api/clients/alice/ovpn").text
    assert any(e["kind"] == "remote_changed" and "udp" in (e["detail"] or "")
               for e in client.get("/api/events").json()["events"])

    # and back: the TCP remote returns with the listening port
    client.put("/api/server/config/server", json={"content": conf}, headers=H)
    assert client.get("/api/settings").json()["remote"]["remotes"] == [UDP, TCP]
    assert "remote vpn.example.org 1196 tcp" in client.get("/api/clients/alice/ovpn").text


def test_delete_requires_revocation(client):
    assert client.delete("/api/clients/alice", headers=H).status_code == 400
    assert client.delete("/api/clients/old", headers=H).status_code == 400
    r = client.delete("/api/clients/bob", headers=H)
    assert r.status_code == 200, r.text
    assert "bob" not in {r["name"] for r in client.get("/api/clients").json()["clients"]}
    assert client.get("/api/clients/bob").status_code == 404


def test_notes_static_ip_and_config(client):
    assert client.put("/api/clients/alice/note", json={"note": " laptop "}, headers=H).json() == {"note": "laptop"}
    assert client.put("/api/clients/alice/static-ip", json={"ip": "10.0.70.130"}, headers=H).status_code == 200
    assert (TMP / "staticclients" / "alice").read_text() == "ifconfig-push 10.0.70.130 255.255.255.0\n"
    # outside the server subnet, the server's own address, inside the dynamic pool, taken by alice
    for ip in ("300.1.1.1", "10.0.71.9", "10.0.70.1", "10.0.70.50"):
        assert client.put("/api/clients/old/static-ip", json={"ip": ip}, headers=H).status_code == 400, ip
    r = client.put("/api/clients/old/static-ip", json={"ip": "10.0.70.130"}, headers=H)
    assert r.status_code == 400 and "alice" in r.json()["detail"]
    row = client.get("/api/clients/alice").json()
    assert row["note"] == "laptop" and row["static_ip"] == "10.0.70.130" and row["guest"] is True
    # a static IP left over from the old separate guest subnet is flagged on the dashboard
    (TMP / "staticclients" / "alice").write_text("ifconfig-push 10.0.71.9 255.255.255.0\n")
    assert any("alice (10.0.71.9)" in w for w in client.get("/api/overview").json()["warnings"])
    (TMP / "staticclients" / "alice").unlink()
    r = client.post("/api/clients", json={"name": "old"}, headers=H)
    assert r.status_code == 409 and "renew" in r.json()["detail"]
    conf = client.get("/api/server/config/server").json()["content"]
    r = client.put("/api/server/config/server", json={"content": conf.replace("management ", "#management ")}, headers=H)
    assert r.status_code == 400
    assert client.get("/api/server/config/nope").status_code == 400
    s = client.get("/api/server").json()
    assert s["pki"]["ca"]["cn"] == "Test CA" and s["pki"]["crl"]["revoked"] == 1 and s["listen"] == [UDP, TCP]
    assert client.post("/api/server/restart", headers=H).status_code == 503   # no OpenVPN here
    events = client.get("/api/events").json()["events"]
    assert {"login", "client_deleted", "profile_downloaded", "remote_changed", "static_ip_set"} <= {e["kind"] for e in events}


def test_guest_switch_on_create(client):
    from app import pki
    # a full-access client may not take a guest address, and a guest needs one
    r = client.post("/api/clients", json={"name": "carol", "static_ip": "10.0.70.140"}, headers=H)
    assert r.status_code == 400 and "guest range" in r.json()["detail"]
    r = client.post("/api/clients", json={"name": "carol", "guest": True, "static_ip": "10.0.70.140"}, headers=H)
    assert r.status_code != 400 or "guest range" not in r.json()["detail"]   # accepted; fails later without easy-rsa
    r = client.post("/api/clients", json={"name": "carol", "guest": True, "static_ip": "10.0.70.20"}, headers=H)
    assert r.status_code == 400 and "guest range" in r.json()["detail"]
    # guests without an address get the first free one
    assert pki.next_guest_ip("carol") == "10.0.70.129"
    (TMP / "staticclients" / "alice").write_text("ifconfig-push 10.0.70.129 255.255.255.0\n")
    assert pki.next_guest_ip("carol") == "10.0.70.130"
    (TMP / "staticclients" / "alice").unlink()
