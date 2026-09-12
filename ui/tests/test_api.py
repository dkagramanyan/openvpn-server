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
    # Pin the listening port and protocol so the tests do not depend on the
    # deployment-specific values in the repository's server.conf.
    conf = (ROOT / "server.conf").read_text()
    conf = re.sub(r"(?m)^\s*port\s+\d+", "port 1197", conf)
    conf = re.sub(r"(?m)^\s*proto\s+\S+", "proto udp", conf)
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


def test_profile_download_and_remote(client):
    r = client.get("/api/clients/alice/ovpn")
    assert r.status_code == 200
    assert "<cert>" in r.text and "verify-x509-name server name" in r.text and "auth-user-pass" in r.text
    assert client.get("/api/clients/old/ovpn").status_code == 200   # expired but still issued
    assert client.get("/api/clients/bob/ovpn").status_code == 404
    r = client.put("/api/settings", json={"host": "vpn.example.org", "port": 443}, headers=H)
    assert r.status_code == 200, r.text
    # The protocol is never taken from the request; it follows server.conf.
    assert r.json()["remote"] == {"host": "vpn.example.org", "port": "443", "proto": "udp"}
    assert r.json()["listen"] == {"port": "1197", "proto": "udp"}
    profile = client.get("/api/clients/alice/ovpn").text
    assert "remote vpn.example.org 443" in profile and "proto udp" in profile
    # A protocol sent anyway is ignored rather than honoured.
    r = client.put("/api/settings", json={"host": "vpn.example.org", "port": 443, "proto": "tcp"}, headers=H)
    assert r.json()["remote"]["proto"] == "udp"
    assert client.put("/api/settings", json={"host": "bad host", "port": 443}, headers=H).status_code == 400


def test_port_mismatch_warns_and_protocol_follows_server_conf(client):
    # profiles dial 443 while OpenVPN listens on 1197
    warns = client.get("/api/overview?range=today").json()["warnings"]
    assert any("443" in w and "1197" in w for w in warns), warns

    # switching the server to TCP rewrites the protocol of every profile
    conf = client.get("/api/server/config/server").json()["content"]
    r = client.put("/api/server/config/server", json={"content": conf.replace("proto udp", "proto tcp")}, headers=H)
    assert r.status_code == 200 and r.json()["restart_required"] is True
    s = client.get("/api/settings").json()
    assert s["listen"]["proto"] == "tcp" and s["remote"]["proto"] == "tcp"
    assert "proto tcp" in client.get("/api/clients/alice/ovpn").text
    assert any(e["kind"] == "remote_changed" and "tcp" in (e["detail"] or "")
               for e in client.get("/api/events").json()["events"])

    # and back to UDP
    conf = client.get("/api/server/config/server").json()["content"]
    client.put("/api/server/config/server", json={"content": conf.replace("proto tcp", "proto udp")}, headers=H)
    assert client.get("/api/settings").json()["remote"]["proto"] == "udp"
    assert "proto udp" in client.get("/api/clients/alice/ovpn").text


def test_delete_requires_revocation(client):
    assert client.delete("/api/clients/alice", headers=H).status_code == 400
    assert client.delete("/api/clients/old", headers=H).status_code == 400
    r = client.delete("/api/clients/bob", headers=H)
    assert r.status_code == 200, r.text
    assert "bob" not in {r["name"] for r in client.get("/api/clients").json()["clients"]}
    assert client.get("/api/clients/bob").status_code == 404


def test_notes_static_ip_and_config(client):
    assert client.put("/api/clients/alice/note", json={"note": " laptop "}, headers=H).json() == {"note": "laptop"}
    assert client.put("/api/clients/alice/static-ip", json={"ip": "10.0.71.9"}, headers=H).status_code == 200
    assert (TMP / "staticclients" / "alice").read_text() == "ifconfig-push 10.0.71.9 255.255.255.0\n"
    assert client.put("/api/clients/alice/static-ip", json={"ip": "300.1.1.1"}, headers=H).status_code == 400
    row = client.get("/api/clients/alice").json()
    assert row["note"] == "laptop" and row["static_ip"] == "10.0.71.9"
    conf = client.get("/api/server/config/server").json()["content"]
    r = client.put("/api/server/config/server", json={"content": conf.replace("management ", "#management ")}, headers=H)
    assert r.status_code == 400
    assert client.get("/api/server/config/nope").status_code == 400
    s = client.get("/api/server").json()
    assert s["pki"]["ca"]["cn"] == "Test CA" and s["pki"]["crl"]["revoked"] == 1 and s["remote"]["port"] == "443"
    assert client.post("/api/server/restart", headers=H).status_code == 503   # no OpenVPN here
    events = client.get("/api/events").json()["events"]
    assert {"login", "client_deleted", "profile_downloaded", "remote_changed", "static_ip_set"} <= {e["kind"] for e in events}
