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
unique_subject = no
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


def test_login_is_throttled_per_user_and_per_address(client, monkeypatch):
    from app import auth
    from app.main import limiter
    cookies = dict(client.cookies)
    client.cookies.clear()
    post = lambda user, pw: client.post("/api/login", json={"username": user, "password": pw}, headers=H).status_code
    try:
        # one user name: the sixth attempt has to wait, even with the right password
        limiter._state.clear()
        assert [post("admin", "wrong") for _ in range(5)] == [401] * 5
        assert post("admin", "test-password") == 429
        # one address trying many names: stopped as well, so it cannot fill the table of counters;
        # an unknown name costs the server a password check like a known one
        limiter._state.clear()
        checked = []
        monkeypatch.setattr(auth, "verify_unknown_user", checked.append)
        codes = [post(f"user{i}", "x") for i in range(25)]
        assert codes == [401] * 20 + [429] * 5 and len(checked) == 20
        assert post("admin", "test-password") == 429
        # a successful login clears the counters of its address
        limiter._state.clear()
        assert [post("admin", "wrong") for _ in range(3)] == [401] * 3
        assert post("admin", "test-password") == 200 and not limiter._state
    finally:
        limiter._state.clear()
        client.cookies.clear()
        client.cookies.update(cookies)
    assert client.get("/api/me").json()["username"] == "admin"
    rows = [e for e in client.get("/api/events?limit=1000").json()["events"] if e["kind"] == "login_failed"]
    assert len(rows) == 1 + 5 + 20 + 3      # attempts that had to wait are not logged


def test_every_route_needs_a_session_and_every_change_the_csrf_header(client):
    from fastapi.routing import APIRoute
    from app.main import app, limiter
    public = {"/healthz", "/", "/p/{token}", "/p/{token}/download"}
    cookies = dict(client.cookies)
    seen = 0
    try:
        for route in app.routes:
            if not isinstance(route, APIRoute):
                continue
            path = route.path.replace("{name}", "alice").replace("{which}", "server").replace("{token}", "x")
            for method in route.methods:
                seen += 1
                client.cookies.update(cookies)
                if method != "GET":     # no header: refused whoever asks
                    assert client.request(method, path, json={}).status_code == 403, (method, path)
                client.cookies.clear()
                r = client.request(method, path, json={}, headers=H)
                if route.path in public or route.path == "/api/logout":
                    assert r.status_code != 401, (method, path)
                elif route.path == "/api/login":
                    assert r.status_code == 422, (method, path)      # an empty body
                else:
                    assert r.status_code == 401, (method, path)
    finally:
        limiter._state.clear()
        client.cookies.clear()
        client.cookies.update(cookies)
    assert seen > 35


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
    assert client.put("/api/clients/alice/static-ip", json={"ip": "10.0.70.100"}, headers=H).status_code == 200
    assert (TMP / "staticclients" / "alice").read_text() == "ifconfig-push 10.0.70.100 255.255.255.0\n"
    # invalid, outside the subnet, the server itself, the dynamic pool, the guest range, taken by alice
    for ip in ("300.1.1.1", "10.0.70.07", "10.0.71.9", "10.0.70.1", "10.0.70.50", "10.0.70.140", "10.0.70.100"):
        r = client.put("/api/clients/old/static-ip", json={"ip": ip}, headers=H)
        assert r.status_code == 400, ip
    assert "alice" in r.json()["detail"]
    row = client.get("/api/clients/alice").json()
    assert row["note"] == "laptop" and row["static_ip"] == "10.0.70.100" and row["guest"] is False
    # a static IP left over from 1.1 (separate guest subnet) is flagged on the dashboard
    (TMP / "staticclients" / "alice").write_text("ifconfig-push 10.0.71.9 255.255.255.0\n")
    assert any("alice (10.0.71.9)" in w for w in client.get("/api/overview").json()["warnings"])
    (TMP / "staticclients" / "alice").unlink()
    r = client.post("/api/clients", json={"name": "old"}, headers=H)
    assert r.status_code == 409 and "renew" in r.json()["detail"]
    conf = client.get("/api/server/config/server").json()["content"]
    r = client.put("/api/server/config/server", json={"content": conf.replace("management ", "#management ")}, headers=H)
    assert r.status_code == 400
    assert client.get("/api/server/config/nope").status_code == 400
    # a mistyped network in server.conf is reported by OpenVPN, not by a broken dashboard
    (TMP / "server.conf").write_text(conf.replace("server 10.0.70.0 255.255.255.0", "server 10.0.70.0 255.255.300.0"))
    assert client.get("/api/overview").status_code == 200
    assert client.put("/api/clients/alice/static-ip", json={"ip": "10.0.70.100"}, headers=H).status_code == 200
    (TMP / "staticclients" / "alice").unlink()
    (TMP / "server.conf").write_text(conf)
    s = client.get("/api/server").json()
    assert s["pki"]["ca"]["cn"] == "Test CA" and s["pki"]["crl"]["revoked"] == 1 and s["listen"] == [UDP, TCP]
    assert client.post("/api/server/restart", headers=H).status_code == 503   # no OpenVPN here
    events = client.get("/api/events").json()["events"]
    assert {"login", "client_deleted", "profile_downloaded", "remote_changed", "static_ip_set"} <= {e["kind"] for e in events}


def test_config_editor_refuses_lines_that_run_programs(client):
    def save(which, content):
        return client.put(f"/api/server/config/{which}", json={"content": content}, headers=H)

    conf = client.get("/api/server/config/server").json()["content"]
    assert "client-connect /opt/app/bin/client-access.sh" in conf and save("server", conf).status_code == 200
    for line in ("up /tmp/x.sh", "--up /tmp/x.sh", '"up" /tmp/x.sh', "u\\p /tmp/x.sh", "plugin /tmp/x.so",
                 "script-security 3", "log-append /etc/openvpn/fw-rules.sh", "setenv PATH /tmp",
                 "setenv opt up /tmp/x.sh", "client-connect /tmp/x.sh", "config /tmp/other.conf",
                 "dns-updown /tmp/x.sh", "tls-crypt-v2-verify /tmp/x.sh", "providers /tmp/x", "engine /tmp/x.so",
                 # the ways OpenVPN's parser reads an option name that a naive split does not
                 '"up"/tmp/x.sh', "'log'/tmp/x", '"plugin""/tmp/x.so"', "\\ up /tmp/x.sh", "\\\tscript-security 3",
                 "\tup\t/tmp/x.sh", "<up>"):
        r = save("server", conf + line + "\n")
        assert r.status_code == 400 and "cannot be added" in r.json()["detail"], line
    # a byte order mark before the first line, a line long enough for OpenVPN to read its end as a
    # line of its own, control characters
    assert save("server", "\ufeffup /tmp/x.sh\n" + conf).status_code == 400
    assert "longer than" in save("server", conf + "# " + "x" * 254 + "up /tmp/x.sh\n").json()["detail"]
    for text in ("verb 3\x00up /tmp/x.sh", "\x1fup /tmp/x.sh", "verb 3\rup /tmp/x.sh"):
        assert save("server", conf + text + "\n").status_code == 400, text
    assert save("server", conf.replace("\n", "\r\n")).status_code == 200      # a Windows clipboard
    # changing such a line counts as adding one; so does bringing one in as a comment first
    assert save("server", conf.replace("client-connect /opt/app/bin/client-access.sh", "client-connect /tmp/x.sh")).status_code == 400
    assert save("server", conf.replace("status /var/log/openvpn/openvpn-status.log 5", "status /etc/passwd 5")).status_code == 400
    assert save("server", conf + "#up /tmp/x.sh\n").status_code == 200
    assert save("server", conf + "up /tmp/x.sh\n").status_code == 400
    # ordinary options, and the 2FA switch the file documents, are saved
    r = save("server", conf.replace("#auth-user-pass-verify", "auth-user-pass-verify") + "push \"route 10.9.0.0 255.255.255.0\"\n")
    assert r.status_code == 200, r.text
    assert save("server", conf).status_code == 200
    assert (TMP / "server.conf").read_text() == conf

    # client profiles run on other people's devices
    profile = client.get("/api/server/config/client").json()["content"]
    assert save("client", profile + "script-security 2\nup /tmp/x.sh\n").status_code == 400
    assert save("client", profile + "mssfix 1300\n").status_code == 200
    assert save("client", profile).status_code == 200

    # easy-rsa runs its vars file as a shell script
    vars_file = client.get("/api/server/config/vars").json()["content"]
    for line in ("touch /tmp/x", 'set_var EASYRSA_REQ_CN "$(id)"', "set_var EASYRSA_REQ_CN `id`", "set_var PATH /tmp",
                 "set_var EASYRSA_CERT_EXPIRE 1; id", 'set_var EASYRSA_REQ_OU "a"#;touch /tmp/x',
                 "set_var EASYRSA_REQ_OU a#;touch /tmp/x", 'set_var EASYRSA_OPENSSL "/bin/sh"',
                 "set_var EASYRSA_PKI /tmp/pki"):
        assert save("vars", vars_file + line + "\n").status_code == 400, line
    assert save("vars", vars_file + 'set_var EASYRSA_CERT_EXPIRE 400\nset_var EASYRSA_REQ_ORG "My Org"  # ; a comment\n'
                '# note\n').status_code == 200
    (TMP / "config" / "easy-rsa.vars").unlink()      # no pki/vars here: the editor wrote the template


def test_guests_get_addresses_per_device(client):
    from app import pki
    # guests are a marker, not a static IP
    r = client.post("/api/clients", json={"name": "carol", "guest": True, "static_ip": "10.0.70.140"}, headers=H)
    assert r.status_code == 400 and "guest range" in r.json()["detail"]
    r = client.put("/api/clients/alice/access", json={"guest": True}, headers=H)
    assert r.status_code == 200 and (TMP / "guests" / "alice").exists()
    assert client.get("/api/clients/alice").json()["guest"] is True
    assert client.put("/api/clients/alice/static-ip", json={"ip": "10.0.70.101"}, headers=H).status_code == 400
    assert client.put("/api/clients/alice/access", json={"guest": False}, headers=H).status_code == 200
    assert not (TMP / "guests" / "alice").exists()
    # 1.3 guests (a static IP in the guest range) become guests with per-device addresses
    (TMP / "staticclients" / "alice").write_text("ifconfig-push 10.0.70.129 255.255.255.0\n")
    assert pki.migrate_guest_static_ips() == ["alice"]
    assert (TMP / "guests" / "alice").exists() and not (TMP / "staticclients" / "alice").exists()
    pki.set_guest("alice", False)


def test_share_link_is_single_use(client):
    r = client.post("/api/clients/alice/share", json={"hours": 2}, headers=H)
    assert r.status_code == 200, r.text
    link = r.json()
    assert link["import_url"] == "openvpn://import-profile/" + link["url"] + "/download" and "<svg" in link["qr_svg"]
    path = "/p/" + link["url"].rsplit("/p/", 1)[1]
    cookies = dict(client.cookies)
    client.cookies.clear()                       # the link works without a session
    try:
        # the link itself is a page offering the profile: a messenger's preview does not use it up
        for _ in range(3):
            r = client.get(path)
            assert r.status_code == 200 and r.headers["content-type"].startswith("text/html")
            assert "<cert>" not in r.text and "alice" not in r.text
            assert f'href="{link["url"]}/download"' in r.text and f'href="{link["import_url"]}"' in r.text
            assert "script-src" not in r.headers["content-security-policy"] and r.headers["cache-control"] == "no-store"
        # a profile that cannot be built leaves the link usable
        from app import pki
        build = pki.build_profile
        pki.build_profile = lambda name: (_ for _ in ()).throw(pki.PkiError("no disk space"))
        try:
            assert client.get(path + "/download").status_code == 400
        finally:
            pki.build_profile = build
        r = client.get(path + "/download")
        assert r.status_code == 200 and "<cert>" in r.text and r.headers["cache-control"] == "no-store"
        assert 'filename="alice.ovpn"' in r.headers["content-disposition"]
        assert client.get(path + "/download").status_code == 404        # used
        assert client.get(path).status_code == 404
        assert client.get("/p/not-a-token").status_code == 404
    finally:
        from app.main import limiter
        limiter._state.clear()
        client.cookies.update(cookies)
    assert client.post("/api/clients/old/share", json={}, headers=H).status_code == 400   # expired cert
    assert any(e["kind"] == "profile_link_used" for e in client.get("/api/events").json()["events"])


def test_rejected_attempts_from_the_logs(client):
    from app.main import collector
    (TMP / "log" / "openvpn.log").write_text(
        "2026-09-26 17:04:27 udp4:194.55.141.10:54333 VERIFY ERROR: depth=0, error=certificate revoked: C=UA, "
        "CN=Ian_pile_experimental, emailAddress=sweet@home.net, serial=1656\n"
        "2026-09-26 17:05:02 udp4:194.55.141.10:49920 VERIFY ERROR: depth=0, error=certificate revoked: C=UA, "
        "CN=Ian_pile_experimental, emailAddress=sweet@home.net, serial=1656\n"
        "2026-09-26 17:06:00 TLS Error: tls-crypt unwrapping failed from [AF_INET]45.1.2.3:1234\n"
        "2026-09-26 17:06:30 TLS Error: could not determine wrapping from [AF_INET]45.1.2.3:1235\n"
        "2026-09-26 17:06:40 client-access: refused cn='alice' from='5.6.7.9' reason=too-many-devices\n"
        "2026-09-26 17:07:00 MANAGEMENT: CMD 'version'\npartial line without newline")
    (TMP / "log" / "oath.log").write_text(
        "2026-09-26 17:08:00 2FA FAIL user='alice' cn='alice' from='5.6.7.8' reason=wrong-code\n")
    collector.read_logs()
    collector.read_logs()                        # nothing new: nothing counted twice
    rows = {(r["client"], r["reason"]): r for r in collector.db.rejections(0)}
    assert rows[("Ian_pile_experimental", "certificate revoked")]["count"] == 2
    assert rows[("Ian_pile_experimental", "certificate revoked")]["address"] == "194.55.141.10"
    assert rows[("", "unknown control channel key")]["address"] == "45.1.2.3"
    assert rows[("", "unknown control channel key")]["count"] == 2      # shared key and tls-crypt-v2 wording
    assert rows[("alice", "2FA: wrong code")]["address"] == "5.6.7.8"
    assert rows[("alice", "too many devices")]["address"] == "5.6.7.9"
    assert [r["reason"] for r in client.get("/api/clients/alice").json()["rejections"]] == ["2FA: wrong code", "too many devices"]


def test_new_certificate_under_an_old_name_starts_a_new_history(client):
    from app.main import db
    with db.tx() as conn:
        conn.execute("INSERT INTO vpn_sessions (client_name, cid, connected_at, last_seen, bytes_in, bytes_out) "
                     "VALUES ('dora', 1, 100, 200, 5, 6)")
        db.add_traffic(conn, 120, "dora", 5, 6)
    key = db.archive_client_history("dora")
    assert key and key.startswith("dora#")
    assert db.totals(0, 10**10, "dora") == (0, 0) and db.totals(0, 10**10, key) == (5, 6)
    assert db.one("SELECT client_name FROM vpn_sessions WHERE cid = 1")["client_name"] == key
    assert db.archive_client_history("dora") is None       # nothing left to archive
    # only history before a given time, used to split data merged by earlier releases
    with db.tx() as conn:
        db.add_traffic(conn, 1000, "erin", 1, 1)
        db.add_traffic(conn, 5000, "erin", 2, 2)
    db.archive_client_history("erin", before=3000)
    assert db.totals(0, 10**10, "erin") == (2, 2)


def test_identity_start_tells_renewals_from_new_certificates(client):
    from app import pki
    p = TMP / "pki"
    # frank: renewed, so the same key signed twice -> history goes back to the first certificate
    issue(p, "frank", "client", "20260101000000Z", "20360101000000Z")
    (p / "renewed" / "issued").mkdir(parents=True, exist_ok=True)
    shutil.move(p / "issued" / "frank.crt", p / "renewed" / "issued" / "frank.crt")
    ossl("ca", "-batch", "-config", str(p / "ca.cnf"), "-extensions", "client", "-startdate", "20260601000000Z",
         "-enddate", "20360101000000Z", "-in", str(p / "reqs" / "frank.req"), "-out", str(p / "issued" / "frank.crt"),
         "-notext")
    assert pki.identity_start("frank") == pki.parse_asn1_time("20260101000000Z")
    # bob: revoked earlier, then created again with a new key -> a new client from the new certificate on
    issue(p, "bob", "client", "20260701000000Z", "20360101000000Z")
    assert pki.identity_start("bob") == pki.parse_asn1_time("20260701000000Z")


def test_visits_and_connection_quality(client):
    from app.main import db
    now = int(__import__("time").time())
    with db.tx() as conn:
        for i, (start, reason) in enumerate([(now - 300, "left"), (now - 200, "left"), (now - 100, "timed out")]):
            db.insert_session(conn, "alice", f"udp4:203.0.113.5:{5000 + i}", start, last_seen=start + 30,
                              disconnected_at=start + 30, end_reason=reason, platform="ios", client_ver="3.11.1")
    raw = client.get("/api/sessions?name=alice").json()
    assert raw["total"] == 3 and raw["sessions"][0]["end_reason"] == "timed out"
    merged = client.get("/api/sessions?name=alice&merge=true").json()
    assert merged["total"] == 1 and merged["sessions"][0]["connections"] == 3
    assert merged["sessions"][0]["online_seconds"] == 90 and merged["sessions"][0]["platform"] == "ios"
    assert client.get("/api/sessions?name=alice&merge=true&active=true").json()["total"] == 0
    assert client.get("/api/clients/alice").json()["sessions"][0]["connections"] == 3
    stats = {c["name"]: c for c in client.get("/api/connections?range=24h").json()["clients"]}
    assert (stats["alice"]["sessions"], stats["alice"]["left"], stats["alice"]["timed_out"]) == (3, 2, 1)
    assert stats["alice"]["median_seconds"] == 30 and stats["alice"]["short"] == 3
    assert client.get("/api/connections?range=bogus").status_code == 400


def test_backup_archive(client):
    import sqlite3
    import tarfile
    from app import backup
    from app.settings import settings
    assert client.get("/api/server").json()["backup"]["last"] is None
    r = client.post("/api/server/backup", headers=H)
    assert r.status_code == 200, r.text
    st = r.json()["backup"]
    assert st["count"] == 1 and st["last"] and st["size"] > 1000 and st["enabled"] is True
    archive = backup.archives()[0]
    assert archive.stat().st_mode & 0o777 == 0o600 and archive.parent.stat().st_mode & 0o777 == 0o700
    with tarfile.open(archive) as tar:
        names = set(tar.getnames())
        assert {"server.conf", "pki/ca.crt", "pki/private/ca.key", "clients/oath.secrets", "config/client.conf",
                "db/openvpn-ui.db"} <= names
        assert not any(n.startswith(("backups", "log")) or "-wal" in n for n in names)
        tar.extract("db/openvpn-ui.db", TMP / "restored", filter="data")
    copy = sqlite3.connect(TMP / "restored" / "db" / "openvpn-ui.db")
    assert copy.execute("SELECT username FROM users").fetchone() == ("admin",)
    assert copy.execute("SELECT COUNT(*) FROM vpn_sessions WHERE client_name = 'alice'").fetchone() == (3,)
    copy.close()
    assert backup.ensure_recent() is None                    # one a day is enough
    assert list(archive.parent.glob(".*")) == []             # no snapshot or partial file left behind
    # only the newest archives are kept
    for stamp in ("20200101-000000", "20200102-000000", "20200103-000000"):
        (archive.parent / f"openvpn-backup-{stamp}.tar.gz").write_bytes(b"old")
    settings.backup_keep = 2
    try:
        archive.unlink()
        new = backup.create()
        assert [a.name for a in backup.archives()] == ["openvpn-backup-20200103-000000.tar.gz", new.name]
    finally:
        settings.backup_keep = 14
    assert any(e["kind"] == "backup_created" for e in client.get("/api/events").json()["events"])


def test_backup_archive_encrypted(client, monkeypatch, tmp_path):
    from app import backup
    from app.settings import settings
    # A stand-in for age (the real one runs in the end-to-end test): marks its output, fails on request.
    fake = tmp_path / "age"
    fake.write_text('#!/bin/sh\n[ "$1" = -r ] || exit 2\n[ -e "$FAIL" ] && { echo "age: no" >&2; exit 1; }\n'
                    'printf "sealed for %s\\n" "$2"; cat\n')
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    monkeypatch.setenv("FAIL", str(tmp_path / "fail"))
    key = "age1" + "q" * 58
    before = {a.name for a in backup.archives()}
    monkeypatch.setattr(settings, "backup_recipient", key)
    new = backup.create()
    assert new.name.endswith(".tar.gz.age") and new.stat().st_mode & 0o777 == 0o600
    head, _, rest = new.read_bytes().partition(b"\n")
    assert head == f"sealed for {key}".encode() and rest[:2] == b"\x1f\x8b"       # the gzip stream went through age
    assert client.get("/api/server").json()["backup"]["encrypted"] is True
    # a failing age or a recipient that is not a key: an error, never an unencrypted archive
    (tmp_path / "fail").touch()
    r = client.post("/api/server/backup", headers=H)
    assert r.status_code == 500 and "age: no" in r.json()["detail"]
    monkeypatch.setattr(settings, "backup_recipient", "not-a-key")
    assert client.post("/api/server/backup", headers=H).status_code == 500
    assert {a.name for a in backup.archives()} == before | {new.name}
    assert list(new.parent.glob(".*")) == []
    new.unlink()


def test_health_reports_a_dead_collector(client, monkeypatch):
    from app.main import collector
    assert client.get("/healthz").status_code == 200
    monkeypatch.setattr(collector, "alive", lambda: False)
    assert client.get("/healthz").status_code == 503


def test_page_asks_for_the_assets_of_this_version(client):
    from app import __version__
    html = client.get("/").text
    assert f'/static/app.js?v={__version__}"' in html and f'/static/app.css?v={__version__}"' in html
    assert client.get(f"/static/app.js?v={__version__}").status_code == 200
