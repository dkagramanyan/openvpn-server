#!/usr/bin/env python3
"""Exercise built UI, relay, signer and real Traefik containers in an isolated network.

Run with UI test dependencies installed after building the three :relay-test images.
Every identity and credential is temporary; no production keys or Docker ports are used.
"""
import http.cookiejar
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
from urllib.error import HTTPError
from urllib.request import build_opener, HTTPCookieProcessor, ProxyHandler, Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ui/tests"))
from test_profile_signing import make_identity, write_store


def command(*args, data=None, env=None):
    result = subprocess.run(args, input=data, capture_output=True, env=env)
    if result.returncode:
        # Never include argv: curl headers and environment can contain test credentials.
        raise RuntimeError(f"{args[0]} failed ({result.returncode}): {result.stderr.decode(errors='replace')[-1500:]}")
    return result.stdout.decode().strip()


def check_browser(api_url, portal_url, admin_password, folder):
    from playwright.sync_api import sync_playwright
    portal_password = secrets.token_hex(16)
    errors = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=os.environ.get("CHROME_BIN", "/usr/bin/google-chrome"), headless=True)
        admin = browser.new_page(viewport={"width": 1440, "height": 1000}, accept_downloads=True)
        admin.on("pageerror", lambda error: errors.append(str(error)))
        admin.goto(api_url)
        admin.locator('input[name=username]').fill("admin")
        admin.locator('input[type=password]').fill(admin_password)
        admin.get_by_role("button", name="Sign in", exact=True).click()
        admin.get_by_role("link", name="Relay", exact=True).click()
        admin.get_by_text("Signed downloads enabled", exact=True).wait_for()
        admin.get_by_role("heading", name="Relay activity", exact=True).wait_for()
        assert admin.get_by_label("Shared signing token", exact=True).input_value() == ""
        admin.get_by_role("button", name="Save signing settings", exact=True).click()
        admin.get_by_text("Signing settings saved", exact=True).wait_for()
        # Open the grouped user row; detail rows keep their destination filter.
        admin.locator('details summary').filter(has_text='alice').first.click()
        admin.get_by_text("Signed downloads enabled", exact=True).wait_for()
        admin.screenshot(path="/tmp/ovpn-relay-activity.png", full_page=True)
        admin.goto(api_url + "/#/clients/alice")
        admin.get_by_role("button", name="Portal access", exact=True).click()
        admin.get_by_label("Portal username", exact=True).fill("alice-portal")
        admin.get_by_label("Portal password", exact=True).fill(portal_password)
        admin.get_by_role("button", name="Save login", exact=True).click()
        admin.get_by_text("Portal login saved", exact=True).wait_for()
        # The fixture CA is verified by curl/OpenSSL below; it is not installed
        # into Chrome's global trust store on the developer/CI machine.
        context = browser.new_context(accept_downloads=True, ignore_https_errors=True, viewport={"width": 390, "height": 844})
        user = context.new_page()
        user.on("pageerror", lambda error: errors.append(str(error)))
        user.goto(portal_url + "/portal")
        user.locator('input[name=username]').fill("alice-portal")
        user.locator('input[type=password]').fill(portal_password)
        user.get_by_role("button", name="Sign in", exact=True).click()
        user.get_by_role("heading", name="My profiles", exact=True).wait_for()
        user.get_by_role("heading", name="My relay activity", exact=True).wait_for()
        personal = user.evaluate("fetch('/api/portal/relay/status').then(r => r.json())")
        assert all(row["client"] == "alice" for key in ("clients","active","events") for row in personal[key])
        assert personal["clients"][0]["active"] > 0 and personal["clients"][0]["bytes_down"] > 0
        user.get_by_role("link", name="OpenVPN config", exact=True).wait_for()
        assert user.locator('a[href="#/server"]').count() == 0
        with user.expect_download() as download:
            user.get_by_role("link", name="OpenVPN config", exact=True).click()
        assert download.value.suggested_filename == "alice.ovpn"
        with user.expect_download() as download:
            user.get_by_role("button", name="Apple relay", exact=True).click()
        assert download.value.suggested_filename == "alice-relay.mobileconfig"
        verify_env = {**os.environ, "SSL_CERT_FILE": str(folder / "identity/ca.pem")}
        content = Path(download.value.path()).read_bytes()
        verified = command("openssl", "cms", "-verify", "-binary", "-inform", "DER", "-purpose", "any", data=content, env=verify_env)
        assert "alice" in plistlib.loads(verified.encode())["PayloadDisplayName"]
        assert user.evaluate("fetch('/api/server').then(r => r.status)") == 404
        user.screenshot(path="/tmp/ovpn-user-portal.png", full_page=True)
        admin.get_by_role("button", name="Portal access", exact=True).click()
        admin.get_by_role("button", name="Disable access", exact=True).click()
        admin.get_by_text("Portal access disabled", exact=True).wait_for()
        assert user.evaluate("fetch('/api/portal').then(r => r.status)") == 401
        assert not errors, errors
        browser.close()
    print("PASS: browser shows relay activity and signing; admin creates portal login; user downloads both configs; disabling access invalidates session")


def main():
    prefix = "ovpn-relay-test-" + secrets.token_hex(4)
    folder = Path(tempfile.mkdtemp(prefix=prefix))
    containers = []
    fixture = None
    stream = None
    password, signing_token = secrets.token_hex(24), secrets.token_hex(32)
    network = prefix

    def run(name, *args):
        full_name = prefix + "-" + name
        command("docker", "run", "-d", "--name", full_name, "--network", network,
                "--ip", str(next(addresses)), "--network-alias", name, *args)
        containers.append(full_name)
        return full_name

    def published(name, port):
        result = command("docker", "port", name, str(port) + "/tcp")
        return result.splitlines()[0].rsplit(":", 1)[1]

    try:
        entry = make_identity(folder / "identity")
        write_store(folder / "acme.json", entry)
        command("docker", "network", "create", network)
        # Production uses stable host/LAN addresses. Keep fixture addresses
        # stable too when Docker releases and reattaches bridge endpoints.
        subnet = json.loads(command("docker", "network", "inspect", network))[0]["IPAM"]["Config"][0]["Subnet"]
        addresses = iter(ipaddress.ip_network(subnet).hosts())
        next(addresses)  # Docker gateway.
        pg_password = secrets.token_urlsafe(24)
        app_password, policy_password = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        postgres = run("postgres", "-p", "127.0.0.1::5432", "-e", "POSTGRES_PASSWORD=" + pg_password,
                       "-e", "POSTGRES_DB=openvpn", "-e", "OPENVPN_DB_PASSWORD=" + app_password,
                       "-e", "RELAY_POLICY_DB_PASSWORD=" + policy_password,
                       "-v", f"{ROOT}/postgres/00-roles.sh:/docker-entrypoint-initdb.d/00-roles.sh:ro", "postgres:18.6-alpine")
        for _ in range(60):
            if subprocess.run(["docker", "exec", postgres, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "openvpn"], capture_output=True).returncode == 0:
                break
            time.sleep(1)
        else: raise RuntimeError("PostgreSQL did not become ready")
        # Host fixtures and production containers use the actual restricted app role.
        os.environ["OVPN_DATABASE_URL"] = "postgresql://openvpn:" + app_password + "@127.0.0.1:" + published(postgres, 5432) + "/openvpn"
        import test_api as fixture
        container_dsn = "postgresql://openvpn:" + app_password + "@postgres/openvpn"
        policy_dsn = "postgresql://relay_policy:" + policy_password + "@postgres/openvpn"
        relay = run("relay", "-p", "127.0.0.1::8080", "-e", "RELAY_TRUSTED_PROXIES=" + subnet,
                    "openvpn-apple-relay:relay-test")
        (folder / "dynamic.yml").write_text('''tcp:
  routers:
    relay:
      entryPoints: [relay]
      rule: "HostSNI(`localhost`)"
      service: relay
      tls:
        options: relay-h2
  services:
    relay:
      loadBalancer:
        servers:
          - address: "relay:8444"
http:
  routers:
    portal:
      entryPoints: [websecure]
      rule: "Host(`localhost`) && (Path(`/portal`) || Path(`/api/portal`) || PathPrefix(`/api/portal/`) || PathPrefix(`/static/`))"
      service: ui
      tls: {}
    signer:
      entryPoints: [websecure]
      rule: "Host(`traefik`) && Path(`/internal/relay-sign`)"
      service: signer
      tls: {}
  services:
    ui:
      loadBalancer:
        servers:
          - url: "http://relay:8080"
    signer:
      loadBalancer:
        servers:
          - url: "http://signer:8085"
tls:
  options:
    relay-h2:
      alpnProtocols: [h2]
  certificates:
    - certFile: /fixture/identity/fullchain.pem
      keyFile: /fixture/identity/key.pem
''')
        proxy = run("traefik", "-p", "127.0.0.1::8443", "-p", "127.0.0.1::443", "-v", f"{folder}:/fixture:ro", "traefik:v3.7.15",
                    "--entrypoints.relay.address=:8443", "--entrypoints.websecure.address=:443",
                    "--providers.file.filename=/fixture/dynamic.yml", "--log.level=ERROR")
        origin = "https://localhost:" + published(proxy, 8443)
        portal_url = "https://localhost:" + published(proxy, 443)
        run("signer", "-v", f"{folder}:/fixture:ro", "-e", "PROFILE_SIGNER_ACME=/fixture/acme.json",
            "-e", "SSL_CERT_FILE=/fixture/identity/ca.pem", "-e", "PROFILE_SIGNER_HOSTNAME=localhost",
            "-e", "PROFILE_SIGNER_RELAY_URL=" + origin, "-e", "PROFILE_SIGNER_TOKEN=" + signing_token,
            "openvpn-profile-signer:relay-test")
        # UI and relay share a network namespace, matching production host networking.
        ui_name = prefix + "-ui"
        command("docker", "run", "-d", "--name", ui_name, "--restart", "unless-stopped", "--network", "container:" + relay,
                "-v", f"{fixture.TMP}:/etc/openvpn", "-v", f"{folder}:/fixture:ro",
                "-e", "SSL_CERT_FILE=/fixture/identity/ca.pem", "-e", "MGMT_PORT=1", "-e", "OVPN_BACKUP_KEEP=0",
                "-e", "OVPN_DATABASE_URL=" + container_dsn, "-e", "OPENVPN_ADMIN_PASSWORD=" + password, "openvpn-ui:relay-test")
        containers.append(ui_name)
        api_url = "http://127.0.0.1:" + published(relay, 8080)
        client = build_opener(ProxyHandler({}), HTTPCookieProcessor(http.cookiejar.CookieJar()))

        def api(path, body=None, method=None):
            request = Request(api_url + path, data=json.dumps(body).encode() if body is not None else None,
                              headers={"Content-Type": "application/json", "X-Requested-With": "fetch"}, method=method)
            with client.open(request, timeout=15) as response:
                return response.read()

        for _ in range(60):
            try:
                api("/api/login", {"username": "admin", "password": password})
                break
            except Exception:
                time.sleep(1)
        else:
            raise RuntimeError("UI did not become ready")
        policy_name = prefix + "-policy"
        command("docker", "run", "-d", "--name", policy_name, "--restart", "unless-stopped", "--network", "container:" + relay,
                "-v", f"{fixture.TMP}/pki:/etc/openvpn/pki:ro", "-v", f"{fixture.TMP}/guests:/etc/openvpn/guests:ro",
                "-v", f"{fixture.TMP}/server.conf:/etc/openvpn/server.conf:ro",
                "--tmpfs", "/etc/openvpn/pki/private:mode=0700", "--tmpfs", "/etc/openvpn/pki/renewed:mode=0700",
                "--tmpfs", "/etc/openvpn/pki/revoked:mode=0700", "--read-only", "--tmpfs", "/tmp",
                "-e", "OVPN_DATABASE_URL=" + policy_dsn, "openvpn-ui:relay-test", "python", "-m", "app.policy_server")
        containers.append(policy_name)
        for _ in range(30):
            health = subprocess.run(["docker", "exec", relay, "wget", "-qO-", "http://127.0.0.1:8446/readyz"], capture_output=True)
            if health.returncode == 0: break
            time.sleep(1)
        else: raise RuntimeError("Independent policy service did not become ready")
        assert command("docker", "exec", policy_name, "sh", "-c", "test ! -e /etc/openvpn/pki/private/ca.key && echo hidden") == "hidden"
        # The policy role cannot read admin password hashes or change access.
        from app.db import connection_parameters
        import psycopg
        params = connection_parameters(os.environ["OVPN_DATABASE_URL"])
        with psycopg.connect(**{**params, "user": "relay_policy", "password": policy_password}, autocommit=True) as connection:
            assert connection.execute("SELECT count(*) FROM relay_policy_settings").fetchone() is not None
            for statement in ("SELECT * FROM users", "UPDATE settings SET value='bad'"):
                try: connection.execute(statement)
                except psycopg.Error: pass
                else: raise AssertionError("Policy role had excessive database permissions")
        api("/api/relay/settings", {"enabled": True, "url": origin, "allowed_cidrs": [subnet]}, "PUT")
        try:
            api("/api/clients/alice/relay.mobileconfig", {}, "POST")
        except HTTPError as exc:
            assert exc.code == 503 and not exc.read().startswith(b"<?xml")
        else: raise AssertionError("Unconfigured signer returned an unsigned download")
        status = json.loads(api("/api/relay/signing", {"url":"https://traefik/internal/relay-sign", "token":signing_token, "required":True}, "PUT"))
        assert status["ready"] and status["token_configured"], status
        assert signing_token not in json.dumps(status)
        signed = api("/api/clients/alice/relay.mobileconfig", {}, "POST")
        env = {**os.environ, "SSL_CERT_FILE": str(folder / "identity/ca.pem")}
        plain = command("openssl", "cms", "-verify", "-binary", "-inform", "DER", "-purpose", "any",
                        "-verify_hostname", "localhost", data=signed, env=env).encode()
        document = plistlib.loads(plain)
        token = document["PayloadContent"][0]["Relays"][0]["AdditionalHTTPHeaderFields"]["Authorization"]
        assert document["PayloadContent"][0]["MatchDomains"] == []
        headers = folder / "headers.txt"
        headers.write_text("Authorization: " + token + "\n"); headers.chmod(0o600)
        address = json.loads(command("docker", "inspect", relay))[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        curl = ["curl", "--silent", "--show-error", "--fail", "--proxytunnel", "--write-out", "%{http_connect}", "--max-time", "10", "--noproxy", "", "--proxy", origin,
                "--proxy-http2", "--proxy-cacert", str(folder / "identity/ca.pem"), "--proxy-header", "@" + str(headers)]
        page = command(*curl, "http://" + address + ":8080/")
        assert "OpenVPN" in page
        print("PASS: signed profile verified; real HTTP/2 CONNECT through Docker Traefik reaches LAN")
        # Reboot-style startup: policy/UI/relay come up before PostgreSQL. Use
        # only the already downloaded profile, never issue a replacement grant.
        original_grant = fixture.db.get_setting("relay_client:alice")
        original_instance = fixture.db.get_setting("relay_instance")
        command("docker", "stop", "-t", "5", ui_name, policy_name)
        command("docker", "stop", "-t", "5", relay, postgres)
        command("docker", "start", relay, policy_name, ui_name)
        readiness = subprocess.run(["docker", "exec", relay, "wget", "-qO-", "http://127.0.0.1:8446/readyz"], capture_output=True)
        assert readiness.returncode != 0, "Relay reported ready while persistent database was stopped"
        command("docker", "start", postgres)
        for _ in range(60):
            restored = subprocess.run([*curl, "http://" + address + ":8080/"], capture_output=True)
            if restored.returncode == 0 and b"OpenVPN" in restored.stdout:
                break
            time.sleep(0.5)
        else:
            raise AssertionError("Original installed profile did not recover after reboot-style startup")
        # Docker reallocates randomly published fixture ports on restart.
        # Production's fixed host ports do not change on reboot.
        api_url = "http://127.0.0.1:" + published(relay, 8080)
        restarted_dsn = "postgresql://openvpn:" + app_password + "@127.0.0.1:" + published(postgres, 5432) + "/openvpn"
        restarted_db = type(fixture.db)(restarted_dsn, schema=fixture.db.schema)
        assert restarted_db.get_setting("relay_client:alice") == original_grant
        assert restarted_db.get_setting("relay_instance") == original_instance
        print("PASS: original signed profile works after relay/UI/policy/database restart; credentials and identifiers persist; startup waits for database")
        api("/api/clients/alice/access", {"guest": True}, "PUT")
        time.sleep(2)  # The authorization cache expires after one second.
        denied = subprocess.run([*curl, "http://" + address + ":8080/"], capture_output=True)
        assert denied.returncode != 0
        activity = json.loads(api("/api/relay/status"))["events"]
        assert any(e["guest"] and e["kind"] == "denied" and e["reason"] == "destination_denied" for e in activity)
        internet = command(*curl, "https://example.com/")
        assert "Example Domain" in internet
        print("PASS: guest reaches public HTTPS internet while LAN access is denied")
        guest_signed = api("/api/clients/alice/relay.mobileconfig", {}, "POST")
        guest_xml = command("openssl", "cms", "-verify", "-binary", "-inform", "DER", "-purpose", "any", data=guest_signed, env=env)
        assert token == plistlib.loads(guest_xml.encode())["PayloadContent"][0]["Relays"][0]["AdditionalHTTPHeaderFields"]["Authorization"]
        api("/api/clients/alice/access", {"guest": False}, "PUT")
        time.sleep(2)
        assert "OpenVPN" in command(*curl, "http://" + address + ":8080/")
        runtime = json.loads(api("/api/relay/status"))
        assert runtime["total"] >= 2 and runtime["denied"] >= 1
        user_stats = next(row for row in runtime["clients"] if row["client"] == "alice")
        assert user_stats["accepted"] >= 2 and user_stats["denied"] >= 1 and user_stats["bytes_down"] > 0
        assert any(e["client"] == "alice" and e["kind"] == "closed" for e in runtime["events"])
        assert token not in json.dumps(runtime)
        public_check = ["curl", "--silent", "--show-error", "--max-time", "10", "--cacert", str(folder / "identity/ca.pem")]
        assert command(*public_check, portal_url + "/portal").startswith("<!doctype html>")
        assert command(*public_check, "--output", "/dev/null", "--write-out", "%{http_code}", portal_url + "/api/server") == "404"
        # UI maintenance must not interrupt relay authorization. Use the private
        # signer HTTP backend as a destination while the UI is stopped.
        signer_address = json.loads(command("docker", "inspect", prefix + "-signer"))[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        destination = "http://" + signer_address + ":8085/"
        (folder / "stream.py").write_text('''from http.server import BaseHTTPRequestHandler, HTTPServer
import time
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Length", "307200")
        self.end_headers()
        try:
            for _ in range(300):
                self.wfile.write(b"x" * 1024)
                self.wfile.flush()
                time.sleep(0.2)
        except (OSError, ConnectionError): pass
    def log_message(self, *args): pass
HTTPServer(("0.0.0.0", 8089), Handler).serve_forever()
''')
        streamer = run("streamer", "-v", f"{folder}:/fixture:ro", "--entrypoint", "python", "openvpn-ui:relay-test", "/fixture/stream.py")
        stream_address = json.loads(command("docker", "inspect", streamer))[0]["NetworkSettings"]["Networks"][network]["IPAddress"]
        for _ in range(30):
            probe = subprocess.run(["docker", "exec", streamer, "python", "-c", "import socket; socket.create_connection(('127.0.0.1',8089),timeout=1).close()"], capture_output=True)
            if probe.returncode == 0: break
            time.sleep(0.2)
        else: raise AssertionError("Stream destination did not start")
        progress = folder / "download"
        stream = subprocess.Popen([*curl, "--max-time", "90", "--output", str(progress), "http://" + stream_address + ":8089/"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        for _ in range(30):
            if progress.exists() and progress.stat().st_size > 0: break
            time.sleep(0.2)
        else: raise AssertionError("Long-lived CONNECT did not start")
        live = json.loads(api("/api/relay/status"))
        live_user = next(row for row in live["clients"] if row["client"] == "alice")
        assert live_user["active"] > 0 and live_user["bytes_down"] > user_stats["bytes_down"]
        if os.environ.get("RELAY_STACK_BROWSER"):
            check_browser(api_url, portal_url, password, folder)
        command("docker", "stop", "-t", "3", ui_name)
        time.sleep(2)
        before = progress.stat().st_size
        time.sleep(6)  # Exceeds live policy recheck interval.
        assert stream.poll() is None and progress.stat().st_size > before
        # Any response from the destination is sufficient; CONNECT must be 200.
        assert command(*[x for x in curl if x != "--fail"], destination).startswith("{}")
        metrics = command("docker", "exec", relay, "wget", "-qO-", "http://127.0.0.1:8446/metrics")
        assert "relay_authorization_checks_total" in metrics and token not in metrics and "alice" not in metrics
        # Independent policy sees role changes even while the UI is down.
        command("docker", "run", "--rm", "-v", f"{fixture.TMP}:/fixture", "--entrypoint", "sh", "openvpn-ui:relay-test", "-c", "touch /fixture/guests/alice")
        time.sleep(2)
        denied = subprocess.run([*curl, destination], capture_output=True)
        assert denied.returncode != 0
        stream.communicate(timeout=12)
        assert stream.returncode != 0, "Role downgrade did not terminate the active LAN flow"
        state = json.loads(command("docker", "exec", relay, "wget", "-qO-", "http://127.0.0.1:8446/status"))
        assert any(e["reason"] == "access_revoked" for e in state["events"])
        assert any(e["guest"] and e["reason"] == "destination_denied" and e["target"].endswith(":8085") for e in state["events"])
        command("docker", "run", "--rm", "-v", f"{fixture.TMP}:/fixture", "--entrypoint", "sh", "openvpn-ui:relay-test", "-c", "rm /fixture/guests/alice")
        time.sleep(2)
        assert command(*[x for x in curl if x != "--fail"], destination).startswith("{}")
        command("docker", "stop", "-t", "2", policy_name)
        time.sleep(2)
        unavailable = subprocess.run([*curl, destination], capture_output=True)
        assert unavailable.returncode != 0
        state = json.loads(command("docker", "exec", relay, "wget", "-qO-", "http://127.0.0.1:8446/status"))
        assert state["policy_ready"] is False
        assert any(e["reason"] == "authorization_unavailable" for e in state["events"])
        command("docker", "start", policy_name, ui_name)
        for _ in range(30):
            try:
                api("/api/login", {"username": "admin", "password": password})
                break
            except Exception: time.sleep(1)
        assert "OpenVPN" in command(*curl, "http://" + address + ":8080/")
        print("PASS: relay works during UI outage; live role changes apply; policy outage returns retryable 503; policy cannot read admin data or keys")
        restarts = json.loads(command("docker", "inspect", policy_name))[0]["RestartCount"]
        config = json.loads(api("/api/server/config/server"))["content"]
        api("/api/server/config/server", {"content": config + "\n# Policy mount refresh test\n"}, "PUT")
        assert "OpenVPN" in command(*curl, "http://" + address + ":8080/")
        # The UI deliberately writes in place. Editors/git-style replacements
        # can unlink the bound inode: exercise that separate deployment case.
        command("docker", "run", "--rm", "-v", f"{fixture.TMP}:/fixture", "--entrypoint", "python", "openvpn-ui:relay-test",
                "-c", "from pathlib import Path; p=Path('/fixture/server.conf'); t=p.with_suffix('.new'); t.write_bytes(p.read_bytes()); t.replace(p)")
        for _ in range(40):
            restarted = json.loads(command("docker", "inspect", policy_name))[0]["RestartCount"] > restarts
            health = subprocess.run(["docker", "exec", relay, "wget", "-qO-", "http://127.0.0.1:8446/readyz"], capture_output=True)
            if restarted and health.returncode == 0: break
            time.sleep(0.5)
        else: raise AssertionError("Policy did not refresh the atomically replaced server configuration")
        assert "OpenVPN" in command(*curl, "http://" + address + ":8080/")
        print("PASS: UI config saves keep relay access; external atomic replacement refreshes the policy mount automatically")
        api("/api/clients/alice/relay", method="DELETE")
        time.sleep(2)
        denied = subprocess.run([*curl, "http://" + address + ":8080/"], capture_output=True)
        assert denied.returncode != 0
        assert any(e["reason"] == "authorization_denied" for e in json.loads(api("/api/relay/status"))["events"])
        print("PASS: same profile follows guest/full-access changes, logs are visible in UI API, revoked access is denied")
    except Exception:
        for name in containers:
            logs = subprocess.run(["docker", "logs", "--tail=15", name], capture_output=True)
            print(name + ": " + (logs.stdout + logs.stderr).decode(errors="replace"), file=sys.stderr)
        raise
    finally:
        if stream is not None and stream.poll() is None:
            stream.kill()
            stream.communicate()
        if containers:
            subprocess.run(["docker", "rm", "-f", *reversed(containers)], capture_output=True)
        subprocess.run(["docker", "network", "rm", network], capture_output=True)
        shutil.rmtree(folder, ignore_errors=True)
        if fixture is not None:
            # Only the synthetic fixture: Docker created root-owned PKI directories.
            subprocess.run(["docker", "run", "--rm", "-v", f"{fixture.TMP}:/fixture", "--entrypoint", "sh",
                            "openvpn-ui:relay-test", "-c", f"chown -R {os.getuid()}:{os.getgid()} /fixture"], capture_output=True)
            shutil.rmtree(fixture.TMP, ignore_errors=True)


if __name__ == "__main__":
    main()
