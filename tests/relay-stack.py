#!/usr/bin/env python3
"""Exercise built UI, relay, signer and real Traefik containers in an isolated network.

Run with UI test dependencies installed after building the three :relay-test images.
Every identity and credential is temporary; no production keys or Docker ports are used.
"""
import http.cookiejar
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
from urllib.request import build_opener, HTTPCookieProcessor, ProxyHandler, Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "ui/tests"))
import test_api as fixture
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
    password, signing_token = secrets.token_hex(24), secrets.token_hex(32)
    network = prefix

    def run(name, *args):
        full_name = prefix + "-" + name
        command("docker", "run", "-d", "--name", full_name, "--network", network, "--network-alias", name, *args)
        containers.append(full_name)
        return full_name

    def published(name, port):
        result = command("docker", "port", name, str(port) + "/tcp")
        return result.splitlines()[0].rsplit(":", 1)[1]

    try:
        entry = make_identity(folder / "identity")
        write_store(folder / "acme.json", entry)
        command("docker", "network", "create", network)
        subnet = json.loads(command("docker", "network", "inspect", network))[0]["IPAM"]["Config"][0]["Subnet"]
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
        command("docker", "run", "-d", "--name", ui_name, "--network", "container:" + relay,
                "-v", f"{fixture.TMP}:/etc/openvpn", "-v", f"{folder}:/fixture:ro",
                "-e", "SSL_CERT_FILE=/fixture/identity/ca.pem", "-e", "MGMT_PORT=1", "-e", "OVPN_BACKUP_KEEP=0",
                "-e", "OPENVPN_ADMIN_PASSWORD=" + password, "-e", "OVPN_RELAY_SIGNER_URL=https://traefik/internal/relay-sign",
                "-e", "RELAY_PROFILE_SIGNING_TOKEN=" + signing_token, "openvpn-ui:relay-test")
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
        api("/api/relay/settings", {"enabled": True, "url": origin, "allowed_cidrs": [subnet]}, "PUT")
        status = json.loads(api("/api/relay/signing"))
        assert status["ready"], status
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
        api("/api/clients/alice/access", {"guest": True}, "PUT")
        time.sleep(2)  # The authorization cache expires after one second.
        denied = subprocess.run([*curl, "http://" + address + ":8080/"], capture_output=True)
        assert denied.returncode != 0
        activity = json.loads(api("/api/relay/status"))["events"]
        assert any(e["guest"] and e["kind"] == "denied" and e["reason"] == "destination_denied_or_dns_failed" for e in activity)
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
        assert any(e["client"] == "alice" and e["kind"] == "closed" for e in runtime["events"])
        assert token not in json.dumps(runtime)
        public_check = ["curl", "--silent", "--show-error", "--max-time", "10", "--cacert", str(folder / "identity/ca.pem")]
        assert command(*public_check, portal_url + "/portal").startswith("<!doctype html>")
        assert command(*public_check, "--output", "/dev/null", "--write-out", "%{http_code}", portal_url + "/api/server") == "404"
        if os.environ.get("RELAY_STACK_BROWSER"):
            check_browser(api_url, portal_url, password, folder)
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
        if containers:
            subprocess.run(["docker", "rm", "-f", *reversed(containers)], capture_output=True)
        subprocess.run(["docker", "network", "rm", network], capture_output=True)
        shutil.rmtree(folder, ignore_errors=True)
        shutil.rmtree(fixture.TMP, ignore_errors=True)


if __name__ == "__main__":
    main()
