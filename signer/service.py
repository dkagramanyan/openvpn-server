"""Private CMS signer for Apple relay profiles, using Traefik's ACME identity."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import plistlib
import re
import ssl
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from xml.parsers.expat import ExpatError

MAX_PROFILE = 128 * 1024


def openssl(*args, data=None):
    return subprocess.run(["openssl", *args], input=data, capture_output=True,
                          check=True, timeout=8).stdout


class Signer:
    def __init__(self, acme, hostname, relay_url, token):
        if len(token) < 32:
            raise ValueError("PROFILE_SIGNER_TOKEN must contain at least 32 characters")
        self.acme, self.hostname, self.relay_url, self.token = Path(acme), hostname, relay_url.rstrip("/"), token
        self.lock = threading.Lock()
        self.cached = None
        self.slots = threading.BoundedSemaphore(4)

    def identity(self):
        with self.lock:
            stat = self.acme.stat()
            signature = (stat.st_ino, stat.st_mtime_ns, stat.st_size)
            if (self.cached and self.cached[0] == signature and time.monotonic() < self.cached[1]
                    and self.cached[4]["expires_at"] > time.time()):
                return self.cached[2:]
            store = json.loads(self.acme.read_text())
            candidates = []
            for resolver in store.values():
                if not isinstance(resolver, dict):
                    continue
                for entry in resolver.get("Certificates") or []:
                    domain = entry.get("domain") or {}
                    names = [domain.get("main", ""), *(domain.get("sans") or [])]
                    if not any(n == self.hostname or n.startswith("*.") and self.hostname.partition(".")[2] == n[2:] for n in names):
                        continue
                    try:
                        fullchain = base64.b64decode(entry["certificate"], validate=True)
                        key = base64.b64decode(entry["key"], validate=True)
                        certs = re.findall(rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", fullchain, re.S)
                        if not certs:
                            continue
                        with tempfile.TemporaryDirectory() as temp:
                            root = Path(temp)
                            leaf, chain, private = root / "cert.pem", root / "chain.pem", root / "key.pem"
                            leaf.write_bytes(certs[0]); chain.write_bytes(b"\n".join(certs[1:])); private.write_bytes(key)
                            private.chmod(0o600)
                            ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(leaf, private)
                            args = ["verify", "-purpose", "sslserver", "-verify_hostname", self.hostname]
                            if certs[1:]:
                                args += ["-untrusted", str(chain)]
                            openssl(*args, str(leaf))
                            info = openssl("x509", "-in", str(leaf), "-noout", "-enddate", "-subject", "-fingerprint", "-sha256").decode().splitlines()
                            expires = ssl.cert_time_to_seconds(info[0].split("=", 1)[1])
                            metadata = {"subject": info[1].split("=", 1)[1].strip(), "expires_at": int(expires),
                                        "fingerprint": hashlib.sha256(ssl.PEM_cert_to_DER_cert(certs[0].decode())).hexdigest()}
                            candidates.append((expires, certs, key, metadata))
                    except (KeyError, ValueError, ssl.SSLError, subprocess.SubprocessError):
                        continue
            if not candidates:
                raise ValueError("No valid, trusted certificate and matching key for the signing hostname")
            _, certs, key, metadata = max(candidates, key=lambda c: c[0])
            # Recheck validity every minute, and reload immediately after renewal.
            self.cached = (signature, time.monotonic() + 60, certs, key, metadata)
            return certs, key, metadata

    def sign(self, content):
        if len(content) > MAX_PROFILE:
            raise ValueError("Profile is too large")
        profile = plistlib.loads(content, fmt=plistlib.FMT_XML)
        # Only sign the UI's canonical XML. This also avoids duplicate-key
        # interpretation differences and untrusted binary-plist object counts.
        if plistlib.dumps(profile, sort_keys=False) != content:
            raise ValueError("Expected a canonical XML relay profile")
        payloads = profile.get("PayloadContent", [])
        if profile.get("PayloadType") != "Configuration" or len(payloads) != 1:
            raise ValueError("Only single-payload relay profiles can be signed")
        payload = payloads[0]
        if payload.get("PayloadType") != "com.apple.relay.managed" or not profile.get("PayloadIdentifier", "").startswith("org.openvpn.apple-relay."):
            raise ValueError("Only OpenVPN Apple relay profiles can be signed")
        relays = payload.get("Relays", [])
        if len(relays) != 1:
            raise ValueError("Expected one relay")
        urls = [v for k, v in relays[0].items() if k in ("HTTP2RelayURL", "HTTP3RelayURL")]
        if not urls or any(not isinstance(u, str) or u != self.relay_url + "/.well-known/masque/udp/{target_host}/{target_port}/" for u in urls):
            raise ValueError("Unexpected relay URL")
        certs, key, _ = self.identity()
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            leaf, chain, private = root / "cert.pem", root / "chain.pem", root / "key.pem"
            leaf.write_bytes(certs[0]); chain.write_bytes(b"\n".join(certs[1:])); private.write_bytes(key)
            private.chmod(0o600)
            args = ["cms", "-sign", "-binary", "-nodetach", "-nosmimecap", "-outform", "DER", "-md", "sha256",
                    "-signer", str(leaf), "-inkey", str(private)]
            if certs[1:]:
                args += ["-certfile", str(chain)]
            return openssl(*args, data=content)


def handler(signer):
    class Handler(BaseHTTPRequestHandler):
        def setup(self):
            super().setup()
            self.connection.settimeout(10)

        def log_message(self, *args):
            pass  # Never log profile contents, credentials or request headers.

        def respond(self, status, body, content_type="application/json"):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def dispatch(self, signing):
            self.connection.settimeout(10)
            if self.path != "/internal/relay-sign":
                return self.respond(404, b'{}')
            auth = self.headers.get("Authorization", "")
            if not hmac.compare_digest(auth.encode(), ("Bearer " + signer.token).encode()):
                return self.respond(403, b'{"error":"Signing access denied"}')
            if not signer.slots.acquire(blocking=False):
                return self.respond(503, b'{"error":"Signer is busy; retry shortly"}')
            try:
                if signing:
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= MAX_PROFILE or self.headers.get("Transfer-Encoding"):
                        return self.respond(400, b'{"error":"Invalid profile length"}')
                    content = self.rfile.read(length)
                    if len(content) != length:
                        return self.respond(400, b'{"error":"Incomplete profile"}')
                    result = signer.sign(content)
                    self.respond(200, result, "application/x-apple-aspen-config")
                else:
                    self.respond(200, json.dumps({"ready": True, **signer.identity()[2]}).encode())
            except (ValueError, TypeError, KeyError, AttributeError, plistlib.InvalidFileException, ExpatError, RecursionError):
                self.respond(422, b'{"error":"Profile or signing identity is invalid"}')
            except (OSError, subprocess.SubprocessError):
                self.respond(503, b'{"error":"Profile signer is unavailable"}')
            finally:
                signer.slots.release()

        def do_POST(self):
            self.dispatch(True)

        def do_GET(self):
            self.dispatch(False)

    return Handler


class SigningServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, *args):
        super().__init__(*args)
        self.connections = threading.BoundedSemaphore(16)

    def process_request(self, request, address):
        if not self.connections.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.connections.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.connections.release()


def main():
    signer = Signer(os.environ.get("PROFILE_SIGNER_ACME", "/letsencrypt/acme.json"),
                    os.environ.get("PROFILE_SIGNER_HOSTNAME", ""),
                    os.environ.get("PROFILE_SIGNER_RELAY_URL", ""),
                    os.environ.get("PROFILE_SIGNER_TOKEN", ""))
    server = SigningServer(("0.0.0.0", 8085), handler(signer))
    print("Relay profile signer listening on port 8085; certificate keys stay on this host", flush=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
