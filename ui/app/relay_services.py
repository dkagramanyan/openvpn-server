"""Private relay diagnostics and verified CMS profile downloads."""
from __future__ import annotations

import json
import ssl
import subprocess
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from .pki import PkiError
from .settings import settings


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


def signing_request(content=None):
    parsed = urlsplit(settings.relay_signer_url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise PkiError("Profile signing requires an HTTPS signer URL")
    if len(settings.relay_signer_token) < 32:
        raise PkiError("Configure the profile signing token on both hosts")
    req = Request(settings.relay_signer_url, data=content, headers={
        "Authorization": "Bearer " + settings.relay_signer_token,
        "Content-Type": "application/x-apple-aspen-config"})
    try:
        opener = build_opener(ProxyHandler({}), NoRedirect(), HTTPSHandler(context=ssl.create_default_context()))
        with opener.open(req, timeout=10) as response:
            body = response.read(256 * 1024 + 1)
            if len(body) > 256 * 1024:
                raise PkiError("Profile signer returned an oversized response")
            return body
    except HTTPError as exc:
        detail = {403: "check the shared token and allowed source IP", 404: "the Traefik signing route was not found",
                  422: "check the signing certificate and ACME store on the Pi", 503: "the signer is temporarily unavailable"}.get(exc.code, "check the signer service")
        raise PkiError("Cannot reach the profile signer: " + detail) from exc
    except (OSError, URLError) as exc:
        # Keep credentials, response bodies and exception URLs out of the UI.
        raise PkiError("Cannot reach the profile signer; check its certificate, token and Traefik route") from exc


def sign_profile(content, hostname):
    if not settings.relay_signer_url:
        return content
    signed = signing_request(content)
    try:
        verified = subprocess.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER",
                                   "-purpose", "any", "-verify_hostname", hostname, "-verify_retcode"],
                                  input=signed, capture_output=True, check=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise PkiError("Profile signature could not be verified; no unsigned profile was returned") from exc
    if verified != content:
        raise PkiError("Profile signer changed the profile contents")
    return signed


def signing_status():
    if not settings.relay_signer_url:
        return {"configured": False, "ready": False, "message": "Profile signing is not configured"}
    try:
        info = json.loads(signing_request())
        return {"configured": True, "ready": bool(info["ready"]), "subject": info["subject"],
                "expires_at": info["expires_at"], "fingerprint": info["fingerprint"]}
    except (PkiError, ValueError, KeyError, TypeError) as exc:
        return {"configured": True, "ready": False, "message": str(exc) if isinstance(exc, PkiError) else "Invalid signer status"}


def runtime_status():
    # Deliberately fixed to host loopback: never let an API parameter choose a URL.
    try:
        with build_opener(ProxyHandler({})).open("http://127.0.0.1:8446/status", timeout=2) as response:
            return json.loads(response.read(512 * 1024))
    except (OSError, ValueError, URLError):
        return {"ready": False, "message": "Relay backend is unreachable on this host", "events": [], "active": []}
