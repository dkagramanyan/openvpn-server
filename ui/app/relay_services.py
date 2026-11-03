"""Private relay diagnostics and verified CMS profile downloads."""
from __future__ import annotations

import json
import ssl
import subprocess

from pydantic import BaseModel, Field
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit, urlencode
from urllib.request import HTTPRedirectHandler, HTTPSHandler, ProxyHandler, Request, build_opener

from .pki import PkiError
from .settings import settings


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *args):
        return None


class SigningUnavailable(PkiError):
    pass


class SigningSettings(BaseModel):
    url: str = Field(default="", max_length=2048)
    token: str | None = Field(default=None, max_length=512, repr=False, json_schema_extra={"writeOnly": True})
    required: bool = True
    use_environment: bool = False


def signing_config(db=None):
    saved = json.loads(db.get_setting("relay_signing", "{}")) if db is not None else {}
    return {"url": saved.get("url", settings.relay_signer_url),
            "token": saved.get("token", settings.relay_signer_token),
            "required": saved.get("required", settings.relay_signing_required),
            "source": "ui" if saved else "environment"}


def validate_signer_url(url):
    try:
        parsed = urlsplit(url)
        valid_port = parsed.port != 0
    except ValueError:
        raise PkiError("Signing URL must be a valid HTTPS URL") from None
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
            or parsed.password is not None or parsed.query or parsed.fragment or not valid_port
            or parsed.path != "/internal/relay-sign" or any(c.isspace() for c in url) or "\\" in url):
        raise PkiError("Signing URL must be HTTPS and end in /internal/relay-sign")


def save_signing(db, body):
    if body.use_environment:
        db.execute("DELETE FROM settings WHERE key = ?", ("relay_signing",))
        return signing_status(db)
    current = signing_config(db)
    url = body.url.strip()
    if url: validate_signer_url(url)
    token = current["token"] if body.token is None else body.token.strip()
    if token and (not 32 <= len(token) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in token)):
        raise PkiError("Use the shared signing token from Traefik (32–512 printable characters)")
    db.set_setting("relay_signing", json.dumps({"url": url, "token": token, "required": body.required}))
    # Never return the token to the browser, including after saving it.
    return signing_status(db)


def signing_request(content=None, config=None):
    config = config or signing_config()
    validate_signer_url(config["url"])
    if not 32 <= len(config["token"]) <= 512 or any(ord(c) < 33 or ord(c) > 126 for c in config["token"]):
        raise PkiError("Configure the valid shared profile signing token on both hosts")
    req = Request(config["url"], data=content, headers={
        "Authorization": "Bearer " + config["token"],
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


def sign_profile(content, hostname, db=None):
    config = signing_config(db)
    if not config["url"]:
        if config["required"]:
            raise SigningUnavailable("Signed relay downloads require setup in Relay → Profile signing. Configure the HTTPS signer URL and shared Traefik token.")
        return content
    try:
        signed = signing_request(content, config=config)
    except PkiError as exc:
        raise SigningUnavailable(str(exc)) from exc
    try:
        verified = subprocess.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER",
                                   "-purpose", "any", "-verify_hostname", hostname, "-verify_retcode"],
                                  input=signed, capture_output=True, check=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        raise SigningUnavailable("Profile signature could not be verified; no unsigned profile was returned") from exc
    if verified != content:
        raise SigningUnavailable("Profile signer changed the profile contents")
    return signed


def signing_status(db=None):
    config = signing_config(db)
    base = {"configured": bool(config["url"]), "url": config["url"], "token_configured": bool(config["token"]),
            "required": config["required"], "source": config["source"]}
    if not config["url"]:
        return {**base, "ready": False, "message": "Set the signer URL and shared Traefik token; signed downloads are blocked until setup is complete" if config["required"] else "Unsigned downloads explicitly allowed"}
    try:
        info = json.loads(signing_request(config=config))
        return {**base, "ready": bool(info["ready"]), "subject": info["subject"],
                "expires_at": info["expires_at"], "fingerprint": info["fingerprint"]}
    except (PkiError, ValueError, KeyError, TypeError) as exc:
        return {**base, "ready": False, "message": str(exc) if isinstance(exc, PkiError) else "Invalid signer status"}


def runtime_status(client=None):
    # Deliberately fixed to host loopback: never let an API parameter choose a URL.
    endpoint = "http://127.0.0.1:8446/status" + ("?" + urlencode({"client": client}) if client else "")
    try:
        with build_opener(ProxyHandler({})).open(endpoint, timeout=2) as response:
            content = response.read(2 * 1024 * 1024 + 1)
            if len(content) > 2 * 1024 * 1024: raise ValueError("Oversized relay status")
            return json.loads(content)
    except (OSError, ValueError, URLError):
        return {"ready": False, "message": "Relay backend is unreachable on this host", "events": [], "active": [], "clients": []}
