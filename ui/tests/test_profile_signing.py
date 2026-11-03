"""Real CMS signatures, HTTPS authentication and ACME renewal, without production keys."""
import base64
import importlib.util
import json
import plistlib
import ssl
import subprocess
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("profile_signer", ROOT / "signer/service.py")
service = importlib.util.module_from_spec(spec)
spec.loader.exec_module(service)


def command(*args):
    return subprocess.run(["openssl", *args], check=True, capture_output=True).stdout


def make_identity(root, ca=None):
    root.mkdir(parents=True)
    if ca is None:
        ca = root
        command("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2",
                "-subj", "/CN=Relay Test Root", "-addext", "basicConstraints=critical,CA:TRUE",
                "-addext", "keyUsage=critical,keyCertSign,cRLSign", "-keyout", str(ca / "ca.key"), "-out", str(ca / "ca.pem"))
    command("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
            "-subj", "/CN=relay.example.com", "-keyout", str(root / "key.pem"), "-out", str(root / "req.pem"))
    (root / "ext.cnf").write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:relay.example.com,DNS:localhost,DNS:traefik\n")
    command("x509", "-req", "-in", str(root / "req.pem"), "-CA", str(ca / "ca.pem"), "-CAkey", str(ca / "ca.key"),
            "-CAcreateserial", "-days", "1", "-extfile", str(root / "ext.cnf"), "-out", str(root / "cert.pem"))
    chain = (root / "cert.pem").read_bytes() + (ca / "ca.pem").read_bytes()
    (root / "fullchain.pem").write_bytes(chain)
    return {"domain": {"main": "relay.example.com", "sans": ["localhost", "traefik"]}, "certificate": base64.b64encode(chain).decode(),
            "key": base64.b64encode((root / "key.pem").read_bytes()).decode()}


def write_store(path, entry):
    path.write_text(json.dumps({"letsencrypt": {"Certificates": [entry]}}))


def profile():
    return plistlib.dumps({"PayloadType": "Configuration", "PayloadVersion": 1,
        "PayloadIdentifier": "org.openvpn.apple-relay.test", "PayloadContent": [{
            "PayloadType": "com.apple.relay.managed", "Relays": [{
                "HTTP2RelayURL": "https://relay.example.com:8443/.well-known/masque/udp/{target_host}/{target_port}/",
                "AdditionalHTTPHeaderFields": {"Authorization": "Bearer alice:personal-test-credential"}}], "MatchDomains": []}]})


@pytest.fixture
def signing(tmp_path, monkeypatch):
    entry = make_identity(tmp_path / "initial")
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "initial/ca.pem"))
    acme = tmp_path / "acme.json"
    write_store(acme, entry)
    signer = service.Signer(acme, "relay.example.com", "https://relay.example.com:8443", "t" * 64)
    return signer, acme, tmp_path


def test_sign_and_verify_through_real_https_service(signing, monkeypatch):
    from app import relay_services
    from app.settings import settings
    signer, _, root = signing
    server = ThreadingHTTPServer(("127.0.0.1", 0), service.handler(signer))
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root / "initial/fullchain.pem", root / "initial/key.pem")
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setattr(settings, "relay_signer_url", f"https://localhost:{server.server_port}/internal/relay-sign")
    monkeypatch.setattr(settings, "relay_signer_token", "t" * 64)
    try:
        status = relay_services.signing_status()
        assert status["ready"] and status["expires_at"] > 0
        signed = relay_services.sign_profile(profile(), "relay.example.com")
        assert signed != profile() and not signed.startswith(b"<?xml")
        # Rejection must never silently return an unsigned download.
        monkeypatch.setattr(settings, "relay_signer_token", "wrong" * 16)
        with pytest.raises(relay_services.PkiError, match="Cannot reach"):
            relay_services.sign_profile(profile(), "relay.example.com")
        assert relay_services.signing_status()["ready"] is False
    finally:
        server.shutdown(); server.server_close(); thread.join()


def test_signer_reloads_renewed_certificate_without_restart(signing):
    signer, acme, root = signing
    first = signer.identity()[2]["fingerprint"]
    replacement = make_identity(root / "renewed", root / "initial")
    write_store(acme, replacement)
    assert signer.identity()[2]["fingerprint"] != first
    assert signer.sign(profile())
    # Malformed ACME replacement cannot reuse stale keys or return an unsigned file.
    acme.write_text("{}")
    with pytest.raises(ValueError, match="No valid"):
        signer.sign(profile())


def test_signer_rejects_untrusted_certificates_and_unrelated_payloads(signing, monkeypatch):
    signer, acme, root = signing
    for edits in [{"PayloadContent": []}, {"PayloadType": "NotAProfile"},
                  {"PayloadContent": [{"PayloadType": "com.apple.mdm"}]},
                  {"PayloadContent": [{"PayloadType": "com.apple.relay.managed", "Relays": [{"HTTP2RelayURL": "https://attacker.example/"}]}]}]:
        document = plistlib.loads(profile()); document.update(edits)
        with pytest.raises(ValueError):
            signer.sign(plistlib.dumps(document))
    other = make_identity(root / "untrusted")
    write_store(acme, other)
    with pytest.raises(ValueError, match="No valid"):
        signer.sign(profile())


def test_ui_checks_signature_contents_and_hostname(signing, monkeypatch):
    from app import relay_services
    signer, _, _ = signing
    signed = signer.sign(profile())
    monkeypatch.setattr(relay_services.settings, "relay_signer_url", "https://localhost/internal/relay-sign")
    monkeypatch.setattr(relay_services, "signing_request", lambda content=None, **kwargs: signed)
    with pytest.raises(relay_services.PkiError, match="changed"):
        relay_services.sign_profile(profile() + b"\n", "relay.example.com")
    with pytest.raises(relay_services.PkiError, match="verified"):
        relay_services.sign_profile(profile(), "wrong.example.com")
    monkeypatch.setattr(relay_services, "signing_request", lambda content=None, **kwargs: signed[:-30] + bytes(30))
    with pytest.raises(relay_services.PkiError, match="verified"):
        relay_services.sign_profile(profile(), "relay.example.com")


def test_unsigned_download_requires_explicit_opt_out(monkeypatch):
    from app import relay_services
    from app.settings import Settings
    monkeypatch.delenv('OVPN_RELAY_REQUIRE_SIGNED', raising=False)
    assert Settings().relay_signing_required is True
    monkeypatch.setattr(relay_services.settings, 'relay_signer_url', '')
    monkeypatch.setattr(relay_services.settings, 'relay_signing_required', True)
    with pytest.raises(relay_services.SigningUnavailable, match='setup'):
        relay_services.sign_profile(profile(), 'relay.example.com')
    monkeypatch.setattr(relay_services.settings, 'relay_signing_required', False)
    assert relay_services.sign_profile(profile(), 'relay.example.com') == profile()


def test_environment_token_with_newline_is_rejected_without_exposure(monkeypatch):
    from app import relay_services
    secret = 'private-token-sentinel' * 3 + '\n'
    config = {'url':'https://example.com/internal/relay-sign', 'token':secret}
    with pytest.raises(relay_services.PkiError) as error:
        relay_services.signing_request(config=config)
    assert 'private-token-sentinel' not in str(error.value)
