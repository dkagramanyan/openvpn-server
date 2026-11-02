"""Exercise the standalone certificate exporter using real certificates and keys."""
import base64
import importlib.util
import json
from pathlib import Path
import stat
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "bin" / "export-relay-cert.py"
spec = importlib.util.spec_from_file_location("export_relay_cert", SCRIPT)
exporter = importlib.util.module_from_spec(spec)
spec.loader.exec_module(exporter)


def identity(path, name, days=1):
    path.mkdir()
    key, cert = path / "key.pem", path / "cert.pem"
    subprocess.run(["openssl", "req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                    "-nodes", "-subj", "/CN=" + name, "-addext", "subjectAltName=DNS:" + name,
                    "-keyout", str(key), "-out", str(path / "request.pem")], check=True, capture_output=True)
    subprocess.run(["openssl", "x509", "-req", "-in", str(path / "request.pem"), "-signkey", str(key),
                    "-copy_extensions", "copy", "-days", str(days), "-out", str(cert)],
                   check=True, capture_output=True)
    return {"domain": {"main": name}, "certificate": base64.b64encode(cert.read_bytes()).decode(),
            "key": base64.b64encode(key.read_bytes()).decode()}


def store(path, entries):
    path.write_text(json.dumps({"letsencrypt": {"Account": {"PrivateKey": "do-not-export"}, "Certificates": entries}}))
    return path


def test_export_only_selected_identity_with_private_permissions(tmp_path):
    chosen = identity(tmp_path / "chosen", "*.example.com")
    other = identity(tmp_path / "other", "unrelated.example.net")
    acme = store(tmp_path / "acme.json", [other, chosen])
    original = acme.read_bytes()
    target = tmp_path / "out"
    result = subprocess.run([sys.executable, str(SCRIPT), "--acme", str(acme), "--hostname", "relay.example.com",
                             "--output", str(target)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert set(p.name for p in target.iterdir()) == {"fullchain.pem", "privkey.pem"}
    assert (target / "fullchain.pem").read_bytes() == base64.b64decode(chosen["certificate"])
    assert (target / "privkey.pem").read_bytes() == base64.b64decode(chosen["key"])
    assert stat.S_IMODE(target.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in target.iterdir())
    assert acme.read_bytes() == original
    assert chosen["key"] not in result.stdout + result.stderr
    assert "PRIVATE KEY" not in result.stdout + result.stderr


@pytest.mark.parametrize("failure", ["hostname", "key", "expired", "base64"])
def test_invalid_export_preserves_existing_files(tmp_path, failure):
    entry = identity(tmp_path / "cert", "relay.example.com", days=-1 if failure == "expired" else 1)
    if failure == "hostname":
        entry["domain"]["main"] = "different.example.com"  # metadata alone cannot authorize a hostname
    elif failure == "key":
        entry["key"] = identity(tmp_path / "other", "relay.example.com")["key"]
    elif failure == "base64":
        entry["key"] = "!invalid!"
    target = tmp_path / "out"
    target.mkdir()
    (target / "privkey.pem").write_text("existing-key")
    (target / "fullchain.pem").write_text("existing-cert")
    with pytest.raises(ValueError):
        exporter.export(store(tmp_path / "acme.json", [entry]),
                        "different.example.com" if failure == "hostname" else "relay.example.com", target)
    assert (target / "privkey.pem").read_text() == "existing-key"
    assert (target / "fullchain.pem").read_text() == "existing-cert"


def test_wildcards_cover_only_one_label():
    assert exporter.covers("*.example.com", "relay.example.com")
    assert not exporter.covers("*.example.com", "example.com")
    assert not exporter.covers("*.example.com", "nested.relay.example.com")
    assert not exporter.covers("*.example.com", "relay.example.com.attacker.test")
