#!/usr/bin/env python3
"""Export one TLS identity from Traefik's ACME store, without printing secrets."""
import argparse
import base64
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile


def covers(pattern, hostname):
    pattern = pattern.lower().rstrip(".")
    return pattern == hostname or (pattern.startswith("*.") and
                                   hostname.partition(".")[2] == pattern[2:])


def export(acme, hostname, output):
    hostname = hostname.lower().rstrip(".")
    if not re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", hostname):
        raise ValueError("Pass a DNS hostname, without a scheme, port or wildcard")
    data = json.loads(Path(acme).read_text())
    candidates = []
    for resolver in data.values():
        if not isinstance(resolver, dict):
            continue
        for entry in resolver.get("Certificates") or []:
            domain = entry.get("domain") or {}
            names = [domain.get("main", ""), *(domain.get("sans") or [])]
            if any(covers(name, hostname) for name in names):
                candidates.append(entry)
    if not candidates:
        raise ValueError(f"No certificate for {hostname} in this ACME store")

    # Validate before touching an existing export. OpenSSL trusts only the
    # selected certificate here to check its name and dates, not public trust.
    # The source store must already contain a publicly trusted TLS identity.
    selected = None
    with tempfile.TemporaryDirectory(prefix="relay-cert-") as temporary:
        cert_path = Path(temporary) / "fullchain.pem"
        key_path = Path(temporary) / "privkey.pem"
        for entry in candidates:
            try:
                cert = base64.b64decode(entry["certificate"], validate=True)
                key = base64.b64decode(entry["key"], validate=True)
                cert_path.write_bytes(cert)
                key_path.write_bytes(key)
                key_path.chmod(0o600)
                ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER).load_cert_chain(cert_path, key_path)
                subprocess.run(["openssl", "verify", "-trusted", str(cert_path), "-partial_chain",
                                "-verify_hostname", hostname, str(cert_path)],
                               check=True, capture_output=True, timeout=5)
                selected = cert, key
                break
            except (KeyError, ValueError, ssl.SSLError, subprocess.CalledProcessError):
                continue
    if selected is None:
        raise ValueError("Matching certificates are invalid, expired, or have mismatched keys")

    output = Path(output)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    # sudo is often necessary to read acme.json. Keep the export owned by the
    # invoking user so it can be transferred with their usual SSH identity.
    uid = int(os.environ.get("SUDO_UID", os.getuid())) if os.geteuid() == 0 else os.getuid()
    gid = int(os.environ.get("SUDO_GID", os.getgid())) if os.geteuid() == 0 else os.getgid()
    output.chmod(0o700)
    for filename, content in zip(("fullchain.pem", "privkey.pem"), selected):
        fd, temp = tempfile.mkstemp(prefix=".relay-cert-", dir=output)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(content)
                stream.flush()
                os.fsync(stream.fileno())
            if os.geteuid() == 0:
                os.chown(temp, uid, gid)
            os.replace(temp, output / filename)
        finally:
            if os.path.exists(temp):
                os.unlink(temp)
    if os.geteuid() == 0:
        os.chown(output, uid, gid)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acme", required=True, type=Path, help="Host path to Traefik's acme.json")
    parser.add_argument("--hostname", required=True, help="Public relay hostname")
    parser.add_argument("--output", required=True, type=Path, help="Private export directory")
    args = parser.parse_args()
    try:
        export(args.acme, args.hostname, args.output)
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        parser.exit(1, f"Export failed: {exc}\n")
    print(f"Exported TLS files for {args.hostname} to {args.output}; no ACME account key was copied.")


if __name__ == "__main__":
    main()
