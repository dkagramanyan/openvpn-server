#!/usr/bin/env python3
"""Run UI tests with the production PostgreSQL client/runtime in isolated Docker."""
import os
from pathlib import Path
import secrets
import subprocess
import time

ROOT = Path(__file__).resolve().parents[1]
name = "ovpn-ui-pg-test-" + secrets.token_hex(4)
network = name + "-net"
password = secrets.token_urlsafe(24)

def run(*args, **kwargs):
    return subprocess.run(args, check=True, **kwargs)

try:
    run("docker", "build", "-f", "ui/Dockerfile", "-t", "openvpn-ui:unit-test", str(ROOT), cwd=ROOT)
    run("docker", "network", "create", network, stdout=subprocess.DEVNULL)
    run("docker", "run", "-d", "--name", name, "--network", network, "--network-alias", "postgres",
        "-e", "POSTGRES_PASSWORD=" + password, "postgres:18.6-alpine", stdout=subprocess.DEVNULL)
    for _ in range(60):
        if subprocess.run(["docker", "exec", name, "pg_isready", "-h", "127.0.0.1", "-U", "postgres"], capture_output=True).returncode == 0: break
        time.sleep(1)
    else: raise RuntimeError("Temporary PostgreSQL did not start")
    run("docker", "run", "--rm", "--network", network, "-v", f"{ROOT}:/source:ro", "-w", "/source",
        "-e", "OVPN_TEST_DATABASE_URL=postgresql://postgres:" + password + "@postgres/postgres",
        "-e", "OVPN_TEST_REPAIR_PERMISSIONS=1",
        "--entrypoint", "sh", "openvpn-ui:unit-test", "-c", "apk add --no-cache git sudo && pip install -q pytest httpx && python -m pytest ui/tests -q -p no:cacheprovider --tb=short")
finally:
    subprocess.run(["docker", "rm", "-f", name], capture_output=True)
    subprocess.run(["docker", "network", "rm", network], capture_output=True)
