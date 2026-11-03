"""Independent, loopback-only relay authorization with read-only live state."""
from __future__ import annotations

from contextlib import contextmanager
import ipaddress
import json
import logging
import os
import psycopg
from psycopg import sql as pgsql
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import relay
from .db import connection_parameters
from .settings import settings

log = logging.getLogger("relay-policy")


class ReadOnlySettings:
    """The policy login can select only the filtered policy settings view."""
    def __init__(self, connection):
        self.connection = connection

    def get_setting(self, key, default=None):
        row = self.connection.execute("SELECT value FROM relay_policy_settings WHERE key = %s", (key,)).fetchone()
        return row[0] if row else default

    @classmethod
    @contextmanager
    def open(cls):
        with psycopg.connect(**{"connect_timeout": 2, **connection_parameters(settings.database_url)}) as connection:
            connection.read_only = True
            connection.execute(pgsql.SQL("SET LOCAL search_path TO {}").format(pgsql.Identifier(settings.database_schema)))
            yield cls(connection)


def check_metadata():
    index = settings.pki_dir / "index.txt"
    if not index.is_file() or index.stat().st_nlink == 0:
        raise OSError("PKI index unavailable")
    index.read_bytes()
    if not settings.guests_dir.is_dir():
        raise OSError("Access role directory unavailable")
    if settings.server_conf.stat().st_nlink == 0:
        raise OSError("Recreate policy service after replacing server.conf")


def monitor_config_mount():
    """An external atomic replacement unlinks the inode. Restart to rebind it.

    Requests fail closed while the old inode is visible. Compose's restart
    policy then mounts the new host file without needing a Docker socket here.
    """
    while True:
        time.sleep(0.5)
        try:
            replaced = settings.server_conf.stat().st_nlink == 0
        except OSError:
            continue  # Request readiness reports unavailable metadata.
        if replaced:
            log.warning("Server configuration replaced; restarting policy service to refresh its read-only mount")
            os._exit(75)


class PolicyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass  # No credentials, usernames, query strings or policy bodies in logs.

    def reply(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/healthz":
            self.reply(404, {"detail": "Not found"})
            return
        try:
            with ReadOnlySettings.open() as db:
                db.get_setting("apple_relay")
                check_metadata()
            self.reply(200, {"ok": True})
        except (OSError, psycopg.Error, ValueError):
            self.reply(503, {"ok": False, "detail": "Policy state unavailable"})

    def do_POST(self):
        if self.path != "/api/relay/authorize":
            self.reply(404, {"detail": "Not found"})
            return
        # Authorization has no request body. Close instead of reading unbounded
        # uploads or allowing unread bytes to become a second HTTP request.
        self.close_connection = True
        try:
            with ReadOnlySettings.open() as db:
                check_metadata()
                policy = relay.authorize(db, self.headers.get("Authorization", ""), strict_state=True)
            self.reply(200 if policy is not None else 403, policy or {"detail": "Relay access denied"})
        except (OSError, psycopg.Error, ValueError, KeyError, TypeError):
            self.reply(503, {"detail": "Policy state unavailable"})


class PolicyServer(ThreadingHTTPServer):
    daemon_threads = True
    request_queue_size = 64

    def __init__(self, *args, **kwargs):
        self.slots = threading.BoundedSemaphore(64)
        super().__init__(*args, **kwargs)

    def process_request(self, request, address):
        if not self.slots.acquire(blocking=False):
            self.shutdown_request(request)
            return
        try:
            super().process_request(request, address)
        except BaseException:
            self.slots.release()
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            self.slots.release()

    def handle_error(self, request, address):
        log.warning("Policy request failed; request details suppressed")

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(4)
        return connection, address


def main():
    address = os.environ.get("RELAY_POLICY_BIND", "127.0.0.1:8447")
    host, port = address.rsplit(":", 1)
    if not ipaddress.ip_address(host.strip("[]")).is_loopback:
        raise ValueError("Relay policy service must bind a loopback address")
    logging.basicConfig(level=logging.INFO)
    log.info("Independent relay policy service listening on %s", address)
    threading.Thread(target=monitor_config_mount, daemon=True).start()
    PolicyServer((host, int(port)), PolicyHandler).serve_forever()


if __name__ == "__main__":
    main()
