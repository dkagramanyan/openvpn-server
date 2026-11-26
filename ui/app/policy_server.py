"""Independent, loopback-only relay authorization with read-only live state."""
from __future__ import annotations

from contextlib import contextmanager
import ipaddress
import json
import logging
import os
import psycopg
import sys
from psycopg import sql as pgsql
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import relay
from .db import connection_parameters
from .settings import settings

log = logging.getLogger("relay-policy")


class ReadOnlySettings:
    """The policy login can select only the filtered policy settings view.

    Connections are kept between checks: a new PostgreSQL login for every
    check delayed the first connection a phone opened in any second.
    """
    _idle: list = []
    _lock = threading.Lock()
    KEEP = 8

    def __init__(self, connection):
        self.connection = connection

    def get_setting(self, key, default=None):
        row = self.connection.execute("SELECT value FROM relay_policy_settings WHERE key = %s", (key,)).fetchone()
        return row[0] if row else default

    def get_device(self, device_id):
        row = self.connection.execute("SELECT id, client_name, fingerprint, revoked_at FROM relay_policy_devices "
                                      "WHERE id = %s", (device_id,)).fetchone()
        return dict(zip(("id", "client_name", "fingerprint", "revoked_at"), row)) if row else None

    @classmethod
    def _connect(cls):
        connection = psycopg.connect(**{"connect_timeout": 2, **connection_parameters(settings.database_url)},
                                     autocommit=True)
        connection.execute("SET default_transaction_read_only = on")
        connection.execute(pgsql.SQL("SET search_path TO {}").format(pgsql.Identifier(settings.database_schema)))
        return connection

    @classmethod
    def discard_idle(cls):
        with cls._lock:
            idle, cls._idle = cls._idle, []
        for connection in idle:
            connection.close()

    @classmethod
    @contextmanager
    def open(cls):
        with cls._lock:
            connection = cls._idle.pop() if cls._idle else None
        if connection is None:
            connection = cls._connect()
        try:
            yield cls(connection)
        except BaseException:
            connection.close()
            raise
        with cls._lock:
            if len(cls._idle) < cls.KEEP:
                cls._idle.append(connection)
                return
        connection.close()


def with_settings(function):
    """Run function(db). A kept connection that died (PostgreSQL restarted) is
    replaced once; a database that is really down still fails the check."""
    try:
        with ReadOnlySettings.open() as db:
            return function(db)
    except psycopg.OperationalError:
        ReadOnlySettings.discard_idle()
        with ReadOnlySettings.open() as db:
            return function(db)


def check_metadata():
    """Fail closed (503) when the public PKI state or the access roles are unreadable."""
    index = settings.pki_dir / "index.txt"
    if not index.is_file():
        raise OSError("PKI index unavailable")
    index.read_bytes()
    if not settings.guests_dir.is_dir():
        raise OSError("Access role directory unavailable")


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
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path != "/healthz":
            self.reply(404, {"detail": "Not found"})
            return
        try:
            with_settings(lambda db: (db.get_setting("apple_relay"), check_metadata()))
            self.reply(200, {"ok": True})
        except (OSError, psycopg.Error, ValueError):
            self.reply(503, {"ok": False, "detail": "Policy state unavailable"})

    def do_POST(self):
        if self.path != "/api/relay/authorize":
            self.reply(404, {"detail": "Not found"})
            return
        # Authorization has no request body. The relay's own requests are kept
        # alive; anything that announces a body is answered and closed, so
        # unread bytes can never become a second HTTP request.
        if self.headers.get("Content-Length", "0").strip() != "0" or self.headers.get("Transfer-Encoding"):
            self.close_connection = True
        authorization = self.headers.get("Authorization", "")
        # Set by the relay from the TLS handshake (loopback only): the client certificate's SHA-256.
        device = self.headers.get("X-Relay-Device", "")

        def check(db):
            check_metadata()
            return relay.authorize(db, authorization, device=device, strict_state=True)
        try:
            policy = with_settings(check)
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
        # A client that drops a kept connection is not a failed request.
        if isinstance(sys.exc_info()[1], ConnectionError):
            return
        log.warning("Policy request failed; request details suppressed")

    def get_request(self):
        connection, address = super().get_request()
        connection.settimeout(30)   # the relay keeps its connections for reuse
        return connection, address


def main():
    address = os.environ.get("RELAY_POLICY_BIND", "127.0.0.1:8447")
    host, port = address.rsplit(":", 1)
    if not ipaddress.ip_address(host.strip("[]")).is_loopback:
        raise ValueError("Relay policy service must bind a loopback address")
    logging.basicConfig(level=logging.INFO)
    log.info("Independent relay policy service listening on %s", address)
    PolicyServer((host, int(port)), PolicyHandler).serve_forever()


if __name__ == "__main__":
    main()
