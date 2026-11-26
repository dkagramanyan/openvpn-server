"""The relay policy service reuses HTTP and PostgreSQL connections between checks."""
import http.client
import json
import threading

import psycopg
import pytest

from app import policy_server
from app.db import Database
from app.settings import settings


@pytest.fixture
def service(monkeypatch):
    Database(settings.database_url, schema=settings.database_schema)   # creates relay_policy_settings
    logins = []
    connect = policy_server.ReadOnlySettings._connect.__func__

    def counted(cls):
        connection = connect(cls)
        logins.append(connection)
        return connection
    monkeypatch.setattr(policy_server.ReadOnlySettings, "_connect", classmethod(counted))
    monkeypatch.setattr(policy_server, "check_metadata", lambda: None)
    monkeypatch.setattr(policy_server.relay, "authorize", lambda db, token, device="", strict_state=False:
                        {"client": "alice", "relay": db.get_setting("apple_relay", "{}"), "device": device}
                        if token == "Bearer alice:secret" else None)
    policy_server.ReadOnlySettings.discard_idle()
    server = policy_server.PolicyServer(("127.0.0.1", 0), policy_server.PolicyHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], logins
    server.shutdown()
    server.server_close()
    policy_server.ReadOnlySettings.discard_idle()


def ask(connection, token="Bearer alice:secret", body=None):
    connection.request("POST", "/api/relay/authorize", body=body, headers={"Authorization": token})
    response = connection.getresponse()
    return response.status, json.loads(response.read()), response.getheader("Connection")


def test_checks_share_one_http_and_database_connection(service):
    port, logins = service
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    for _ in range(5):
        status, body, _ = ask(connection)
        assert status == 200 and body["client"] == "alice"
    assert ask(connection, "Bearer alice:wrong")[0] == 403
    connection.request("GET", "/healthz")
    assert connection.getresponse().read() == b'{"ok": true}'
    assert len(logins) == 1


def test_writes_are_refused_on_a_kept_connection(service):
    with policy_server.ReadOnlySettings.open() as db:
        with pytest.raises(psycopg.errors.ReadOnlySqlTransaction):
            db.connection.execute("CREATE TABLE policy_must_not_write (id int)")


def test_dead_kept_connection_is_replaced(service):
    port, logins = service
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    assert ask(connection)[0] == 200
    logins[0].close()       # as after a PostgreSQL restart
    assert ask(connection)[0] == 200
    assert len(logins) == 2


def test_request_with_a_body_closes_the_connection(service):
    port, _ = service
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    status, _, header = ask(connection, body=b"x" * 10)
    assert status == 200 and header == "close"


def test_dropped_connection_is_not_logged_as_a_failed_request(service, caplog):
    import socket, struct, time
    port, _ = service
    raw = socket.create_connection(("127.0.0.1", port))
    raw.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n")
    raw.recv(200)
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))   # close with a reset
    raw.close()
    time.sleep(0.3)
    assert "Policy request failed" not in caplog.text


def test_the_relays_device_header_reaches_the_policy(service):
    port, _ = service
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    connection.request("POST", "/api/relay/authorize", headers={"Authorization": "Bearer alice:secret",
                                                                 "X-Relay-Device": "ab" * 32})
    response = connection.getresponse()
    assert json.loads(response.read())["device"] == "ab" * 32


def test_policy_login_reads_enrolled_devices_only(service):
    db = Database(settings.database_url, schema=settings.database_schema)
    db.execute("DELETE FROM relay_devices WHERE client_name = 'policy-test'")
    db.execute("INSERT INTO relay_devices (id, client_name, code_hash, created_at, expires_at, enrolled_at, fingerprint) "
               "VALUES ('policy-dev-1', 'policy-test', 'h1', 1, 2, 3, ?), ('policy-dev-2', 'policy-test', 'h2', 1, 2, NULL, NULL)",
               ("cd" * 32,))
    with policy_server.ReadOnlySettings.open() as ro:
        assert ro.get_device("policy-dev-1") == {"id": "policy-dev-1", "client_name": "policy-test",
                                                  "fingerprint": "cd" * 32, "revoked_at": None}
        assert ro.get_device("policy-dev-2") is None      # not installed yet: unknown to the relay
    db.execute("DELETE FROM relay_devices WHERE client_name = 'policy-test'")
