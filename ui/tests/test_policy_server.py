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
    monkeypatch.setattr(policy_server.relay, "authorize", lambda db, token, strict_state=False:
                        {"client": "alice", "relay": db.get_setting("apple_relay", "{}")} if token == "Bearer alice:secret" else None)
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
