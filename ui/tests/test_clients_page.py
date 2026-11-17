"""The clients list: each client's traffic steps (sparkline) and top podkop section for the period."""
import test_api  # noqa: F401  (puts the environment in place before app.main is imported)
from pg_fixture import Database
from app import main

START = 1_794_000_000        # a period of 24 hours: one step an hour


def fresh(monkeypatch):
    db = Database()
    monkeypatch.setattr(main, "db", db)
    return db


def test_sparks_are_one_series_per_client_in_at_most_24_steps(monkeypatch):
    db = fresh(monkeypatch)
    with db.tx() as conn:
        db.add_traffic(conn, START, "alice", 10, 20)                              # step 0
        db.add_traffic(conn, START + 60, "alice", 1, 2, source="relay")           # step 0 too: both ways in
        db.add_traffic(conn, START + 5 * 3600, "alice", 100, 200)                 # step 5
        db.add_traffic(conn, START + 23 * 3600 + 3540, "bob", 7, 0)               # the last step
        db.add_traffic(conn, START - 60, "alice", 999, 999)                       # before the period
        db.add_traffic(conn, START + 86400, "alice", 999, 999)                    # after it
    sparks = main.client_sparks(START, START + 86400)
    assert set(sparks) == {"alice", "bob"} and len(sparks["alice"]) == 24
    assert sparks["alice"][0] == 33 and sparks["alice"][5] == 300 and sum(sparks["alice"]) == 333
    assert sparks["bob"] == [0] * 23 + [7]
    # A long period still gives 24 steps, a short one fewer (never finer than a minute).
    assert len(main.client_sparks(START - 40 * 86400, START + 86400)["alice"]) == 24
    assert len(main.client_sparks(START, START + 600)["alice"]) == 10


def test_top_section_prefers_a_named_section_and_gives_its_share(monkeypatch):
    db = fresh(monkeypatch)
    rows = [("alice", "youtube", 600), ("alice", "", 300), ("alice", "?", 100), ("alice", "meta", 0),
            ("bob", "", 80), ("bob", "?", 20),                 # nothing named: the larger of the two
            ("carol", "main", 0)]                              # no bytes: nothing to show
    with db.tx() as conn:
        for name, section, n in rows:
            conn.execute("INSERT INTO section_traffic (ts, client_name, source, section, bytes_in, bytes_out, flows) "
                         "VALUES (?, ?, 'vpn', ?, 0, ?, 1)", (START, name, section, n))
        conn.execute("INSERT INTO section_traffic (ts, client_name, source, section, bytes_in, bytes_out, flows) "
                     "VALUES (?, 'alice', 'relay', 'meta', 0, 5000, 1)", (START - 3600,))      # outside the period
    top = main.client_top_sections(START, START + 86400)
    assert top == {"alice": {"section": "youtube", "share": 0.6}, "bob": {"section": "", "share": 0.8}}


def test_the_list_carries_both_and_one_client_lookup_does_not(monkeypatch):
    calls = []
    monkeypatch.setattr(main, "client_sparks", lambda start, end: calls.append("spark") or {})
    monkeypatch.setattr(main, "client_top_sections", lambda start, end: calls.append("top") or {})
    monkeypatch.setattr(main.pki, "list_clients", lambda hidden: {})
    assert main.clients_payload() == [] and calls == []
    assert main.clients_payload(extras=True) == [] and calls == ["spark", "top"]
