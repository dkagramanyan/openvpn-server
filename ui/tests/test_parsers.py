import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("OPENVPN_DIR", "/nonexistent")

from app import auth, mgmt, pki  # noqa: E402
from app.db import Database  # noqa: E402


def test_parse_index_handles_legacy_suffix_and_reasons():
    text = (
        "V\t281208105324Z\t\t6A99\tunknown\t/C=UA/CN=server/emailAddress=a@b\n"
        "R\t281208105325Z\t260905105325Z,keyCompromise\tD87D\tunknown\t/C=UA/CN=alice/emailAddress=a@b\n"
        "V\t281208105324Z\t\t9941\tunknown\t/CN=bob/name=bob/LocalIP=10.0.71.5/2FAName=none\n"
        "garbage line\n"
    )
    entries = pki.parse_index(text)
    assert entries["6A99"]["cn"] == "server" and entries["6A99"]["status"] == "V"
    assert entries["D87D"]["status"] == "R" and entries["D87D"]["reason"] == "keyCompromise"
    assert entries["D87D"]["revoked_at"] == pki.parse_asn1_time("260905105325Z")
    assert entries["9941"]["cn"] == "bob"
    assert entries["6A99"]["expires"] == pki.parse_asn1_time("281208105324Z")


def test_time_parsers():
    assert pki.parse_asn1_time("281208105324Z") == pki.parse_asn1_time("20281208105324Z")
    assert pki.parse_openssl_time("Sep  5 10:53:25 2026 GMT") == 1788605605
    assert pki.parse_openssl_time("bogus") is None


def test_status_parsing(monkeypatch):
    lines = [
        "TITLE\tOpenVPN 2.7.7 x86_64",
        "TIME\t2026-09-05 10:00:00\t1788602400",
        "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tVirtual IPv6 Address\tBytes Received"
        "\tBytes Sent\tConnected Since\tConnected Since (time_t)\tUsername\tClient ID\tPeer ID\tData Channel Cipher",
        "CLIENT_LIST\talice\t1.2.3.4:5555\t10.0.70.2\t\t1234\t5678\t2026-09-05 09:00:00\t1788598800\tUNDEF\t0\t0\tAES-256-GCM",
        "HEADER\tROUTING_TABLE\tVirtual Address\tCommon Name\tReal Address\tLast Ref\tLast Ref (time_t)",
        "ROUTING_TABLE\t10.0.70.2\talice\t1.2.3.4:5555\t2026-09-05 09:59:00\t1788602340",
        "GLOBAL_STATS\tMax bcast/mcast queue length\t0",
        "GLOBAL_STATS\tdco_enabled\t0",
    ]
    m = mgmt.Management("127.0.0.1", 1)
    monkeypatch.setattr(m, "command", lambda cmd: lines)
    st = m.status()
    assert st["time"] == 1788602400
    assert st["stats"]["dco_enabled"] == "0"
    c = st["clients"][0]
    assert c["cn"] == "alice" and c["bytes_in"] == 1234 and c["bytes_out"] == 5678
    assert c["cid"] == 0 and c["connected_since"] == 1788598800 and c["cipher"] == "AES-256-GCM"


def test_load_stats(monkeypatch):
    m = mgmt.Management("127.0.0.1", 1)
    monkeypatch.setattr(m, "command", lambda cmd: ["SUCCESS: nclients=2,bytesin=10,bytesout=20"])
    assert m.load_stats() == {"nclients": 2, "bytesin": 10, "bytesout": 20}


def test_password_hashing_and_limiter():
    h = auth.hash_password("correct horse")
    assert auth.verify_password("correct horse", h)
    assert not auth.verify_password("wrong", h)
    assert not auth.verify_password("x", "garbage")
    assert not auth.needs_rehash(h) and auth.needs_rehash("scrypt$32768$8$1$c2FsdA==$ZGlnZXN0")
    assert auth.verify_password("pw", auth.hash_password("pw").replace("$3$", "$1$")) is False


def test_login_limiter():
    lim = auth.LoginLimiter(threshold=2, max_delay=10)
    assert lim.attempt("k") == 0            # the first attempt goes ahead ...
    assert lim.attempt("k") == 0            # ... and the second, which reaches the threshold
    assert lim.attempt("k") > 0             # so the third has to wait
    lim.success("k")
    assert lim.attempt("k") == 0
    # several keys with a threshold each (user name and address of the login form): an attempt
    # that one key holds back is not counted against the other
    assert [lim.attempt({"ip": 4, "ip|admin": 2}) > 0 for _ in range(6)] == [False, False] + [True] * 4
    assert lim._state["ip"][0] == 2 and lim._state["ip|admin"][0] == 2
    assert lim.attempt({"ip": 4, "ip|other": 2}) == 0


def test_login_limiter_counts_parallel_attempts_and_is_not_reset_by_a_flood():
    import threading
    lim = auth.LoginLimiter(threshold=5, max_keys=100)
    passed = []
    threads = [threading.Thread(target=lambda: passed.append(lim.attempt("admin") == 0)) for _ in range(40)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert sum(passed) == 5                 # not 40: each attempt is counted before it is checked
    # 150 other names push out the oldest entries, never the whole table
    lim = auth.LoginLimiter(threshold=2, max_keys=100)
    lim.attempt("old")
    for i in range(150):
        lim.attempt(f"flood{i}")
        if i == 50:
            lim.attempt("admin"), lim.attempt("admin")      # blocked from here on
    assert len(lim._state) == 100 and "old" not in lim._state
    assert lim.attempt("admin") > 0
    # failures are forgotten once the last of them is old enough
    lim = auth.LoginLimiter(threshold=2, forget=60)
    lim._state["k"] = (7, time.monotonic() - 61)
    assert lim.attempt("k") == 0 and lim._state["k"][0] == 1
    lim._state["k"] = (7, time.monotonic() - 59)
    assert lim.attempt("k") == 0 and lim._state["k"][0] == 8 and lim.attempt("k") > 0


def test_management_password_is_read_when_connecting():
    answers = iter([None, "secret"])
    m = mgmt.Management("127.0.0.1", 1, lambda: next(answers))
    assert m.password is None and m.password == "secret"       # the file appeared after the UI started
    assert mgmt.Management("127.0.0.1", 1, "fixed").password == "fixed"


def test_a_failed_commit_does_not_leave_the_connection_in_a_transaction(tmp_path):
    import sqlite3
    db = Database(tmp_path / "t.db")
    conn = db._conn()
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("CREATE TABLE parent (id INTEGER PRIMARY KEY)")
    conn.execute("CREATE TABLE child (p INTEGER REFERENCES parent (id) DEFERRABLE INITIALLY DEFERRED)")
    try:
        with db.tx() as c:
            c.execute("INSERT INTO child (p) VALUES (1)")      # checked at COMMIT, which then fails
        raise AssertionError("the commit should have failed")
    except sqlite3.IntegrityError:
        pass
    db.set_setting("k", "v")                                    # the next transaction starts normally
    assert db.get_setting("k") == "v" and db.one("SELECT COUNT(*) AS n FROM child")["n"] == 0


def test_watchdog_ends_an_unresponsive_process():
    import threading
    from app.watchdog import Watchdog
    died = threading.Event()
    answers = iter([True, False, False, True, False, False, False])
    dog = Watchdog(lambda: next(answers, False), interval=0.01, failures=3, grace=0, die=died.set)
    dog.start()
    assert died.wait(5)                     # three failures in a row, not two
    assert next(answers, None) is None
    healthy = Watchdog(lambda: True, interval=0.01, failures=1, grace=0, die=died.clear)
    healthy.start()
    time.sleep(0.1)
    healthy.stop()
    assert died.is_set()


def test_traffic_aggregation_and_rollup(tmp_path):
    db = Database(tmp_path / "t.db")
    now = int(time.time())
    minute = now - now % 60
    with db.tx() as conn:
        db.add_traffic(conn, minute, "alice", 100, 200)
        db.add_traffic(conn, minute, "alice", 1, 2)          # upsert adds
        db.add_traffic(conn, minute - 60, "bob", 10, 20)
        db.add_traffic(conn, minute - 3 * 86400, "alice", 1000, 2000)  # old -> rolled into hour
    assert db.totals_by_client(0, now + 1) == {"alice": (1101, 2202), "bob": (10, 20)}
    assert db.totals(minute - 60, now + 1, "alice") == (101, 202)
    db.rollup(now)
    assert db.query("SELECT COUNT(*) AS n FROM traffic_minute")[0]["n"] == 2
    assert db.query("SELECT COUNT(*) AS n FROM traffic_hour")[0]["n"] == 1
    assert db.totals_by_client(0, now + 1) == {"alice": (1101, 2202), "bob": (10, 20)}
    series = db.series(minute - 120, now + 1, 60)
    assert [p["ts"] for p in series] == [minute - 60, minute]
    assert series[1]["bytes_in"] == 101


def test_sessions_lifecycle(tmp_path):
    db = Database(tmp_path / "s.db")
    with db.tx() as conn:
        conn.execute("INSERT INTO vpn_sessions (client_name, connected_at, last_seen, bytes_in, bytes_out) "
                     "VALUES ('alice', 100, 200, 5, 6)")
    assert db.close_stale_sessions() == 1
    row = db.one("SELECT disconnected_at FROM vpn_sessions")
    assert row["disconnected_at"] == 200
    stats = db.session_stats_by_client()
    assert stats["alice"]["sessions"] == 1 and stats["alice"]["online_seconds"] == 100


def test_name_with_a_trailing_newline_is_refused():
    import pytest
    for name in ("alice\n", "alice\nbob", " alice"):
        with pytest.raises(pki.PkiError):
            pki.validate_name(name)
    assert not mgmt.NAME_RE.match("alice\n") and mgmt.NAME_RE.match("alice")


def test_option_name_is_read_like_openvpn_reads_it():
    for line, name in (("up /x", "up"), ("  --up /x", "up"), ('"up"/x', "up"), ("'up'/x", "up"), ("u\\p /x", "up"),
                       ("\\ up /x", "up"), ('u"p" /x', 'u"p"'), ("<ca>", "ca"), ("# up /x", ""), ("; up", ""), ("", ""),
                       ('push "route 10.0.0.0 255.0.0.0"', "push"), ("-up", "-up"), ("--", "--"),
                       ("\xa0up /x", "\xa0up"), ("'a b' c", "a b"), ('"a\\"b" c', 'a"b')):
        assert pki.option_name(line) == name, line


def test_name_validation():
    assert pki.validate_name("alice.laptop@home-1") == "alice.laptop@home-1"
    for bad in ("", "-x", "a b", "a/b", "server", "x" * 65, "../etc"):
        try:
            pki.validate_name(bad)
        except pki.PkiError:
            continue
        raise AssertionError(f"{bad!r} should be rejected")


def test_tfa_uri_and_qr(monkeypatch):
    monkeypatch.setattr(pki, "tfa_secrets", lambda: {"alice": "3132333435363738393031323334353637383930"})
    uri = pki.tfa_uri("alice")
    assert uri.startswith("otpauth://totp/OpenVPN:alice?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")
    svg = pki.qr_svg(uri)
    assert "<svg" in svg and "path" in svg and "xmlns" in svg


STATUS_V3 = (
    "TITLE\tOpenVPN 2.7.7\nTIME\t2026-09-05 10:00:00\t1788602400\n"
    "HEADER\tCLIENT_LIST\tCommon Name\tReal Address\tVirtual Address\tBytes Received\tBytes Sent\n"
    "CLIENT_LIST\talice\t1.2.3.4:5555\t10.0.70.2\t1234\t5678\nEND\n"
)


def test_status_file(tmp_path):
    f = tmp_path / "status.log"
    f.write_text(STATUS_V3)
    st = mgmt.read_status_file(f, max_age=30)
    assert st["time"] == 1788602400 and st["clients"][0]["bytes_out"] == 5678
    # version 2 is the same data with commas
    f.write_text(STATUS_V3.replace("\t", ","))
    assert mgmt.read_status_file(f, max_age=30)["clients"][0]["cn"] == "alice"
    f.write_text(STATUS_V3[:-4])            # caught mid-write: no END yet
    assert mgmt.read_status_file(f, max_age=30) is None
    f.write_text(STATUS_V3)
    os.utime(f, (time.time() - 100, time.time() - 100))
    assert mgmt.read_status_file(f, max_age=30) is None     # OpenVPN stopped writing it
    assert mgmt.read_status_file(tmp_path / "missing", max_age=30) is None
