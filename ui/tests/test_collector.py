import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("OPENVPN_DIR", "/nonexistent")

from app.collector import Collector, parse_connection  # noqa: E402
from app.db import MERGE_GAP, Database  # noqa: E402
from app.mgmt import ManagementError  # noqa: E402


class FakeMgmt:
    def __init__(self):
        self.connected = True
        self.connected_since = time.time()
        self.clients = []

    def status(self):
        return {"time": int(time.time()), "clients": list(self.clients), "stats": {}}

    def version(self):
        return "OpenVPN 2.7.7"

    def load_stats(self):
        return {}


def client(cn, cid, since, b_in, b_out):
    return {"cn": cn, "real_address": "1.2.3.4:5", "vpn_ip": "10.0.70.2", "vpn_ipv6": "", "bytes_in": b_in,
            "bytes_out": b_out, "connected_since": since, "username": "", "cid": cid, "peer_id": 0, "cipher": ""}


def test_restart_reopens_session_without_recounting_traffic(tmp_path):
    db = Database(tmp_path / "c.db")
    mgmt = FakeMgmt()
    since = int(time.time()) - 100
    mgmt.clients = [client("alice", 0, since, 100, 200)]
    c1 = Collector(db, mgmt, 5)
    c1.poll()
    mgmt.clients = [client("alice", 0, since, 150, 260)]
    c1.poll()
    assert db.totals(0, int(time.time()) + 1, "alice") == (150, 260)

    # UI restart: sessions are closed at startup, then the same connection shows up again
    assert db.close_stale_sessions() == 1
    mgmt.clients = [client("alice", 0, since, 170, 300)]
    c2 = Collector(db, mgmt, 5)
    c2.poll()
    rows = db.query("SELECT * FROM vpn_sessions")
    assert len(rows) == 1 and rows[0]["disconnected_at"] is None
    assert rows[0]["bytes_in"] == 170 and rows[0]["bytes_out"] == 300
    assert db.totals(0, int(time.time()) + 1, "alice") == (170, 300)
    assert db.one("SELECT COUNT(*) AS n FROM events")["n"] == 0     # connections are sessions, not audit events

    # a genuinely new connection gets its own row
    mgmt.clients = [client("alice", 1, since + 50, 10, 20)]
    c2.poll()
    rows = db.query("SELECT * FROM vpn_sessions ORDER BY id")
    assert len(rows) == 2 and rows[0]["disconnected_at"] is not None and rows[1]["disconnected_at"] is None
    assert db.totals(0, int(time.time()) + 1, "alice") == (180, 320)


def test_first_traffic_ts(tmp_path):
    db = Database(tmp_path / "f.db")
    assert db.first_traffic_ts() is None
    with db.tx() as conn:
        db.add_traffic(conn, 1_000_000, "a", 1, 1)
        db.add_traffic(conn, 2_000_000, "b", 1, 1)
    assert db.first_traffic_ts() == 1_000_000


def test_status_file_is_preferred_and_unchanged_file_is_skipped(tmp_path):
    db = Database(tmp_path / "s.db")
    mgmt = FakeMgmt()
    mgmt.status = None                      # the management "status" command must not be used
    f = tmp_path / "status.log"
    now = int(time.time())

    def write(t, b_in):
        f.write_text(f"TITLE\tx\nTIME\tx\t{t}\nHEADER\tCLIENT_LIST\tCommon Name\tVirtual Address\tBytes Received"
                     f"\tBytes Sent\tConnected Since (time_t)\tClient ID\n"
                     f"CLIENT_LIST\talice\t10.0.70.2\t{b_in}\t0\t{now - 60}\t3\nEND\n")

    c = Collector(db, mgmt, 5, lambda: (f, 5))
    write(now - 10, 1000)
    c.poll()
    write(now - 5, 6000)
    c.poll()
    assert c.live["clients"][0]["rate_in"] == 1000.0      # 5000 bytes over the file's own 5 s
    c.poll()                                              # same file again: nothing counted twice
    assert db.totals(0, now + 1, "alice") == (6000, 0)


def test_handshakes_in_progress_are_not_sessions(tmp_path):
    db = Database(tmp_path / "u.db")
    mgmt = FakeMgmt()
    now = int(time.time())
    undef = client("UNDEF", 7, now, 2660, 418)
    undef["vpn_ip"] = ""
    mgmt.clients = [undef, client("alice", 8, now, 10, 20)]
    Collector(db, mgmt, 5).poll()
    assert [r["client_name"] for r in db.query("SELECT client_name FROM vpn_sessions")] == ["alice"]


def test_live_updates_reach_async_subscribers_from_the_collector_thread(tmp_path):
    # The live stream waits on an asyncio queue, so an open stream holds no worker thread.
    import asyncio
    import threading
    c = Collector(Database(tmp_path / "c.db"), FakeMgmt(), 5)

    async def main():
        q = c.subscribe()
        threading.Thread(target=c.poll).start()      # publishes from another thread
        snap = await asyncio.wait_for(q.get(), 5)
        c.unsubscribe(q)
        return snap

    assert asyncio.run(main())["connected"] is True
    assert c._subscribers == []


def stamp(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def handshake(ts, address, cn, plat, ver, gui=None):
    lines = [f"{stamp(ts)} {address} VERIFY OK: depth=0, CN={cn}", f"{stamp(ts)} {address} peer info: IV_VER={ver}",
             f"{stamp(ts)} {address} peer info: IV_PLAT={plat}", f"{stamp(ts)} {address} peer info: IV_PROTO=8094"]
    if gui:
        lines.append(f"{stamp(ts)} {address} peer info: IV_GUI_VER={gui}")
    lines.append(f"{stamp(ts)} {address} [{cn}] Peer Connection Initiated with [AF_INET]{address.split(':', 1)[1]}")
    return "\n".join(lines) + "\n"


def test_parse_connection_lines():
    t = "2026-10-02 07:20:46"
    ts = int(time.mktime(time.strptime(t, "%Y-%m-%d %H:%M:%S")))
    p = parse_connection
    assert p(f"{t} udp4:203.0.113.40:52447 peer info: IV_PLAT=ios") == ("info", ts, "udp4:203.0.113.40:52447", "PLAT", "ios")
    assert p(f"{t} udp4:203.0.113.40:52447 peer info: IV_GUI_VER=net.openvpn.connect.ios_3.7.3-7004")[3:] == (
        "GUI_VER", "net.openvpn.connect.ios_3.7.3-7004")
    assert p(f"{t} udp4:203.0.113.40:52447 peer info: IV_CIPHERS=AES-256-GCM") is None
    # a renegotiation repeats the peer info under the client's name: not a new connection
    assert p(f"{t} bob/udp4:203.0.113.40:52447 peer info: IV_PLAT=ios") is None
    assert p(f"{t} udp4:203.0.113.40:52447 [bob] Peer Connection Initiated with [AF_INET]203.0.113.40:52447") == (
        "open", ts, "udp4:203.0.113.40:52447", "bob")
    end = lambda line: p(f"{t} {line}")[2:]     # noqa: E731
    assert end("bob/udp4:203.0.113.40:52447 SIGTERM[soft,delayed-exit] received, client-instance exiting") == (
        "udp4:203.0.113.40:52447", "bob", "left")
    assert end("bob/udp4:203.0.113.40:52447 SIGTERM[soft,ovpn-dco: ping expired] received, client-instance exiting")[2] == "timed out"
    assert end("bob/udp4:203.0.113.40:52447 SIGUSR1[soft,ping-restart] received, client-instance restarting")[2] == "timed out"
    assert end("bob/tcp4-server:203.0.113.40:40112 SIGUSR1[soft,connection-reset] received, client-instance restarting") == (
        "tcp4-server:203.0.113.40:40112", "bob", "closed")
    # a handshake that failed before any certificate was accepted has no name
    assert end("udp4:203.0.113.40:52447 SIGUSR1[soft,tls-error] received, client-instance restarting") == (
        "udp4:203.0.113.40:52447", None, "tls-error")
    assert p(f"{t} bob/udp4:203.0.113.40:52447 CC-EEN exit message received by peer") is None
    assert p(f"{t} SIGTERM[hard,] received, process exiting") is None


def test_log_gives_sessions_their_device_and_ending(tmp_path):
    db = Database(tmp_path / "l.db")
    mgmt = FakeMgmt()
    logfile = tmp_path / "openvpn.log"
    c = Collector(db, mgmt, 5, logs=(logfile,))
    t0 = int(time.time()) - 100
    alice = client("alice", 0, t0, 10, 20)
    alice["real_address"] = "udp4:203.0.113.5:40000"

    # the handshake is in the log before the status file lists the client
    logfile.write_text(handshake(t0, "udp4:203.0.113.5:40000", "alice", "ios", "3.11.1", "net.openvpn.connect.ios_3.7.3-7004"))
    c.read_logs()
    assert db.query("SELECT 1 FROM vpn_sessions") == []
    mgmt.clients = [alice]
    c.poll()
    c.read_logs()
    row = db.one("SELECT * FROM vpn_sessions")
    assert (row["proto"], row["platform"], row["client_ver"]) == ("udp", "ios", "net.openvpn.connect.ios_3.7.3-7004")
    assert row["end_reason"] is None and c._pending == {}

    with logfile.open("a") as fh:
        fh.write(f"{stamp(t0 + 40)} alice/udp4:203.0.113.5:40000 SIGTERM[soft,delayed-exit] received, client-instance exiting\n")
        # bob came and went between two status files; his client has no GUI version
        fh.write(handshake(t0 + 50, "tcp4-server:203.0.113.9:40112", "bob", "android", "2.7.7"))
        fh.write(f"{stamp(t0 + 53)} bob/tcp4-server:203.0.113.9:40112 SIGUSR1[soft,connection-reset] received, client-instance restarting\n")
        # a handshake that never completed leaves nothing behind
        fh.write(f"{stamp(t0 + 60)} udp4:203.0.113.77:1 peer info: IV_PLAT=win\n")
        fh.write(f"{stamp(t0 + 61)} udp4:203.0.113.77:1 SIGUSR1[soft,tls-error] received, client-instance restarting\n")
    c.read_logs()
    mgmt.clients = []
    c.poll()
    rows = {r["client_name"]: r for r in db.query("SELECT * FROM vpn_sessions")}
    assert set(rows) == {"alice", "bob"} and c._pending == {}
    assert rows["alice"]["end_reason"] == "left" and rows["alice"]["disconnected_at"] is not None
    bob = rows["bob"]
    assert (bob["proto"], bob["platform"], bob["client_ver"], bob["end_reason"]) == ("tcp", "android", "2.7.7", "closed")
    assert (bob["connected_at"], bob["disconnected_at"], bob["grp"]) == (t0 + 50, t0 + 53, bob["id"])
    c.read_logs()                                # nothing new: nothing written twice
    assert db.one("SELECT COUNT(*) AS n FROM vpn_sessions")["n"] == 2


def test_sessions_open_when_the_server_goes_away_say_so(tmp_path):
    db = Database(tmp_path / "d.db")
    mgmt = FakeMgmt()
    mgmt.clients = [client("alice", 0, int(time.time()) - 10, 1, 1)]
    c = Collector(db, mgmt, 5)
    c.poll()
    c._handle_down(str(ManagementError("connection refused")))
    row = db.one("SELECT * FROM vpn_sessions")
    assert row["disconnected_at"] is not None and row["end_reason"] == "server down"
    assert c.live["connected"] is False


def test_reconnects_merge_into_visits(tmp_path):
    db = Database(tmp_path / "v.db")
    home, lte = "udp4:203.0.113.5", "tcp4-server:198.51.100.7"

    def add(conn, name, address, start, seconds, reason="left", **kw):
        return db.insert_session(conn, name, address, start, last_seen=start + seconds, disconnected_at=start + seconds,
                                 bytes_in=1, bytes_out=2, end_reason=reason, **kw)

    with db.tx() as conn:
        a1 = add(conn, "alice", home + ":1001", 1000, 35, platform="ios", client_ver="3.11.1")
        b1 = add(conn, "alice", lte + ":2001", 1040, 10, "closed")                       # another network: its own visit
        a2 = add(conn, "alice", home + ":1002", 1100, 35)                               # 65 s after a1: same visit
        a3 = add(conn, "alice", home + ":1003", 1135 + MERGE_GAP, 100, "timed out")       # exactly the gap: still the same
        a4 = add(conn, "alice", home + ":1004", 1235 + 2 * MERGE_GAP + 1, 5)            # later: a new visit
        add(conn, "bob", home + ":1005", 1110, 7)                                       # same address, another client
        db.insert_session(conn, "alice", home + ":1006", 1240 + 2 * MERGE_GAP + 10, last_seen=99999)   # still open
    grp = {r["id"]: r["grp"] for r in db.query("SELECT id, grp FROM vpn_sessions")}
    assert grp[a1] == grp[a2] == grp[a3] == a1 and grp[b1] == b1 and grp[a4] == a4

    total, visits = db.visits(" WHERE client_name = ?", ["alice"], 10)
    assert total == 3 and [v["connections"] for v in visits] == [2, 1, 3]
    newest, _, oldest = visits
    assert newest["disconnected_at"] is None and newest["real_address"] == home + ":1006"
    assert (oldest["connected_at"], oldest["disconnected_at"], oldest["online_seconds"]) == (1000, 1235 + MERGE_GAP, 170)
    assert (oldest["bytes_in"], oldest["bytes_out"], oldest["end_reason"], oldest["tcp"]) == (3, 6, "timed out", 0)
    assert db.visits("", [], 10)[0] == 4
    assert db.visits("", [], 1, 3)[1][0]["connected_at"] == 1000         # paging counts visits, not sessions
    total, active = db.visits("", [], 10, 0, active=True)
    assert total == 1 and active[0]["connections"] == 2

    stats = {s["name"]: s for s in db.connection_stats(0, 10**6)}
    a = stats["alice"]
    assert (a["sessions"], a["short"], a["tcp"], a["left"], a["timed_out"], a["closed"], a["other"]) == (6, 4, 1, 3, 1, 1, 0)
    assert a["median_seconds"] == 35 and (a["platform"], a["client_ver"]) == ("ios", "3.11.1")
    assert stats["bob"]["sessions"] == 1 and list(stats)[0] == "alice"
    assert db.connection_stats(1100, 1101)[0]["sessions"] == 1


def test_a_database_from_1_4_gets_the_new_columns_and_visits(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    old = sqlite3.connect(path)
    old.execute("""CREATE TABLE vpn_sessions (id INTEGER PRIMARY KEY, client_name TEXT NOT NULL, cid INTEGER,
                   real_address TEXT, vpn_ip TEXT, username TEXT, cipher TEXT, connected_at INTEGER NOT NULL,
                   last_seen INTEGER NOT NULL, disconnected_at INTEGER, bytes_in INTEGER NOT NULL DEFAULT 0,
                   bytes_out INTEGER NOT NULL DEFAULT 0)""")
    rows = [("alice", "udp4:203.0.113.5:1", 100, 135), ("alice", "tcp4-server:203.0.113.5:2", 140, 150),
            ("alice", "203.0.113.5:3", 150 + MERGE_GAP + 1, 5000), ("bob", None, 120, 130)]
    old.executemany("INSERT INTO vpn_sessions (client_name, real_address, connected_at, last_seen, disconnected_at) "
                    "VALUES (?, ?, ?, ?, ?)", [(n, a, s, e, e) for n, a, s, e in rows])
    old.commit()
    old.close()
    db = Database(path)
    assert db.group_sessions() == 4 and db.group_sessions() == 0
    got = [(r["grp"], r["proto"]) for r in db.query("SELECT grp, proto FROM vpn_sessions ORDER BY id")]
    assert got == [(1, "udp"), (1, "tcp"), (3, None), (4, None)]


def test_a_failed_database_write_does_not_stop_the_collector(tmp_path):
    import sqlite3
    import threading
    db = Database(tmp_path / "c.db")
    mgmt = FakeMgmt()
    since = int(time.time()) - 100
    mgmt.clients = [client("alice", 0, since, 100, 200), client("bob", 1, since, 1, 2)]
    c = Collector(db, mgmt, 0.01)
    c.poll()

    # the disk fills up: every write fails, also the one that reports OpenVPN as gone
    real_tx, broken = db.tx, threading.Event()

    def tx():
        if broken.is_set():
            raise sqlite3.OperationalError("database or disk is full")
        return real_tx()
    db.tx = tx
    broken.set()
    mgmt.load_stats = lambda: (_ for _ in ()).throw(ManagementError("down"))
    c.start()
    time.sleep(0.2)
    assert c.alive() and not c._active          # still turning, and no longer trusting its own state

    # space is back, bob has left meanwhile: alice continues in her row, bob's row is closed
    mgmt.load_stats = lambda: {}
    mgmt.clients = [client("alice", 0, since, 150, 260)]
    broken.clear()
    deadline = time.time() + 10                 # the collector retries a few seconds after an outage
    while time.time() < deadline and db.one("SELECT bytes_in FROM vpn_sessions WHERE client_name = 'alice'")["bytes_in"] != 150:
        time.sleep(0.05)
    c.stop()
    c.join(2)
    rows = {r["client_name"]: r for r in db.query("SELECT * FROM vpn_sessions")}
    assert len(rows) == 2
    assert rows["alice"]["disconnected_at"] is None and rows["alice"]["bytes_in"] == 150
    assert rows["bob"]["disconnected_at"] is not None
    assert db.totals(0, int(time.time()) + 1, "alice") == (150, 260)
    assert not c.alive()                        # stopped: /healthz would say so
