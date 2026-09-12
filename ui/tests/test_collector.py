import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
os.environ.setdefault("OPENVPN_DIR", "/nonexistent")

from app.collector import Collector  # noqa: E402
from app.db import Database  # noqa: E402


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
    assert db.one("SELECT COUNT(*) AS n FROM events WHERE kind = 'vpn_connect'")["n"] == 1

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
