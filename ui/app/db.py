"""SQLite storage: admin accounts, web sessions, VPN sessions, traffic buckets, events."""
from __future__ import annotations

import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at    INTEGER NOT NULL,
    last_login    INTEGER
);
CREATE TABLE IF NOT EXISTS web_sessions (
    token_hash TEXT PRIMARY KEY,
    user_id    INTEGER NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    ip         TEXT,
    user_agent TEXT
);
CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS clients (
    name       TEXT PRIMARY KEY,
    note       TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS hidden_certs (
    serial    TEXT PRIMARY KEY,
    name      TEXT,
    hidden_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vpn_sessions (
    id              INTEGER PRIMARY KEY,
    client_name     TEXT NOT NULL,
    cid             INTEGER,
    real_address    TEXT,
    vpn_ip          TEXT,
    username        TEXT,
    cipher          TEXT,
    connected_at    INTEGER NOT NULL,
    last_seen       INTEGER NOT NULL,
    disconnected_at INTEGER,
    bytes_in        INTEGER NOT NULL DEFAULT 0,
    bytes_out       INTEGER NOT NULL DEFAULT 0,
    proto           TEXT,       -- "udp" or "tcp"
    platform        TEXT,       -- the client's IV_PLAT: ios, android, win, mac, linux
    client_ver      TEXT,       -- IV_GUI_VER, else IV_VER
    end_reason      TEXT,       -- how it ended: "left", "timed out", "closed", or OpenVPN's own word
    grp             INTEGER     -- id of the first session of this visit (see session_group)
);
CREATE INDEX IF NOT EXISTS vpn_sessions_client ON vpn_sessions (client_name, connected_at);
CREATE INDEX IF NOT EXISTS vpn_sessions_open   ON vpn_sessions (disconnected_at);
CREATE TABLE IF NOT EXISTS traffic_minute (
    ts          INTEGER NOT NULL,
    client_name TEXT NOT NULL,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ts, client_name)
);
CREATE TABLE IF NOT EXISTS traffic_hour (
    ts          INTEGER NOT NULL,
    client_name TEXT NOT NULL,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ts, client_name)
);
CREATE TABLE IF NOT EXISTS traffic_day (
    ts          INTEGER NOT NULL,
    client_name TEXT NOT NULL,
    bytes_in    INTEGER NOT NULL DEFAULT 0,
    bytes_out   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (ts, client_name)
);
CREATE TABLE IF NOT EXISTS events (
    id          INTEGER PRIMARY KEY,
    ts          INTEGER NOT NULL,
    kind        TEXT NOT NULL,
    client_name TEXT,
    actor       TEXT,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS events_ts ON events (ts);
-- History of a client whose name was later given to a new certificate:
-- its sessions and traffic were moved to client_name = key ("name#time").
CREATE TABLE IF NOT EXISTS archived_clients (
    key         TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    archived_at INTEGER NOT NULL
);
-- Connection attempts OpenVPN rejected, counted per day, client, reason and source.
CREATE TABLE IF NOT EXISTS rejections (
    day         INTEGER NOT NULL,
    client_name TEXT NOT NULL,
    reason      TEXT NOT NULL,
    address     TEXT NOT NULL,
    count       INTEGER NOT NULL,
    last_ts     INTEGER NOT NULL,
    PRIMARY KEY (day, client_name, reason, address)
);
-- One-time profile download links.
CREATE TABLE IF NOT EXISTS share_tokens (
    token_hash  TEXT PRIMARY KEY,
    client_name TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    used_at     INTEGER,
    created_by  TEXT
);
"""

# Columns added to vpn_sessions after 1.4: an existing database gets them on start.
_SESSION_COLUMNS = (("proto", "TEXT"), ("platform", "TEXT"), ("client_ver", "TEXT"), ("end_reason", "TEXT"),
                    ("grp", "INTEGER"))

_HISTORY = (("vpn_sessions", "connected_at"), ("traffic_minute", "ts"), ("traffic_hour", "ts"), ("traffic_day", "ts"))

MINUTE_RETENTION = 2 * 86400      # minute buckets are kept for two days
HOUR_RETENTION = 90 * 86400       # hourly buckets for 90 days, daily forever
EVENT_RETENTION = 365 * 86400     # the audit log
# A phone drops the tunnel whenever it sleeps and reconnects on wake, hundreds of times a day.
# Sessions of one client from one address that follow each other within this gap are one visit.
MERGE_GAP = 15 * 60
SHORT_SESSION = 60                # "short" in the connection statistics: under a minute

_TRAFFIC_UNION = """
    SELECT ts, client_name, bytes_in, bytes_out FROM traffic_minute WHERE ts >= ? AND ts < ?
    UNION ALL
    SELECT ts, client_name, bytes_in, bytes_out FROM traffic_hour   WHERE ts >= ? AND ts < ?
    UNION ALL
    SELECT ts, client_name, bytes_in, bytes_out FROM traffic_day    WHERE ts >= ? AND ts < ?
"""


def split_address(address: str | None) -> tuple[str | None, str]:
    """("udp" | "tcp" | None, "ip:port") of a real address as OpenVPN prints it:
    "udp4:203.0.113.5:1194", "tcp4-server:203.0.113.5:40112", or just "203.0.113.5:1194" before 2.7."""
    address = address or ""
    head, sep, rest = address.partition(":")
    if sep and head[:3] in ("udp", "tcp"):
        return head[:3], rest
    return None, address


def real_ip(address: str | None) -> str:
    return split_address(address)[1].rpartition(":")[0]


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._local = threading.local()
        self._write_lock = threading.RLock()
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._conn()
        conn.executescript(SCHEMA)
        have = {r["name"] for r in conn.execute("PRAGMA table_info(vpn_sessions)")}
        for col, kind in _SESSION_COLUMNS:
            if col not in have:
                conn.execute(f"ALTER TABLE vpn_sessions ADD COLUMN {col} {kind}")
        conn.execute("CREATE INDEX IF NOT EXISTS vpn_sessions_grp ON vpn_sessions (grp)")

    # -- connection handling -------------------------------------------------
    def _conn(self) -> sqlite3.Connection:
        conn = getattr(self._local, "conn", None)
        if conn is None:
            conn = sqlite3.connect(str(self.path), timeout=30, isolation_level=None, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA synchronous=NORMAL")
            conn.execute("PRAGMA busy_timeout=30000")
            self._local.conn = conn
        return conn

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        """Serialised write transaction."""
        with self._write_lock:
            conn = self._conn()
            conn.execute("BEGIN IMMEDIATE")
            try:
                yield conn
                conn.execute("COMMIT")
            except BaseException:
                # Also after a failed COMMIT (disk full): left open, the transaction would make
                # every later BEGIN on this connection fail. If even the rollback fails, the
                # next transaction of this thread gets a new connection.
                try:
                    if conn.in_transaction:
                        conn.execute("ROLLBACK")
                except sqlite3.Error:
                    conn.close()
                    self._local.conn = None
                raise

    def execute(self, sql: str, params: tuple | list = ()) -> sqlite3.Cursor:
        with self.tx() as conn:
            return conn.execute(sql, params)

    def query(self, sql: str, params: tuple | list = ()) -> list[sqlite3.Row]:
        return self._conn().execute(sql, params).fetchall()

    def one(self, sql: str, params: tuple | list = ()) -> sqlite3.Row | None:
        return self._conn().execute(sql, params).fetchone()

    # -- settings ------------------------------------------------------------
    def get_setting(self, key: str, default: str | None = None) -> str | None:
        row = self.one("SELECT value FROM settings WHERE key = ?", (key,))
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        self.execute(
            "INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

    # -- events --------------------------------------------------------------
    def add_event(self, kind: str, client_name: str | None = None, actor: str | None = None,
                  detail: str | None = None, conn: sqlite3.Connection | None = None) -> None:
        sql = "INSERT INTO events (ts, kind, client_name, actor, detail) VALUES (?, ?, ?, ?, ?)"
        params = (int(time.time()), kind, client_name, actor, detail)
        if conn is not None:
            conn.execute(sql, params)
        else:
            self.execute(sql, params)

    # -- traffic -------------------------------------------------------------
    @staticmethod
    def add_traffic(conn: sqlite3.Connection, ts_minute: int, client_name: str, d_in: int, d_out: int) -> None:
        if d_in <= 0 and d_out <= 0:
            return
        conn.execute(
            """INSERT INTO traffic_minute (ts, client_name, bytes_in, bytes_out) VALUES (?, ?, ?, ?)
               ON CONFLICT(ts, client_name) DO UPDATE SET
                   bytes_in = bytes_in + excluded.bytes_in,
                   bytes_out = bytes_out + excluded.bytes_out""",
            (ts_minute, client_name, max(d_in, 0), max(d_out, 0)),
        )

    def totals_by_client(self, start: int, end: int) -> dict[str, tuple[int, int]]:
        rows = self.query(
            f"SELECT client_name, SUM(bytes_in) AS bi, SUM(bytes_out) AS bo FROM ({_TRAFFIC_UNION}) GROUP BY client_name",
            (start, end) * 3,
        )
        return {r["client_name"]: (int(r["bi"] or 0), int(r["bo"] or 0)) for r in rows}

    def totals(self, start: int, end: int, client_name: str | None = None) -> tuple[int, int]:
        where = " WHERE client_name = ?" if client_name else ""
        params: list[Any] = list((start, end) * 3)
        if client_name:
            params.append(client_name)
        row = self.one(
            f"SELECT SUM(bytes_in) AS bi, SUM(bytes_out) AS bo FROM ({_TRAFFIC_UNION}){where}",
            params,
        )
        return (int(row["bi"] or 0), int(row["bo"] or 0)) if row else (0, 0)

    def series(self, start: int, end: int, bucket: int, client_name: str | None = None,
               tz_offset: int = 0) -> list[dict[str, int]]:
        """Traffic per bucket. tz_offset (seconds east of UTC) aligns day buckets to local midnight."""
        where = " WHERE client_name = ?" if client_name else ""
        params: list[Any] = list((start, end) * 3)
        if client_name:
            params.append(client_name)
        rows = self.query(
            f"""SELECT ((ts + ?) / ?) * ? - ? AS b, SUM(bytes_in) AS bi, SUM(bytes_out) AS bo
                FROM ({_TRAFFIC_UNION}){where} GROUP BY b ORDER BY b""",
            [tz_offset, bucket, bucket, tz_offset] + params,
        )
        return [{"ts": int(r["b"]), "bytes_in": int(r["bi"] or 0), "bytes_out": int(r["bo"] or 0)} for r in rows]

    def first_traffic_ts(self) -> int | None:
        row = self.one(
            "SELECT MIN(ts) AS t FROM (SELECT MIN(ts) AS ts FROM traffic_minute UNION ALL "
            "SELECT MIN(ts) FROM traffic_hour UNION ALL SELECT MIN(ts) FROM traffic_day)"
        )
        return int(row["t"]) if row and row["t"] is not None else None

    def rollup(self, now: int | None = None) -> None:
        """Fold old minute buckets into hourly ones and old hourly buckets into daily ones."""
        now = now or int(time.time())
        with self.tx() as conn:
            cutoff = now - MINUTE_RETENTION
            conn.execute(
                """INSERT INTO traffic_hour (ts, client_name, bytes_in, bytes_out)
                   SELECT (ts / 3600) * 3600, client_name, SUM(bytes_in), SUM(bytes_out)
                   FROM traffic_minute WHERE ts < ? GROUP BY 1, 2
                   ON CONFLICT(ts, client_name) DO UPDATE SET
                       bytes_in = bytes_in + excluded.bytes_in,
                       bytes_out = bytes_out + excluded.bytes_out""",
                (cutoff,),
            )
            conn.execute("DELETE FROM traffic_minute WHERE ts < ?", (cutoff,))
            cutoff = now - HOUR_RETENTION
            conn.execute(
                """INSERT INTO traffic_day (ts, client_name, bytes_in, bytes_out)
                   SELECT (ts / 86400) * 86400, client_name, SUM(bytes_in), SUM(bytes_out)
                   FROM traffic_hour WHERE ts < ? GROUP BY 1, 2
                   ON CONFLICT(ts, client_name) DO UPDATE SET
                       bytes_in = bytes_in + excluded.bytes_in,
                       bytes_out = bytes_out + excluded.bytes_out""",
                (cutoff,),
            )
            conn.execute("DELETE FROM traffic_hour WHERE ts < ?", (cutoff,))
            conn.execute("DELETE FROM web_sessions WHERE expires_at < ?", (now,))
            conn.execute("DELETE FROM rejections WHERE day < ?", (now - HOUR_RETENTION,))
            conn.execute("DELETE FROM share_tokens WHERE expires_at < ?", (now,))
            conn.execute("DELETE FROM events WHERE ts < ?", (now - EVENT_RETENTION,))

    # -- client history ------------------------------------------------------
    def archive_client_history(self, name: str, before: int | None = None) -> str | None:
        """Move the sessions and traffic of <name> (those older than <before>, if given) to an
        archive key, so a new certificate with the same name starts with a clean history."""
        cond = " AND {col} < ?" if before is not None else ""
        extra = [before] if before is not None else []
        with self.tx() as conn:
            if not any(conn.execute(f"SELECT 1 FROM {t} WHERE client_name = ?{cond.format(col=c)} LIMIT 1",
                                    [name] + extra).fetchone() for t, c in _HISTORY):
                return None
            now = int(time.time())
            key = f"{name}#{now}"
            for table, col in _HISTORY:
                conn.execute(f"UPDATE {table} SET client_name = ? WHERE client_name = ?{cond.format(col=col)}",
                             [key, name] + extra)
            conn.execute("INSERT OR REPLACE INTO archived_clients (key, name, archived_at) VALUES (?, ?, ?)",
                         (key, name, now))
            return key

    def purge_client(self, name: str) -> None:
        """Remove every trace of a pseudo client (OpenVPN's "UNDEF" for handshakes in progress)."""
        with self.tx() as conn:
            for table, _ in _HISTORY:
                conn.execute(f"DELETE FROM {table} WHERE client_name = ?", (name,))
            conn.execute("DELETE FROM events WHERE client_name = ?", (name,))

    # -- rejected connection attempts ----------------------------------------
    def add_rejection(self, conn: sqlite3.Connection, ts: int, client: str, reason: str, address: str) -> None:
        conn.execute(
            """INSERT INTO rejections (day, client_name, reason, address, count, last_ts) VALUES (?, ?, ?, ?, 1, ?)
               ON CONFLICT(day, client_name, reason, address) DO UPDATE SET
                   count = count + 1, last_ts = MAX(last_ts, excluded.last_ts)""",
            (ts - ts % 86400, client, reason, address, ts),
        )

    def rejections(self, since: int, client: str | None = None) -> list[dict[str, Any]]:
        where, params = "WHERE last_ts >= ?", [since]
        if client is not None:
            where += " AND client_name = ?"
            params.append(client)
        rows = self.query(
            f"""SELECT client_name, reason, address, SUM(count) AS n, MAX(last_ts) AS last_ts FROM rejections {where}
                GROUP BY client_name, reason, address ORDER BY last_ts DESC LIMIT 50""", params)
        return [{"client": r["client_name"], "reason": r["reason"], "address": r["address"],
                 "count": int(r["n"]), "last_ts": int(r["last_ts"])} for r in rows]

    # -- sessions ------------------------------------------------------------
    def close_stale_sessions(self, at: int | None = None) -> int:
        """Mark every still-open VPN session as ended (used at startup and when OpenVPN goes away)."""
        with self.tx() as conn:
            cur = conn.execute(
                "UPDATE vpn_sessions SET disconnected_at = COALESCE(?, last_seen) WHERE disconnected_at IS NULL",
                (at,),
            )
            return cur.rowcount

    @staticmethod
    def find_session(conn: sqlite3.Connection, client_name: str, cid: int, connected_at: int) -> sqlite3.Row | None:
        """The most recent row of a connection, matched by name, client id and start time."""
        return conn.execute(
            "SELECT id, bytes_in, bytes_out FROM vpn_sessions WHERE client_name = ? AND cid = ? AND connected_at = ? "
            "ORDER BY id DESC LIMIT 1",
            (client_name, cid, connected_at),
        ).fetchone()

    @staticmethod
    def latest_session(conn: sqlite3.Connection, client_name: str, address: str,
                       since: int = 0) -> sqlite3.Row | None:
        """The newest session of a client from this address (compared without the protocol prefix):
        one that is still open, or that started at or after <since>."""
        want = split_address(address)[1]
        for row in conn.execute(
                "SELECT * FROM vpn_sessions WHERE client_name = ? AND (connected_at >= ? OR disconnected_at IS NULL) "
                "ORDER BY connected_at DESC, id DESC LIMIT 20", (client_name, since)):
            if split_address(row["real_address"])[1] == want:
                return row
        return None

    @staticmethod
    def session_group(conn: sqlite3.Connection, client_name: str, address: str, connected_at: int) -> int | None:
        """The visit a new connection continues: the client's previous session from the same IP
        ended at most MERGE_GAP ago. None starts a new visit."""
        ip = real_ip(address)
        for row in conn.execute(
                "SELECT grp, real_address, COALESCE(disconnected_at, last_seen) AS ended FROM vpn_sessions "
                "WHERE client_name = ? ORDER BY connected_at DESC, id DESC LIMIT 20", (client_name,)):
            if real_ip(row["real_address"]) == ip:
                return row["grp"] if connected_at - row["ended"] <= MERGE_GAP else None
        return None

    def insert_session(self, conn: sqlite3.Connection, client_name: str, real_address: str, connected_at: int,
                       **fields: Any) -> int:
        fields = {"proto": split_address(real_address)[0], **fields, "client_name": client_name,
                  "real_address": real_address, "connected_at": connected_at,
                  "grp": self.session_group(conn, client_name, real_address, connected_at)}
        fields.setdefault("last_seen", connected_at)
        cur = conn.execute(f"INSERT INTO vpn_sessions ({', '.join(fields)}) VALUES ({', '.join('?' * len(fields))})",
                           list(fields.values()))
        if fields["grp"] is None:
            conn.execute("UPDATE vpn_sessions SET grp = id WHERE id = ?", (cur.lastrowid,))
        return int(cur.lastrowid)

    def group_sessions(self) -> int:
        """Assign a visit to every session that has none (rows written before 1.5)."""
        last: dict[tuple[str, str], tuple[int, int]] = {}     # (client, ip) -> (grp, end of its latest session)
        with self.tx() as conn:
            rows = conn.execute("SELECT id, client_name, real_address, connected_at, "
                                "COALESCE(disconnected_at, last_seen) AS ended FROM vpn_sessions "
                                "WHERE grp IS NULL ORDER BY connected_at, id").fetchall()
            for r in rows:
                key = (r["client_name"], real_ip(r["real_address"]))
                grp, ended = last.get(key, (r["id"], None))
                if ended is None or r["connected_at"] - ended > MERGE_GAP:
                    grp = r["id"]
                last[key] = (grp, max(ended or 0, r["ended"]))
                conn.execute("UPDATE vpn_sessions SET grp = ?, proto = COALESCE(proto, ?) WHERE id = ?",
                             (grp, split_address(r["real_address"])[0], r["id"]))
            return len(rows)

    def visits(self, where: str, params: list[Any], limit: int, offset: int = 0,
               active: bool = False) -> tuple[int, list[dict[str, Any]]]:
        """Sessions merged into visits, newest first: (number of visits, one page of them). A visit
        carries the address, device and end of its latest session."""
        having = " HAVING SUM(disconnected_at IS NULL) > 0" if active else ""
        grouped = f"""SELECT grp, MIN(connected_at) AS connected_at, MAX(id) AS last_id, COUNT(*) AS connections,
                             MAX(COALESCE(disconnected_at, last_seen)) AS ended,
                             SUM(disconnected_at IS NULL) AS open, SUM(proto = 'tcp') AS tcp,
                             SUM(COALESCE(disconnected_at, last_seen) - connected_at) AS online_seconds,
                             SUM(bytes_in) AS bytes_in, SUM(bytes_out) AS bytes_out
                      FROM vpn_sessions{where} GROUP BY grp{having}"""
        total = self.one(f"SELECT COUNT(*) AS n FROM ({grouped})", params)
        rows = self.query(
            f"""SELECT g.*, l.client_name, l.real_address, l.vpn_ip, l.cipher, l.proto, l.platform, l.client_ver,
                       l.end_reason
                FROM ({grouped}) g JOIN vpn_sessions l ON l.id = g.last_id
                ORDER BY g.connected_at DESC, g.grp DESC LIMIT ? OFFSET ?""", params + [limit, offset])
        out = []
        for r in rows:
            v = dict(r)
            v["disconnected_at"] = None if v.pop("open") else v.pop("ended")
            v.pop("ended", None)
            out.append(v)
        return (int(total["n"]) if total else 0), out

    def connection_stats(self, start: int, end: int) -> list[dict[str, Any]]:
        """Per client, for the sessions that started in [start, end): how many, how long, how they
        ended, how many came over TCP, and the device seen last."""
        stats: dict[str, dict[str, Any]] = {}
        for r in self.query(
                "SELECT client_name, COALESCE(disconnected_at, last_seen) - connected_at AS seconds, disconnected_at, "
                "end_reason, proto, platform, client_ver FROM vpn_sessions WHERE connected_at >= ? AND connected_at < ? "
                "ORDER BY connected_at", (start, end)):
            s = stats.setdefault(r["client_name"], {
                "name": r["client_name"], "sessions": 0, "short": 0, "tcp": 0, "left": 0, "timed_out": 0,
                "closed": 0, "other": 0, "durations": [], "platform": None, "client_ver": None})
            s["sessions"] += 1
            s["tcp"] += r["proto"] == "tcp"
            if r["disconnected_at"] is not None:
                s["durations"].append(max(r["seconds"], 0))
                s["short"] += r["seconds"] < SHORT_SESSION
                s[{"left": "left", "timed out": "timed_out", "closed": "closed"}.get(r["end_reason"], "other")] += 1
            if r["platform"]:
                s["platform"], s["client_ver"] = r["platform"], r["client_ver"]
        for s in stats.values():
            d = sorted(s.pop("durations"))
            s["median_seconds"] = d[(len(d) - 1) // 2] if d else None
        return sorted(stats.values(), key=lambda s: -s["sessions"])

    def session_stats_by_client(self) -> dict[str, dict[str, int]]:
        rows = self.query(
            """SELECT client_name, COUNT(*) AS n, MAX(last_seen) AS last_seen, MIN(connected_at) AS first_seen,
                      SUM(bytes_in) AS bi, SUM(bytes_out) AS bo,
                      SUM(COALESCE(disconnected_at, last_seen) - connected_at) AS online_seconds
               FROM vpn_sessions GROUP BY client_name"""
        )
        return {
            r["client_name"]: {
                "sessions": int(r["n"]),
                "last_seen": int(r["last_seen"]),
                "first_seen": int(r["first_seen"]),
                "bytes_in": int(r["bi"] or 0),
                "bytes_out": int(r["bo"] or 0),
                "online_seconds": int(r["online_seconds"] or 0),
            }
            for r in rows
        }

