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
    bytes_out       INTEGER NOT NULL DEFAULT 0
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
"""

MINUTE_RETENTION = 2 * 86400      # minute buckets are kept for two days
HOUR_RETENTION = 90 * 86400       # hourly buckets for 90 days, daily forever

_TRAFFIC_UNION = """
    SELECT ts, client_name, bytes_in, bytes_out FROM traffic_minute WHERE ts >= ? AND ts < ?
    UNION ALL
    SELECT ts, client_name, bytes_in, bytes_out FROM traffic_hour   WHERE ts >= ? AND ts < ?
    UNION ALL
    SELECT ts, client_name, bytes_in, bytes_out FROM traffic_day    WHERE ts >= ? AND ts < ?
"""


class Database:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._local = threading.local()
        self._write_lock = threading.RLock()
        path.parent.mkdir(parents=True, exist_ok=True)
        conn = self._conn()
        conn.executescript(SCHEMA)

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
            except BaseException:
                conn.execute("ROLLBACK")
                raise
            else:
                conn.execute("COMMIT")

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
            f"""SELECT ((ts + {tz_offset}) / {bucket}) * {bucket} - {tz_offset} AS b,
                       SUM(bytes_in) AS bi, SUM(bytes_out) AS bo
                FROM ({_TRAFFIC_UNION}){where} GROUP BY b ORDER BY b""",
            params,
        )
        return [{"ts": int(r["b"]), "bytes_in": int(r["bi"] or 0), "bytes_out": int(r["bo"] or 0)} for r in rows]

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

    # -- sessions ------------------------------------------------------------
    def close_stale_sessions(self, at: int | None = None) -> int:
        """Mark every still-open VPN session as ended (used at startup and when OpenVPN goes away)."""
        with self.tx() as conn:
            cur = conn.execute(
                "UPDATE vpn_sessions SET disconnected_at = COALESCE(?, last_seen) WHERE disconnected_at IS NULL",
                (at,),
            )
            return cur.rowcount

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


def row_to_dict(row: sqlite3.Row | None) -> dict[str, Any] | None:
    return dict(row) if row is not None else None
