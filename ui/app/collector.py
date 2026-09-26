"""Background threads: poll the management interface, persist sessions and traffic, run maintenance."""
from __future__ import annotations

import copy
import logging
import queue
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .db import Database
from .mgmt import Management, ManagementError, read_status_file

log = logging.getLogger("openvpn-ui.collector")


class Collector(threading.Thread):
    def __init__(self, db: Database, mgmt: Management, interval: float,
                 status_file: Callable[[], tuple[Path | None, int]] = lambda: (None, 0)) -> None:
        super().__init__(name="collector", daemon=True)
        self.db, self.mgmt, self.interval = db, mgmt, interval
        self.status_file = status_file
        self._status_time: int | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._subscribers: list[queue.Queue] = []
        # key -> {session_id, bytes_in, bytes_out, ts, rate_in, rate_out}
        self._active: dict[tuple[int, int, str], dict[str, Any]] = {}
        self.live: dict[str, Any] = {
            "connected": False,
            "error": None,
            "version": None,
            "server_time": None,
            "updated_at": None,
            "connected_since": None,
            "clients": [],
            "load": {},
            "stats": {},
            "rate_in": 0.0,
            "rate_out": 0.0,
        }

    # -- pub/sub -------------------------------------------------------------
    def subscribe(self) -> queue.Queue:
        q: queue.Queue = queue.Queue(maxsize=8)
        with self._lock:
            self._subscribers.append(q)
        return q

    def unsubscribe(self, q: queue.Queue) -> None:
        with self._lock:
            if q in self._subscribers:
                self._subscribers.remove(q)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self.live)

    def _publish(self) -> None:
        with self._lock:
            snap = copy.deepcopy(self.live)
            subs = list(self._subscribers)
        for q in subs:
            try:
                q.put_nowait(snap)
            except queue.Full:
                pass

    # -- main loop -----------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        closed = self.db.close_stale_sessions()
        if closed:
            log.info("closed %d VPN sessions left open by a previous run", closed)
        backoff = 2.0
        while not self._stop.is_set():
            try:
                self.poll()
                backoff = 2.0
                self._stop.wait(self.interval)
            except (ManagementError, OSError) as exc:
                self._handle_down(str(exc))
                self._stop.wait(backoff)
                backoff = min(backoff * 1.5, 15.0)
            except Exception:   # never let the thread die
                log.exception("collector error")
                self._stop.wait(self.interval)

    def _status(self) -> dict[str, Any]:
        """Client list from the status file when server.conf writes a fresh one, else from the
        management interface. OpenVPN logs every management "status" command at verb 3, so
        polling it every few seconds would flood the log."""
        path, every = self.status_file()
        if path is not None:
            status = read_status_file(path, max_age=3 * every + 5)
            if status is not None:
                return {**status, "from_file": True}
        return self.mgmt.status()

    def poll(self) -> None:
        was_connected = self.mgmt.connected
        # load-stats doubles as the liveness check: it is the one command OpenVPN does not log.
        load = self.mgmt.load_stats()
        if not was_connected or not self.live.get("version"):
            try:
                version = self.mgmt.version()
            except ManagementError:
                version = None
        else:
            version = self.live.get("version")
        status = self._status()
        if status.get("from_file") and status["time"] == self._status_time and self.live["connected"]:
            # The status file has not been rewritten since the last poll: nothing new to count.
            with self._lock:
                self.live.update(load=load, updated_at=int(time.time()))
            return
        self._status_time = status["time"]

        now = int(time.time())
        server_now = status["time"]
        minute = now - now % 60
        seen: set[tuple[int, int, str]] = set()
        live_clients: list[dict[str, Any]] = []
        total_rate_in = total_rate_out = 0.0

        with self.db.tx() as conn:
            for cl in status["clients"]:
                key = (cl["cid"], cl["connected_since"], cl["cn"])
                seen.add(key)
                entry = self._active.get(key)
                if entry is None:
                    connected_at = cl["connected_since"] or now
                    # A connection that predates this collector (UI restart, management outage) already
                    # has a row: reopen it and count only the bytes since it was last seen.
                    prev = self.db.find_session(conn, cl["cn"], cl["cid"], connected_at)
                    if prev is not None:
                        session_id = prev["id"]
                        d_in = max(cl["bytes_in"] - prev["bytes_in"], 0)
                        d_out = max(cl["bytes_out"] - prev["bytes_out"], 0)
                        conn.execute(
                            "UPDATE vpn_sessions SET disconnected_at = NULL, last_seen = ?, bytes_in = ?, bytes_out = ? "
                            "WHERE id = ?", (now, cl["bytes_in"], cl["bytes_out"], session_id),
                        )
                    else:
                        cur = conn.execute(
                            """INSERT INTO vpn_sessions (client_name, cid, real_address, vpn_ip, username, cipher,
                                                         connected_at, last_seen, bytes_in, bytes_out)
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                            (cl["cn"], cl["cid"], cl["real_address"], cl["vpn_ip"], cl["username"], cl["cipher"],
                             connected_at, now, cl["bytes_in"], cl["bytes_out"]),
                        )
                        session_id = cur.lastrowid
                        d_in, d_out = cl["bytes_in"], cl["bytes_out"]
                        self.db.add_event("vpn_connect", cl["cn"], None, cl["real_address"], conn=conn)
                    entry = {"session_id": session_id, "bytes_in": cl["bytes_in"], "bytes_out": cl["bytes_out"],
                             "ts": server_now, "rate_in": 0.0, "rate_out": 0.0}
                    self._active[key] = entry
                    self.db.add_traffic(conn, minute, cl["cn"], d_in, d_out)
                else:
                    d_in = cl["bytes_in"] - entry["bytes_in"]
                    d_out = cl["bytes_out"] - entry["bytes_out"]
                    if d_in < 0:
                        d_in = cl["bytes_in"]
                    if d_out < 0:
                        d_out = cl["bytes_out"]
                    dt = max(server_now - entry["ts"], 1)
                    entry.update(bytes_in=cl["bytes_in"], bytes_out=cl["bytes_out"], ts=server_now,
                                 rate_in=d_in / dt, rate_out=d_out / dt)
                    conn.execute(
                        """UPDATE vpn_sessions SET last_seen = ?, bytes_in = ?, bytes_out = ?,
                                  vpn_ip = CASE WHEN ? != '' THEN ? ELSE vpn_ip END,
                                  cipher = CASE WHEN ? != '' THEN ? ELSE cipher END
                           WHERE id = ?""",
                        (now, cl["bytes_in"], cl["bytes_out"], cl["vpn_ip"], cl["vpn_ip"],
                         cl["cipher"], cl["cipher"], entry["session_id"]),
                    )
                    self.db.add_traffic(conn, minute, cl["cn"], d_in, d_out)
                total_rate_in += entry["rate_in"]
                total_rate_out += entry["rate_out"]
                live_clients.append({**cl, "session_id": entry["session_id"],
                                     "rate_in": entry["rate_in"], "rate_out": entry["rate_out"]})

            self._close_sessions(conn, [k for k in self._active if k not in seen], now)

        live_clients.sort(key=lambda c: (c["cn"], c["connected_since"]))
        with self._lock:
            self.live.update(
                connected=True, error=None, version=version, server_time=status["time"], updated_at=now,
                connected_since=self.mgmt.connected_since, clients=live_clients, load=load,
                stats=status.get("stats", {}), rate_in=total_rate_in, rate_out=total_rate_out,
            )
        self._publish()

    def _close_sessions(self, conn, keys: list, now: int, detail: str | None = None) -> None:
        for key in keys:
            entry = self._active.pop(key)
            conn.execute("UPDATE vpn_sessions SET disconnected_at = ? WHERE id = ? AND disconnected_at IS NULL",
                         (now, entry["session_id"]))
            self.db.add_event("vpn_disconnect", key[2], None, detail, conn=conn)

    def _handle_down(self, error: str) -> None:
        self._status_time = None
        if self._active:
            with self.db.tx() as conn:
                self._close_sessions(conn, list(self._active), int(time.time()), "server unreachable")
        with self._lock:
            changed = self.live["connected"] or self.live["error"] != error
            self.live.update(connected=False, error=error, clients=[], load={}, rate_in=0.0, rate_out=0.0,
                             updated_at=int(time.time()), connected_since=None)
        if changed:
            log.warning("management interface unavailable: %s", error)
            self._publish()


class Maintenance(threading.Thread):
    """Hourly housekeeping: traffic roll-ups, CRL freshness."""

    def __init__(self, db: Database, tasks: list[Callable[[], None]], interval: float = 3600.0) -> None:
        super().__init__(name="maintenance", daemon=True)
        self.db, self.tasks, self.interval = db, tasks, interval
        self._stop = threading.Event()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        self._stop.wait(60)
        while not self._stop.is_set():
            try:
                self.db.rollup()
            except Exception:
                log.exception("traffic roll-up failed")
            for task in self.tasks:
                try:
                    task()
                except Exception:
                    log.exception("maintenance task failed")
            self._stop.wait(self.interval)
