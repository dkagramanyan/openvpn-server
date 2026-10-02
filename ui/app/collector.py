"""Background threads: poll the management interface, persist sessions and traffic, run maintenance."""
from __future__ import annotations

import asyncio
import copy
import logging
import os
import re
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .db import Database, split_address
from .mgmt import Management, ManagementError, read_status_file

log = logging.getLogger("openvpn-ui.collector")

_TS = r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d) "
_REJECTS = (    # pattern, then (client, reason, source address) of a match
    # a certificate the server refused: revoked, expired, not from this CA, ...
    (re.compile(_TS + r"[\w-]+:([0-9a-fA-F.:]+?):\d+ VERIFY ERROR: depth=0, error=([^:]+):.*?\bCN=([^,/]+)"),
     lambda m: (m[4], m[3], m[2])),
    # control channel key mismatch: a profile from another server, or a scanner
    (re.compile(_TS + r"TLS Error: (?:(?:tls-crypt unwrapping|incoming packet authentication) failed|"
                r"could not determine wrapping) from \[AF_INET6?\]([0-9a-fA-F.:]+?):\d+"),
     lambda m: ("", "unknown control channel key", m[2])),
    # 2FA (log/oath.log, written by bin/oath.sh)
    (re.compile(_TS + r"2FA FAIL user='[^']*' cn='([^']*)' from='([^']*)' reason=(\S+)"),
     lambda m: (m[2], "2FA: " + m[4].replace("-", " "), m[3])),
    # one certificate on too many devices, or the guest range is full (bin/client-access.sh)
    (re.compile(_TS + r"client-access: refused cn='([^']*)' from='([^']*)' reason=(\S+)"),
     lambda m: (m[2], m[4].replace("-", " "), m[3])),
)


def parse_rejection(line: str) -> tuple[int, str, str, str] | None:
    """(time, client, reason, source address) of a rejected connection attempt in a log line."""
    for rx, fields in _REJECTS:
        m = rx.match(line)
        if m:
            client, reason, address = fields(m)
            return int(time.mktime(time.strptime(m[1], "%Y-%m-%d %H:%M:%S"))), client, reason, address
    return None


# A connection in openvpn.log. Before the certificate is accepted a line starts with the address
# ("udp4:203.0.113.5:1194 ..."), afterwards with "name/address".
_PEER_INFO = re.compile(_TS + r"([^/\s]+) peer info: IV_(PLAT|VER|GUI_VER)=(\S*)")
_PEER_OPEN = re.compile(_TS + r"([^/\s]+) \[([^\]]+)\] Peer Connection Initiated with ")
_PEER_END = re.compile(_TS + r"(?:([^/\s]+)/)?(\S+) SIG[A-Z0-9]+\[\w+,([^\]]*)\] received, client-instance ")
_END_REASONS = {
    "delayed-exit": "left", "remote-exit": "left",                      # the client said goodbye
    "ping-restart": "timed out", "ovpn-dco: ping expired": "timed out",  # it vanished: no keepalive
    "connection-reset": "closed", "ovpn-dco: transport disconnected": "closed",   # TCP connection ended
}
PENDING_MAX_AGE = 600       # a handshake seen in the log whose session never showed up in the status


def parse_connection(line: str) -> tuple | None:
    """("info", time, address, key, value), ("open", time, address, name) or
    ("end", time, address, name or None, reason) for a log line about a client connection."""
    for kind, rx in (("info", _PEER_INFO), ("open", _PEER_OPEN), ("end", _PEER_END)):
        m = rx.match(line)
        if m:
            ts = int(time.mktime(time.strptime(m[1], "%Y-%m-%d %H:%M:%S")))
            if kind == "info":
                return kind, ts, m[2], m[3], m[4]
            if kind == "open":
                return kind, ts, m[2], m[3]
            return kind, ts, m[3], m[2], _END_REASONS.get(m[4], m[4] or "ended")
    return None


def _offer(q: asyncio.Queue, item: dict[str, Any]) -> None:
    try:
        q.put_nowait(item)
    except asyncio.QueueFull:           # a slow reader skips updates
        pass


class Collector(threading.Thread):
    def __init__(self, db: Database, mgmt: Management, interval: float,
                 status_file: Callable[[], tuple[Path | None, int]] = lambda: (None, 0),
                 logs: tuple[Path, ...] = ()) -> None:
        super().__init__(name="collector", daemon=True)
        self.db, self.mgmt, self.interval = db, mgmt, interval
        self.status_file, self.logs = status_file, logs
        self._status_time: int | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self.heartbeat = time.monotonic()       # the last turn of run(): /healthz reports a stuck or dead collector
        self._subscribers: list[tuple[asyncio.AbstractEventLoop, asyncio.Queue]] = []
        # key -> {session_id, bytes_in, bytes_out, ts, rate_in, rate_out}
        self._active: dict[tuple[int, int, str], dict[str, Any]] = {}
        # Handshakes read from the log whose session row has no device yet: address -> {ts, cn, PLAT, ...}
        self._pending: dict[str, dict[str, Any]] = {}
        self._resync = False        # after a failed write: _active may not match the database
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
    # Subscribers are asyncio queues on the web server's event loop, so an open live stream
    # holds no worker thread; the collector thread hands snapshots over with call_soon_threadsafe.
    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=8)
        with self._lock:
            self._subscribers.append((asyncio.get_running_loop(), q))
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        with self._lock:
            self._subscribers = [s for s in self._subscribers if s[1] is not q]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return copy.deepcopy(self.live)

    def _publish(self) -> None:
        with self._lock:
            snap = copy.deepcopy(self.live)
            subs = list(self._subscribers)
        for loop, q in subs:
            try:
                loop.call_soon_threadsafe(_offer, q, snap)
            except RuntimeError:        # the event loop has shut down
                pass

    # -- main loop -----------------------------------------------------------
    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        try:
            closed = self.db.close_stale_sessions()
            if closed:
                log.info("closed %d VPN sessions left open by a previous run", closed)
        except Exception:
            log.exception("could not close the sessions of a previous run")
        backoff = 2.0
        while not self._stop.is_set():
            self.heartbeat = time.monotonic()
            delay = self.interval
            try:    # never let the thread die
                try:
                    self.poll()
                    backoff = 2.0
                except (ManagementError, OSError) as exc:
                    delay = backoff
                    backoff = min(backoff * 1.5, 15.0)
                    self._handle_down(str(exc))
            except Exception:
                # Most likely a failed database write, rolled back: forget what this thread
                # believes is stored and take it from the database on the next turn.
                log.exception("collector error")
                self._active.clear()
                self._status_time = None
                self._resync = True
            try:
                self.read_logs()    # after poll(): a session has its row before the log describes it
            except Exception:
                log.exception("reading the OpenVPN logs failed")
            self._stop.wait(delay)

    def alive(self) -> bool:
        """Running, and its last turn began no longer ago than a slow turn plus the pause takes."""
        return self.is_alive() and time.monotonic() - self.heartbeat < 180 + 2 * self.interval

    def read_logs(self, max_bytes: int = 4 << 20) -> None:
        """Take from the lines appended to the logs since the last call: rejected connection attempts,
        and for every session its device, protocol and the way it ended.
        The position survives restarts; a rotated (truncated or replaced) file is read from the start."""
        for path in self.logs:
            try:
                with open(path, "rb") as fh:
                    st = os.fstat(fh.fileno())
                    key = f"logpos:{path.name}"
                    inode, _, offset = (self.db.get_setting(key) or "0:0").partition(":")
                    pos = int(offset) if int(inode) == st.st_ino and int(offset) <= st.st_size else 0
                    fh.seek(pos)
                    data = fh.read(max_bytes)
            except (OSError, ValueError):
                continue
            end = data.rfind(b"\n") + 1          # only whole lines; the rest is read next time
            if not end:
                continue
            with self.db.tx() as conn:
                for line in data[:end].decode("utf-8", "replace").splitlines():
                    hit = parse_rejection(line)
                    if hit:
                        self.db.add_rejection(conn, *hit)
                        continue
                    hit = parse_connection(line)
                    if hit:
                        self._connection_line(conn, *hit)
                conn.execute("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET "
                             "value = excluded.value", (key, f"{st.st_ino}:{pos + end}"))
        if self._pending:
            with self.db.tx() as conn:
                self._describe_sessions(conn)

    def _connection_line(self, conn, kind: str, ts: int, address: str, *rest: Any) -> None:
        if kind == "info":
            self._pending.setdefault(address, {"ts": ts})[rest[0]] = rest[1]
        elif kind == "open":
            self._pending.setdefault(address, {}).update(ts=ts, cn=rest[0])
        else:
            cn, reason = rest
            peer = self._pending.pop(address, None)
            if cn is None:
                return                  # never got as far as a certificate: not a session
            row = self.db.latest_session(conn, cn, address, peer["ts"] - 30 if peer else 0)
            if row is not None:
                conn.execute("UPDATE vpn_sessions SET end_reason = ? WHERE id = ?", (reason, row["id"]))
                if peer:
                    self._set_device(conn, row["id"], address, peer)
            elif peer and peer.get("cn") == cn:
                # Shorter than the status interval, so poll() never saw it: the log is its only trace.
                sid = self.db.insert_session(conn, cn, address, peer["ts"], last_seen=ts, disconnected_at=ts,
                                             end_reason=reason)
                self._set_device(conn, sid, address, peer)

    @staticmethod
    def _set_device(conn, session_id: int, address: str, peer: dict[str, Any]) -> None:
        conn.execute("UPDATE vpn_sessions SET platform = ?, client_ver = ?, proto = COALESCE(?, proto) WHERE id = ?",
                     (peer.get("PLAT"), peer.get("GUI_VER") or peer.get("VER"), split_address(address)[0], session_id))

    def _describe_sessions(self, conn) -> None:
        """Give the sessions poll() has created since their handshake the device read from the log."""
        now = time.time()
        for address, peer in list(self._pending.items()):
            row = self.db.latest_session(conn, peer["cn"], address, peer["ts"] - 30) if peer.get("cn") else None
            if row is not None:
                self._set_device(conn, row["id"], address, peer)
            if row is not None or now - peer["ts"] > PENDING_MAX_AGE:
                del self._pending[address]

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
                if cl["cn"] in ("", "UNDEF") or not cl["vpn_ip"]:
                    continue        # still in the TLS handshake: no certificate accepted yet
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
                        session_id = self.db.insert_session(
                            conn, cl["cn"], cl["real_address"], connected_at, cid=cl["cid"], vpn_ip=cl["vpn_ip"],
                            username=cl["username"], cipher=cl["cipher"], last_seen=now,
                            bytes_in=cl["bytes_in"], bytes_out=cl["bytes_out"])
                        d_in, d_out = cl["bytes_in"], cl["bytes_out"]
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
            if self._resync:        # sessions that ended while _active was lost
                ids = [e["session_id"] for e in self._active.values()]
                conn.execute("UPDATE vpn_sessions SET disconnected_at = last_seen WHERE disconnected_at IS NULL "
                             f"AND id NOT IN ({', '.join('?' * len(ids))})", ids)
        self._resync = False

        live_clients.sort(key=lambda c: (c["cn"], c["connected_since"]))
        with self._lock:
            self.live.update(
                connected=True, error=None, version=version, server_time=status["time"], updated_at=now,
                connected_since=self.mgmt.connected_since, clients=live_clients, load=load,
                stats=status.get("stats", {}), rate_in=total_rate_in, rate_out=total_rate_out,
            )
        self._publish()

    def _close_sessions(self, conn, keys: list, now: int, reason: str | None = None) -> None:
        for key in keys:
            entry = self._active.pop(key)
            conn.execute("UPDATE vpn_sessions SET disconnected_at = ?, end_reason = COALESCE(end_reason, ?) "
                         "WHERE id = ? AND disconnected_at IS NULL", (now, reason, entry["session_id"]))

    def _handle_down(self, error: str) -> None:
        self._status_time = None
        if self._active:
            with self.db.tx() as conn:
                self._close_sessions(conn, list(self._active), int(time.time()), "server down")
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
