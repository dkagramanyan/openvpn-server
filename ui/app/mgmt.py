"""Client for the OpenVPN management interface (text protocol over TCP)."""
from __future__ import annotations

import re
import socket
import threading
import time
from typing import Any

NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")


class ManagementError(Exception):
    pass


class Management:
    def __init__(self, host: str, port: int, password: str | None = None, timeout: float = 10.0) -> None:
        self.host, self.port, self.password, self.timeout = host, port, password, timeout
        self._lock = threading.RLock()
        self._sock: socket.socket | None = None
        self._buf = b""
        self.connected_since: float | None = None

    # -- low level -------------------------------------------------------------
    @property
    def connected(self) -> bool:
        return self._sock is not None

    def close(self) -> None:
        with self._lock:
            if self._sock is not None:
                try:
                    self._sock.close()
                except OSError:
                    pass
            self._sock = None
            self._buf = b""
            self.connected_since = None

    def _connect(self) -> None:
        sock = socket.create_connection((self.host, self.port), timeout=5)
        sock.settimeout(self.timeout)
        self._sock, self._buf = sock, b""
        # OpenVPN either sends "ENTER PASSWORD:" (no newline) or the ">INFO:" greeting.
        deadline = time.monotonic() + 3
        while b"\n" not in self._buf and b"ENTER PASSWORD:" not in self._buf and time.monotonic() < deadline:
            try:
                data = sock.recv(4096)
            except socket.timeout:
                break
            if not data:
                raise ManagementError("management connection closed by server")
            self._buf += data
        if b"ENTER PASSWORD:" in self._buf:
            self._buf = self._buf.split(b"ENTER PASSWORD:", 1)[1]
            if not self.password:
                self.close()
                raise ManagementError("management interface requires a password but none is configured")
            sock.sendall((self.password + "\n").encode())
            line = self._readline()
            while line.startswith(">"):
                line = self._readline()
            if not line.startswith("SUCCESS:"):
                self.close()
                raise ManagementError(f"management password rejected: {line}")
        self.connected_since = time.time()

    def _readline(self) -> str:
        assert self._sock is not None
        while b"\n" not in self._buf:
            data = self._sock.recv(4096)
            if not data:
                raise ManagementError("management connection closed")
            self._buf += data
        line, self._buf = self._buf.split(b"\n", 1)
        return line.decode("utf-8", "replace").rstrip("\r")

    def command(self, cmd: str) -> list[str]:
        """Send a command and return its response lines (without the END marker)."""
        with self._lock:
            last_error: Exception | None = None
            for attempt in (1, 2):
                try:
                    if self._sock is None:
                        self._connect()
                    assert self._sock is not None
                    self._sock.sendall((cmd + "\n").encode())
                    lines: list[str] = []
                    while True:
                        line = self._readline()
                        if line.startswith(">"):        # asynchronous notification
                            continue
                        if line == "END":
                            return lines
                        lines.append(line)
                        if line.startswith(("SUCCESS:", "ERROR:")) and not lines[:-1]:
                            return lines
                except (OSError, ManagementError) as exc:
                    last_error = exc
                    self.close()
                    if attempt == 2:
                        break
            raise ManagementError(str(last_error) if last_error else "management command failed")

    # -- commands ----------------------------------------------------------------
    def status(self) -> dict[str, Any]:
        lines = self.command("status 3")
        headers: dict[str, list[str]] = {}
        clients: list[dict[str, Any]] = []
        server_time: int | None = None
        stats: dict[str, str] = {}
        for line in lines:
            parts = line.split("\t")
            tag = parts[0]
            if tag == "HEADER" and len(parts) > 2:
                headers[parts[1]] = parts[2:]
            elif tag == "CLIENT_LIST":
                rec = dict(zip(headers.get("CLIENT_LIST", []), parts[1:]))
                clients.append(_normalise_client(rec))
            elif tag == "TIME" and len(parts) > 2:
                try:
                    server_time = int(parts[2])
                except ValueError:
                    pass
            elif tag == "GLOBAL_STATS" and len(parts) > 2:
                stats[parts[1]] = parts[2]
        return {"time": server_time or int(time.time()), "clients": clients, "stats": stats}

    def load_stats(self) -> dict[str, int]:
        line = self.command("load-stats")[0]
        if not line.startswith("SUCCESS:"):
            raise ManagementError(line)
        out: dict[str, int] = {}
        for kv in line.split(":", 1)[1].split(","):
            k, _, v = kv.strip().partition("=")
            if v.isdigit():
                out[k] = int(v)
        return out

    def version(self) -> str:
        for line in self.command("version"):
            if line.startswith("OpenVPN Version:"):
                return line.split(":", 1)[1].strip()
        return "unknown"

    def pid(self) -> int | None:
        line = self.command("pid")[0]
        m = re.search(r"pid=(\d+)", line)
        return int(m.group(1)) if m else None

    def kill(self, common_name: str) -> str:
        if not NAME_RE.match(common_name):
            raise ManagementError("invalid common name")
        line = self.command(f"kill {common_name}")[0]
        if not line.startswith("SUCCESS:"):
            raise ManagementError(line)
        return line

    def client_kill(self, cid: int) -> str:
        line = self.command(f"client-kill {int(cid)}")[0]
        if not line.startswith("SUCCESS:"):
            raise ManagementError(line)
        return line

    def signal(self, name: str) -> str:
        if name not in ("SIGHUP", "SIGTERM", "SIGUSR1", "SIGUSR2"):
            raise ManagementError("unsupported signal")
        try:
            line = self.command(f"signal {name}")[0]
        finally:
            self.close()
        if not line.startswith("SUCCESS:"):
            raise ManagementError(line)
        return line


def _int(value: str | None) -> int:
    try:
        return int(value or 0)
    except ValueError:
        return 0


def _normalise_client(rec: dict[str, str]) -> dict[str, Any]:
    return {
        "cn": rec.get("Common Name", ""),
        "real_address": rec.get("Real Address", ""),
        "vpn_ip": rec.get("Virtual Address", "") or "",
        "vpn_ipv6": rec.get("Virtual IPv6 Address", "") or "",
        "bytes_in": _int(rec.get("Bytes Received")),
        "bytes_out": _int(rec.get("Bytes Sent")),
        "connected_since": _int(rec.get("Connected Since (time_t)")),
        "username": rec.get("Username", "") or "",
        "cid": _int(rec.get("Client ID")),
        "peer_id": _int(rec.get("Peer ID")),
        "cipher": rec.get("Data Channel Cipher", "") or "",
    }
