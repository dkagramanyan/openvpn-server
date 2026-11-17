"""Traffic by podkop section.

The LAN router runs podkop: names in a section's lists resolve to FakeIP addresses
(198.18.0.0/15), addresses in its subnet lists are routed by address, and only
these two go through podkop; everything else leaves directly. This server knows
who sent each connection and how many bytes it carried, the router knows which
section a destination belongs to. So:

* OpenVPN: the container writes the end of every VPN client's connection with its
  bytes to log/flows.log (conntrack); the client is the one that had that VPN
  address at the time.
* Apple relay: every finished relay connection is saved in relay_flows with the
  name the client asked for and the address the relay dialled.

Finished connections wait in section_pending until the router's agent answers
for their destinations (a restricted SSH key that may run only "podkop-agent
sections"), then their bytes are added to section_traffic (kept forever) and,
per domain, to section_domains (kept 7 days).
"""
from __future__ import annotations

import bisect
import ipaddress
import json
import logging
import os
import re
import subprocess
import threading
import time
from pathlib import Path
from typing import Any, Callable

from .settings import settings

log = logging.getLogger("openvpn-ui.sections")

FAKEIP = ipaddress.ip_network("198.18.0.0/15")
DIRECT, UNKNOWN = "", "?"
POLL_SECONDS = 30
BATCH = 500                    # items per list in one agent call (the agent's limit)
PENDING_MAX_AGE = 3600         # unanswered for an hour: counted as "section unknown"
SUBNETS_MAX_AGE = 3600         # the router's address lists are fetched again after an hour
CHECK_SECONDS = 300            # the router is asked at least this often, traffic or not
SESSION_SLACK = 600            # a connection may end this long after its VPN session
START_SLACK = 120              # ... and its start is known (delta-time): the session's last sighting may lag this much
KEY_COMMENT = "openvpn-server-sections"
HOST_RX = re.compile(r"^[A-Za-z0-9_](?:[A-Za-z0-9_.-]{0,251}[A-Za-z0-9_])?$")


class SectionsUnavailable(Exception):
    pass


# -- router access -----------------------------------------------------------------
def router_dir() -> Path:
    return settings.openvpn_dir / "config" / "router"


def key_path() -> Path:
    return router_dir() / "id_ed25519"


def get_router(db) -> dict[str, Any]:
    return json.loads(db.get_setting("router_sections") or "{}")


def validate_address(value: str) -> str:
    """user@host or host (root by default); host is a name or an IPv4 address."""
    value = value.strip()
    if not value:
        return ""
    user, _, host = value.rpartition("@")
    user = user or "root"
    if not re.fullmatch(r"[a-z_][a-z0-9_-]{0,31}", user) or not HOST_RX.match(host):
        raise ValueError("Router address must be host or user@host, e.g. root@192.168.1.1")
    return f"{user}@{host}"


def authorized_line() -> str | None:
    """The line for the router's /etc/dropbear/authorized_keys: this key may run only the lookup."""
    try:
        kind, blob = (key_path().with_suffix(".pub")).read_text().split()[:2]
    except (OSError, ValueError):
        return None
    return f'restrict,command="/usr/bin/podkop-agent --sections-only" {kind} {blob} {KEY_COMMENT}'


def router_command() -> str | None:
    """One line for the router's terminal: this key's line into authorized_keys, replacing an older one of ours."""
    line = authorized_line()
    if line is None:
        return None
    keys = "/etc/dropbear/authorized_keys"
    return (f"sed -i '/ {KEY_COMMENT}$/d' {keys} 2>/dev/null; echo '{line}' >> {keys} && chmod 600 {keys} "
            "&& echo 'key added: press Test in the OpenVPN UI'")


def create_key(replace: bool = False) -> str:
    path = key_path()
    if path.exists() and not replace:
        raise ValueError("A key exists already")
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    for old in (path, path.with_suffix(".pub")):
        old.unlink(missing_ok=True)
    subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", KEY_COMMENT, "-f", str(path)],
                   check=True, capture_output=True, timeout=20)
    os.chmod(path, 0o600)
    return authorized_line() or ""


def ssh_call(address: str, request: dict[str, Any], timeout: float = 25) -> dict[str, Any]:
    """Run "sections" on the router with the request as JSON on stdin; the agent's data."""
    if not key_path().is_file():
        raise SectionsUnavailable("no router key yet")
    command = ["ssh", "-i", str(key_path()), "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes",
               "-o", "UserKnownHostsFile=" + str(router_dir() / "known_hosts"),
               "-o", "StrictHostKeyChecking=accept-new", "-o", "ConnectTimeout=5",
               "-o", "LogLevel=ERROR", "-T", address, "sections"]
    try:
        p = subprocess.run(command, input=json.dumps(request).encode(), capture_output=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SectionsUnavailable(f"router did not answer: {exc.__class__.__name__}") from None
    line = p.stdout.decode("utf-8", "replace").strip().splitlines()[-1:] or [""]
    try:
        answer = json.loads(line[0])
    except ValueError:
        detail = p.stderr.decode("utf-8", "replace").strip().splitlines()[-1:] or ["no answer"]
        raise SectionsUnavailable(f"router refused the call: {detail[0][:200]}") from None
    if not answer.get("ok"):
        error = answer.get("error") or {}
        raise SectionsUnavailable(f"agent: {error.get('code', 'error')}: {str(error.get('message', ''))[:200]}")
    data = answer.get("data")
    if not isinstance(data, dict):
        raise SectionsUnavailable("agent: malformed answer")
    return data


# -- address lists -----------------------------------------------------------------
def ip_int(text: str) -> int | None:
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    return int(address) if address.version == 4 else None


class Ranges:
    """The router's podkop address set: CIDRs and inclusive "a-b" ranges, matched by bisection."""

    def __init__(self, items: list[str]) -> None:
        spans = []
        for item in items:
            try:
                if "-" in item:
                    first, last = (int(ipaddress.IPv4Address(x.strip())) for x in item.split("-", 1))
                else:
                    net = ipaddress.IPv4Network(item.strip(), strict=False)
                    first, last = int(net.network_address), int(net.broadcast_address)
            except ValueError:
                continue
            if first <= last:
                spans.append((first, last))
        spans.sort()
        merged: list[list[int]] = []
        for first, last in spans:
            if merged and first <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], last)
            else:
                merged.append([first, last])
        self.starts = [s for s, _ in merged]
        self.ends = [e for _, e in merged]

    def __contains__(self, value: int) -> bool:
        i = bisect.bisect_right(self.starts, value) - 1
        return i >= 0 and value <= self.ends[i]

    def __len__(self) -> int:
        return len(self.starts)


def is_fakeip(address: str) -> bool:
    value = ip_int(address)
    return value is not None and int(FAKEIP.network_address) <= value <= int(FAKEIP.broadcast_address)


def literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


# -- conntrack lines ---------------------------------------------------------------
_TS = re.compile(r"^\[(\d+)(?:\.\d+)?\]")
_PROTO = re.compile(r"\[DESTROY\]\s+(tcp|udp|icmp|\w+)\s")


def parse_flow(line: str) -> dict[str, Any] | None:
    """One end-of-connection line of `conntrack -E -e DESTROY -o timestamp`: time, the client's
    VPN address, the destination, its port and the bytes of both directions. The first tuple is
    the client's direction (upload), the second the answers (download)."""
    m = _TS.match(line)
    if not m or "[DESTROY]" not in line:
        return None
    fields = line.split()
    src = [f[4:] for f in fields if f.startswith("src=")]
    dst = [f[4:] for f in fields if f.startswith("dst=")]
    dport = [f[6:] for f in fields if f.startswith("dport=")]
    counts = [f[6:] for f in fields if f.startswith("bytes=")]
    if not src or not dst or ip_int(src[0]) is None or ip_int(dst[0]) is None:
        return None
    proto = _PROTO.search(line)
    try:
        up = int(counts[0]) if counts else 0
        down = int(counts[1]) if len(counts) > 1 else 0
    except ValueError:
        return None
    # With net.netfilter.nf_conntrack_timestamp=1 the line says how long the connection lived.
    age = [f[11:] for f in fields if f.startswith("delta-time=")]
    ts = int(m[1])
    return {"ts": ts, "start": ts - int(age[0]) if age and age[0].isdigit() else None,
            "proto": proto[1] if proto else "", "src": src[0], "dst": dst[0],
            "dport": int(dport[0]) if dport and dport[0].isdigit() else 0, "bytes_in": up, "bytes_out": down}


# -- the collector -----------------------------------------------------------------
def hour(ts: int) -> int:
    return ts - ts % 3600


class SectionCollector(threading.Thread):
    def __init__(self, db, call: Callable[[str, dict], dict] | None = None,
                 flows_log: Path | None = None) -> None:
        super().__init__(name="sections", daemon=True)
        self.db = db
        self.call = call or ssh_call
        self.flows_log = flows_log or settings.log_dir / "flows.log"
        self._stop_event = threading.Event()
        self.ranges: Ranges | None = None
        self.ranges_at = 0.0
        self.sections: list[str] = []
        self.status: dict[str, Any] = {"last_ok": None, "last_error": None, "error": None, "unmapped": 0,
                                       "agent": None}

    # ---- intake
    def client_at(self, conn, vpn_ip: str, ts: int, start: int | None = None) -> str | None:
        """The client that had this VPN address when the connection began. An address is given to
        the next client at once, and a connection can be forgotten by the kernel long after its
        client left, so the start is what tells them apart. Without it (no connection timestamps
        on the host): the client that had the address when the connection ended."""
        when, slack = (start, START_SLACK) if start is not None else (ts, SESSION_SLACK)
        row = conn.execute(
            "SELECT client_name FROM vpn_sessions WHERE vpn_ip = ? AND connected_at <= ? "
            "AND COALESCE(disconnected_at, last_seen) + ? >= ? ORDER BY connected_at DESC, id DESC LIMIT 1",
            (vpn_ip, when + (5 if start is not None else 0), slack, when)).fetchone()
        return row["client_name"] if row else None

    def read_vpn(self, max_bytes: int = 4 << 20, now: int | None = None) -> int:
        """New lines of log/flows.log into section_pending. The position (inode and offset) is saved
        with them; a truncated or replaced file is read from its start."""
        now = int(time.time()) if now is None else now
        tail = b""
        try:
            with open(self.flows_log, "rb") as fh:
                st = os.fstat(fh.fileno())
                inode, _, offset = (self.db.get_setting("logpos:flows.log") or "0:0").partition(":")
                pos = int(offset) if int(inode) == st.st_ino and int(offset) <= st.st_size else 0
                if pos == 0 and int(inode) == st.st_ino and int(offset) > st.st_size:
                    tail = self._rotated_tail(int(offset), max_bytes)     # cut since the last look
                fh.seek(pos)
                data = fh.read(max_bytes)
        except (OSError, ValueError):
            return 0
        end = data.rfind(b"\n") + 1
        if not end and not tail:
            return 0
        data = tail + data[:end]
        end_pos = pos + end
        added = 0
        with self.db.tx() as conn:
            cache: dict[tuple[str, int], str | None] = {}
            for line in data.decode("utf-8", "replace").splitlines():
                flow = parse_flow(line)
                if not flow or (flow["bytes_in"] == 0 and flow["bytes_out"] == 0):
                    continue
                when = flow["start"] if flow["start"] is not None else flow["ts"]
                key = (flow["src"], when // 60, flow["start"] is None)
                if key not in cache:
                    cache[key] = self.client_at(conn, flow["src"], flow["ts"], flow["start"])
                client = cache[key]
                if client is None:
                    self.status["unmapped"] += 1
                    continue
                conn.execute("INSERT INTO section_pending (ts, client_name, source, address, host, bytes_in, bytes_out, "
                             "queued_at) VALUES (?, ?, 'vpn', ?, '', ?, ?, ?)",
                             (flow["ts"], client, flow["dst"], flow["bytes_in"], flow["bytes_out"], now))
                added += 1
            conn.execute("INSERT INTO settings (key, value) VALUES ('logpos:flows.log', ?) ON CONFLICT(key) DO UPDATE "
                         "SET value = excluded.value", (f"{st.st_ino}:{end_pos}",))
        return added

    def _rotated_tail(self, offset: int, max_bytes: int) -> bytes:
        """The log was copied to flows.log.1 and emptied: the lines written after the last look are there."""
        try:
            with open(str(self.flows_log) + ".1", "rb") as fh:
                if os.fstat(fh.fileno()).st_size < offset:
                    return b""
                fh.seek(offset)
                data = fh.read(max_bytes)
        except OSError:
            return b""
        return data[:data.rfind(b"\n") + 1]

    def read_relay(self, limit: int = 5000, now: int | None = None) -> int:
        """Finished relay connections with traffic into section_pending, once each."""
        now = int(time.time()) if now is None else now
        with self.db.tx() as conn:
            rows = conn.execute(
                "SELECT instance, id, client_name, ts, target, address, bytes_up, bytes_down FROM relay_flows "
                "WHERE NOT sectioned ORDER BY ts LIMIT ?", (limit,)).fetchall()
            for r in rows:
                address = (r["address"] or "").rpartition(":")[0].strip("[]")
                host = (r["target"] or "").rpartition(":")[0].strip("[]").lower().rstrip(".")
                if ip_int(address) is not None and (r["bytes_up"] or r["bytes_down"]):
                    conn.execute("INSERT INTO section_pending (ts, client_name, source, address, host, bytes_in, "
                                 "bytes_out, queued_at) VALUES (?, ?, 'relay', ?, ?, ?, ?, ?)",
                                 (r["ts"], r["client_name"], address, "" if literal(host) else host[:253],
                                  r["bytes_up"], r["bytes_down"], now))
                conn.execute("UPDATE relay_flows SET sectioned = true WHERE instance = ? AND id = ?",
                             (r["instance"], r["id"]))
        return len(rows)

    # ---- classification
    def _ask(self, address: str, domains: list[str], addresses: list[str], subnets: bool) -> dict[str, Any]:
        merged: dict[str, Any] = {"domains": {}, "addresses": {}}
        chunks = max(1, -(-len(domains) // BATCH), -(-len(addresses) // BATCH))
        for i in range(chunks):
            data = self.call(address, {"domains": domains[i * BATCH:(i + 1) * BATCH],
                                       "addresses": addresses[i * BATCH:(i + 1) * BATCH],
                                       "subnets": subnets and i == 0})
            merged["domains"].update(data.get("domains") or {})
            merged["addresses"].update(data.get("addresses") or {})
            for key in ("boot_id", "sections", "agent"):
                if key in data:
                    merged[key] = data[key]
            if subnets and i == 0 and isinstance(data.get("subnets"), list):
                merged["subnets"] = data["subnets"]
        return merged

    def _answered(self, answer: dict[str, Any] | None, now: int, error: str | None = None) -> None:
        """Keep the router's state; its going silent and its coming back are events."""
        was_down = bool(self.status["error"])
        if answer is None:
            self.status.update(last_error=now, error=error)
            if not was_down:
                self.db.add_event("router_sections_down", detail=(error or "")[:200])
            return
        if "subnets" in answer:
            self.ranges, self.ranges_at = Ranges(answer["subnets"]), now
        self.sections = [s for s in answer.get("sections") or [] if isinstance(s, str)]
        self.status.update(last_ok=now, error=None, agent=str(answer.get("agent") or "")[:32] or None)
        if was_down:
            self.db.add_event("router_sections_up")

    def check(self, now: int | None = None) -> None:
        """Ask the router when nothing else did for CHECK_SECONDS: is the agent there, its sections and lists."""
        now = int(time.time()) if now is None else now
        address = get_router(self.db).get("address", "")
        if not address or now - max(self.status["last_ok"] or 0, self.status["last_error"] or 0) < CHECK_SECONDS:
            return
        try:
            self._answered(self._ask(address, [], [], self.ranges is None or now - self.ranges_at > SUBNETS_MAX_AGE), now)
        except SectionsUnavailable as exc:
            self._answered(None, now, str(exc))

    def classify(self, now: int | None = None) -> int:
        """Answer the waiting connections and add their bytes to the totals."""
        now = int(time.time()) if now is None else now
        rows = self.db.query("SELECT * FROM section_pending ORDER BY id LIMIT 20000")
        if not rows:
            return 0
        address = get_router(self.db).get("address", "")
        answer: dict[str, Any] | None = None
        ask: list[str] = []
        if address:
            need_subnets = self.ranges is None or now - self.ranges_at > SUBNETS_MAX_AGE
            domains = sorted({r["host"] for r in rows if r["host"] and is_fakeip(r["address"])})
            ask = sorted({r["address"] for r in rows if is_fakeip(r["address"])
                          or (self.ranges is not None and ip_int(r["address"]) in self.ranges)})
            try:
                answer = self._ask(address, domains, ask, need_subnets)
                self._answered(answer, now)
                if "subnets" in answer:
                    # The lists came with this answer: ask at once about the addresses in them.
                    extra = sorted({r["address"] for r in rows if r["address"] not in set(ask)
                                    and ip_int(r["address"]) in self.ranges})
                    if extra:
                        more = self._ask(address, [], extra, False)
                        answer["addresses"].update(more["addresses"])
                        ask = ask + extra
            except SectionsUnavailable as exc:
                self._answered(None, now, str(exc))
                answer = None
        boot = answer.get("boot_id") if answer else None
        rebooted = bool(boot and self.db.get_setting("sections:boot_id") not in (None, boot))
        done: list[tuple[dict[str, Any], str, str]] = []
        for r in rows:
            result = self._result(r, answer, rebooted, now, set(ask))
            if result is not None:
                done.append((r, *result))
        if done:
            self._book(done)
        if boot:
            self.db.set_setting("sections:boot_id", boot)
        return len(done)

    def _result(self, r: dict[str, Any], answer: dict[str, Any] | None, rebooted: bool,
                now: int, asked: set[str] = frozenset()) -> tuple[str, str] | None:
        """(section, domain) of a waiting connection, or None to keep it waiting."""
        old = now - r["queued_at"] > PENDING_MAX_AGE
        relay_host = r["host"]
        value = ip_int(r["address"])
        if is_fakeip(r["address"]):
            if answer is None:
                return (UNKNOWN, relay_host) if old else None
            if rebooted:      # the router may have handed this FakeIP to another name since
                return UNKNOWN, relay_host
            hit = answer["addresses"].get(r["address"])
            if isinstance(hit, dict) and hit.get("section"):
                return str(hit["section"]), str(hit.get("host") or relay_host)
            if relay_host and answer["domains"].get(relay_host):
                return str(answer["domains"][relay_host]), relay_host
            return UNKNOWN, relay_host
        if self.ranges is None:
            return (UNKNOWN, relay_host) if old else None
        if value is not None and value in self.ranges:
            if answer is None or r["address"] not in asked:   # (the lists arrived in this very answer)
                return (UNKNOWN, relay_host) if old else None
            hit = answer["addresses"].get(r["address"])
            if isinstance(hit, dict) and hit.get("section"):
                return str(hit["section"]), str(hit.get("host") or relay_host)
            return UNKNOWN, relay_host
        return DIRECT, relay_host

    def _book(self, done: list[tuple[dict[str, Any], str, str]]) -> None:
        totals: dict[tuple, list[int]] = {}
        domains: dict[tuple, list[int]] = {}
        for r, section, domain in done:
            key = (hour(r["ts"]), r["client_name"], r["source"], section[:64])
            t = totals.setdefault(key, [0, 0, 0])
            t[0] += r["bytes_in"]; t[1] += r["bytes_out"]; t[2] += 1
            domain = domain.lower().rstrip(".")[:253]
            if domain and HOST_RX.match(domain):
                d = domains.setdefault(key + (domain,), [0, 0, 0])
                d[0] += r["bytes_in"]; d[1] += r["bytes_out"]; d[2] += 1
        with self.db.tx() as conn:
            for key, (bi, bo, n) in totals.items():
                conn.execute("""INSERT INTO section_traffic (ts, client_name, source, section, bytes_in, bytes_out, flows)
                                VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT (ts, client_name, source, section) DO UPDATE SET
                                bytes_in = section_traffic.bytes_in + excluded.bytes_in,
                                bytes_out = section_traffic.bytes_out + excluded.bytes_out,
                                flows = section_traffic.flows + excluded.flows""", (*key, bi, bo, n))
            for key, (bi, bo, n) in domains.items():
                conn.execute("""INSERT INTO section_domains (ts, client_name, source, section, domain, bytes_in, bytes_out,
                                flows) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                                ON CONFLICT (ts, client_name, source, section, domain) DO UPDATE SET
                                bytes_in = section_domains.bytes_in + excluded.bytes_in,
                                bytes_out = section_domains.bytes_out + excluded.bytes_out,
                                flows = section_domains.flows + excluded.flows""", (*key, bi, bo, n))
            ids = [r["id"] for r, _, _ in done]
            for i in range(0, len(ids), 1000):
                part = ids[i:i + 1000]
                conn.execute(f"DELETE FROM section_pending WHERE id IN ({', '.join('?' * len(part))})", part)

    def poll(self, now: int | None = None) -> None:
        if not get_router(self.db).get("address"):
            return          # switched off: nothing is read, nothing waits
        self.read_vpn(now=now)
        self.read_relay(now=now)
        self.classify(now=now)
        self.check(now=now)

    def run(self) -> None:
        while not self._stop_event.wait(POLL_SECONDS):
            try:
                self.poll()
            except Exception:
                log.exception("Could not count the traffic by section")

    def stop(self) -> None:
        self._stop_event.set()
        self.join(timeout=10)


# -- reports -----------------------------------------------------------------------
def report(db, start: int, end: int, client: str | None = None, *, domains: bool = False,
           top_clients: int = 5, top_domains: int = 10) -> dict[str, Any]:
    """Totals per section in [start, end): both sources together and split, the share of
    "section unknown", and either the top clients (all clients) or the top domains."""
    where, args = "ts >= ? AND ts < ?", [start, end]
    if client is not None:
        where += " AND client_name = ?"
        args.append(client)
    rows = db.query(f"""SELECT section, source, client_name, SUM(bytes_in) AS bi, SUM(bytes_out) AS bo, SUM(flows) AS n
                        FROM section_traffic WHERE {where} GROUP BY section, source, client_name""", args)
    sections: dict[str, dict[str, Any]] = {}
    for r in rows:
        s = sections.setdefault(r["section"], {"section": r["section"], "bytes_in": 0, "bytes_out": 0, "flows": 0,
                                               "vpn": {"bytes_in": 0, "bytes_out": 0},
                                               "relay": {"bytes_in": 0, "bytes_out": 0}, "_clients": {}})
        bi, bo = int(r["bi"] or 0), int(r["bo"] or 0)
        s["bytes_in"] += bi; s["bytes_out"] += bo; s["flows"] += int(r["n"] or 0)
        part = s.get(r["source"])
        if part is not None:
            part["bytes_in"] += bi; part["bytes_out"] += bo
        s["_clients"][r["client_name"]] = s["_clients"].get(r["client_name"], 0) + bi + bo
    detail_from = int(time.time()) - 7 * 86400
    domains_available = domains and start >= hour(detail_from) - 3600
    if domains_available:
        for r in db.query(f"""SELECT section, domain, SUM(bytes_in) AS bi, SUM(bytes_out) AS bo, SUM(flows) AS n
                              FROM section_domains WHERE {where} GROUP BY section, domain""", args):
            s = sections.get(r["section"])
            if s is not None:
                s.setdefault("domains", []).append({"domain": r["domain"], "bytes_in": int(r["bi"] or 0),
                                                    "bytes_out": int(r["bo"] or 0), "flows": int(r["n"] or 0)})
    total = 0
    out = []
    for s in sections.values():
        clients = s.pop("_clients")
        if client is None:
            s["clients"] = [{"name": n, "bytes": b} for n, b in sorted(clients.items(), key=lambda kv: -kv[1])[:top_clients]]
        if "domains" in s:
            s["domains"] = sorted(s["domains"], key=lambda d: -(d["bytes_in"] + d["bytes_out"]))[:top_domains]
        total += s["bytes_in"] + s["bytes_out"]
        out.append(s)
    out.sort(key=lambda s: (s["section"] in (DIRECT, UNKNOWN), -(s["bytes_in"] + s["bytes_out"])))
    unknown = sections.get(UNKNOWN)
    unknown_bytes = (unknown["bytes_in"] + unknown["bytes_out"]) if unknown else 0
    podkop = total - ((sections[DIRECT]["bytes_in"] + sections[DIRECT]["bytes_out"]) if DIRECT in sections else 0)
    return {"sections": out, "bytes": total, "unknown_share": (unknown_bytes / podkop) if podkop else 0.0,
            "domains_available": bool(domains_available), "detail_days": 7}
