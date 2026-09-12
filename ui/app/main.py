"""HTTP API and static frontend."""
from __future__ import annotations

import json
import logging
import queue
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from . import __version__, auth, pki
from .collector import Collector, Maintenance
from .db import Database
from .mgmt import Management, ManagementError
from .pki import PkiError
from .settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("openvpn-ui")

COOKIE = "ovpn_session"
STATIC_DIR = Path(__file__).parent / "static"
EXPIRING_DAYS = 30
RANGES = {"today": None, "24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400, "all": None}

db = Database(settings.db_path)
_mgmt_host, _mgmt_port, _ = settings.management_endpoint()
mgmt = Management(_mgmt_host, _mgmt_port, settings.management_password())
collector = Collector(db, mgmt, settings.poll_interval)
maintenance = Maintenance(db, [lambda: pki.ensure_crl_fresh()])
limiter = auth.LoginLimiter()


# -- startup ---------------------------------------------------------------------
def bootstrap() -> None:
    for d in (settings.clients_dir, settings.static_dir, settings.db_path.parent):
        d.mkdir(parents=True, exist_ok=True)
    if db.one("SELECT 1 FROM users LIMIT 1") is None:
        password = settings.admin_password or secrets.token_urlsafe(12)
        db.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                   (settings.admin_username, auth.hash_password(password), int(time.time())))
        if settings.admin_password:
            log.info("created admin user '%s'", settings.admin_username)
        else:
            log.warning("created admin user '%s' with generated password: %s  (change it in Settings)",
                        settings.admin_username, password)
    if settings.public_host:
        wanted = f"{settings.public_host}:{settings.public_port}:{settings.public_proto}"
        if db.get_setting("remote_from_env") != wanted:
            try:
                pki.set_remote(settings.public_host, settings.public_port, settings.public_proto)
                db.set_setting("remote_from_env", wanted)
                log.info("client profiles now point at %s", wanted)
            except PkiError as exc:
                log.error("cannot apply OVPN_PUBLIC_HOST: %s", exc)


@asynccontextmanager
async def lifespan(_: FastAPI):
    bootstrap()
    if not mgmt.password:
        log.warning("no management password found (%s); connecting without one",
                    settings.management_endpoint()[2])
    collector.start()
    maintenance.start()
    yield
    collector.stop()
    maintenance.stop()
    mgmt.close()


app = FastAPI(title="OpenVPN UI", version=__version__, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    h = response.headers
    h.setdefault("X-Content-Type-Options", "nosniff")
    h.setdefault("X-Frame-Options", "DENY")
    h.setdefault("Referrer-Policy", "same-origin")
    h.setdefault("Content-Security-Policy",
                 "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
                 "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
    if request.url.path.startswith("/api/"):
        h["Cache-Control"] = "no-store"
    return response


@app.exception_handler(PkiError)
async def pki_error(_: Request, exc: PkiError):
    return JSONResponse({"detail": str(exc)}, status_code=400)


@app.exception_handler(ManagementError)
async def mgmt_error(_: Request, exc: ManagementError):
    return JSONResponse({"detail": f"OpenVPN management interface: {exc}"}, status_code=503)


# -- auth helpers -----------------------------------------------------------------
def client_ip(request: Request) -> str:
    return request.client.host if request.client else "?"


def cookie_secure(request: Request) -> bool:
    if settings.secure_cookies in ("true", "1", "yes"):
        return True
    if settings.secure_cookies in ("false", "0", "no"):
        return False
    return request.url.scheme == "https"


def current_user(request: Request) -> dict[str, Any]:
    user = auth.get_session_user(db, request.cookies.get(COOKIE), settings.session_ttl)
    if user is None:
        raise HTTPException(401, "Not authenticated")
    return user


def csrf_check(request: Request) -> None:
    if request.headers.get("x-requested-with") != "fetch":
        raise HTTPException(403, "Missing X-Requested-With header")
    origin = request.headers.get("origin")
    if origin and origin != "null":
        if urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
            raise HTTPException(403, "Cross-origin request rejected")


Authed = Depends(current_user)
Csrf = Depends(csrf_check)


# -- models ---------------------------------------------------------------------
class LoginBody(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class PasswordBody(BaseModel):
    current: str = Field(max_length=256)
    new: str = Field(min_length=8, max_length=256)


class NewClientBody(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    days: int | None = Field(default=None, ge=1, le=3650)
    passphrase: str | None = Field(default=None, max_length=256)
    static_ip: str | None = Field(default=None, max_length=15)
    tfa: bool = False
    note: str = Field(default="", max_length=500)


class ReasonBody(BaseModel):
    reason: str | None = None


class DaysBody(BaseModel):
    days: int | None = Field(default=None, ge=1, le=3650)


class TfaBody(BaseModel):
    enabled: bool


class DisconnectBody(BaseModel):
    cid: int | None = None


class StaticIpBody(BaseModel):
    ip: str | None = Field(default=None, max_length=15)


class NoteBody(BaseModel):
    note: str = Field(default="", max_length=500)


class ConfigBody(BaseModel):
    content: str = Field(max_length=200_000)


class TfaEnforceBody(BaseModel):
    enforced: bool


class RemoteBody(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(ge=1, le=65535)
    proto: str = Field(pattern="^(udp|tcp)$")


# -- helpers --------------------------------------------------------------------
def range_bounds(name: str, tz: int) -> tuple[int, int]:
    now = int(time.time())
    if name not in RANGES:
        raise HTTPException(400, "Unknown range")
    if name == "today":
        start = ((now + tz) // 86400) * 86400 - tz
    elif name == "all":
        start = db.first_traffic_ts() or now - 86400
    else:
        start = now - int(RANGES[name] or 0)
    return start, now + 1


def bucket_for(name: str) -> int:
    return {"today": 600, "24h": 600, "7d": 3600}.get(name, 86400)


def hidden_serials() -> set[str]:
    return {r["serial"] for r in db.query("SELECT serial FROM hidden_certs")}


def fill_series(points: list[dict[str, int]], start: int, end: int, bucket: int, tz: int = 0) -> list[dict[str, int]]:
    by_ts = {p["ts"]: p for p in points}
    first = ((start + tz) // bucket) * bucket - tz
    out = []
    t = first
    while t < end:
        p = by_ts.get(t)
        out.append({"ts": t, "bytes_in": p["bytes_in"] if p else 0, "bytes_out": p["bytes_out"] if p else 0})
        t += bucket
    return out


def clients_payload(range_name: str, tz: int) -> list[dict[str, Any]]:
    start, end = range_bounds(range_name, tz)
    certs = pki.list_clients(hidden_serials())
    statics = pki.static_ips()
    tfa = pki.tfa_secrets()
    live = collector.snapshot()
    online: dict[str, list[dict[str, Any]]] = {}
    for c in live["clients"]:
        online.setdefault(c["cn"], []).append(c)
    period = db.totals_by_client(start, end)
    totals = db.session_stats_by_client()
    notes = {r["name"]: r["note"] for r in db.query("SELECT name, note FROM clients")}
    now = int(time.time())
    rows = []
    for name, c in certs.items():
        cert = c["cert"]
        p_in, p_out = period.get(name, (0, 0))
        t = totals.get(name, {})
        rows.append({
            "name": name,
            "state": cert["state"],
            "cert": cert,
            "previous": c["previous"],
            "history": c["history"],
            "expires": cert["not_after"],
            "days_left": (cert["not_after"] - now) // 86400 if cert["not_after"] else None,
            "static_ip": statics.get(name),
            "tfa": name in tfa,
            "online": bool(online.get(name)),
            "sessions_live": online.get(name, []),
            "traffic": {"bytes_in": p_in, "bytes_out": p_out},
            "total": {"bytes_in": t.get("bytes_in", 0), "bytes_out": t.get("bytes_out", 0),
                      "sessions": t.get("sessions", 0), "last_seen": t.get("last_seen"),
                      "first_seen": t.get("first_seen"), "online_seconds": t.get("online_seconds", 0)},
            "note": notes.get(name, ""),
        })
    order = {"valid": 0, "expired": 1, "revoked": 2}
    rows.sort(key=lambda r: (not r["online"], order.get(r["state"], 3), r["name"].lower()))
    return rows


def find_client(name: str) -> dict[str, Any]:
    pki.validate_name(name)
    for row in clients_payload("today", 0):
        if row["name"] == name:
            return row
    raise HTTPException(404, "Client not found")


def event(kind: str, user: dict[str, Any] | None, client: str | None = None, detail: str | None = None) -> None:
    db.add_event(kind, client, user["username"] if user else None, detail)


# -- auth endpoints -------------------------------------------------------------
@app.post("/api/login", dependencies=[Csrf])
def login(body: LoginBody, request: Request, response: Response):
    key = f"{client_ip(request)}|{body.username.lower()}"
    wait = limiter.retry_after(key)
    if wait:
        raise HTTPException(429, f"Too many attempts, try again in {wait}s", headers={"Retry-After": str(wait)})
    row = db.one("SELECT * FROM users WHERE username = ?", (body.username,))
    if row is None or not auth.verify_password(body.password, row["password_hash"]):
        limiter.record_failure(key)
        db.add_event("login_failed", None, body.username[:64], client_ip(request))
        raise HTTPException(401, "Invalid username or password")
    limiter.record_success(key)
    token = auth.create_session(db, row["id"], settings.session_ttl, client_ip(request),
                                request.headers.get("user-agent"))
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (int(time.time()), row["id"]))
    db.add_event("login", None, row["username"], client_ip(request))
    response.set_cookie(COOKIE, token, max_age=settings.session_ttl, httponly=True, samesite="strict",
                        secure=cookie_secure(request), path="/")
    return {"username": row["username"]}


@app.post("/api/logout", dependencies=[Csrf])
def logout(request: Request, response: Response):
    auth.delete_session(db, request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
def me(user: dict[str, Any] = Authed):
    return {"username": user["username"], "version": __version__}


@app.post("/api/me/password", dependencies=[Csrf])
def change_password(body: PasswordBody, request: Request, user: dict[str, Any] = Authed):
    row = db.one("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
    if row is None or not auth.verify_password(body.current, row["password_hash"]):
        raise HTTPException(400, "Current password is incorrect")
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (auth.hash_password(body.new), user["id"]))
    auth.delete_user_sessions(db, user["id"], keep_token=request.cookies.get(COOKIE))
    event("password_changed", user)
    return {"ok": True}


# -- overview / live --------------------------------------------------------------
@app.get("/api/overview")
def overview(range: str = "today", tz: int = 0, user: dict[str, Any] = Authed):
    start, end = range_bounds(range, tz)
    now = int(time.time())
    live = collector.snapshot()
    total_in, total_out = db.totals(start, end)
    by_client = db.totals_by_client(start, end)
    top = sorted(by_client.items(), key=lambda kv: kv[1][0] + kv[1][1], reverse=True)[:8]
    sess = db.one("SELECT COUNT(*) AS n, COUNT(DISTINCT client_name) AS c FROM vpn_sessions "
                  "WHERE last_seen >= ? AND connected_at < ?", (start, end))
    hour_start = now - 3600
    certs = pki.list_clients(hidden_serials())
    counts = {"valid": 0, "expiring": 0, "expired": 0, "revoked": 0}
    for c in certs.values():
        st = c["cert"]["state"]
        counts[st] = counts.get(st, 0) + 1
        if st == "valid" and c["cert"]["not_after"] and c["cert"]["not_after"] - now < EXPIRING_DAYS * 86400:
            counts["expiring"] += 1
    status = pki.pki_status()
    warnings: list[str] = []
    if not live["connected"]:
        warnings.append(f"OpenVPN management interface unreachable: {live.get('error') or 'not connected'}")
    remote_host = pki.get_remote()["host"]
    if remote_host in ("", "127.0.0.1", "localhost", "::1"):
        warnings.append("Client profiles point at " + (remote_host or "no address")
                        + " - set this server's public address under Settings, then hand out the profiles again")
    crl = status["crl"]
    if crl["exists"] and crl["next_update"] and crl["next_update"] - now < EXPIRING_DAYS * 86400:
        warnings.append("The certificate revocation list expires soon - regenerate it on the Server page")
    if status["server"] and status["server"]["not_after"] and status["server"]["not_after"] - now < EXPIRING_DAYS * 86400:
        warnings.append("The server certificate expires within 30 days")
    if status["ca"] and status["ca"]["not_after"] and status["ca"]["not_after"] - now < 90 * 86400:
        warnings.append("The certificate authority expires within 90 days")
    if counts["expiring"]:
        warnings.append(f"{counts['expiring']} client certificate(s) expire within {EXPIRING_DAYS} days")
    if pki.tfa_enforced():
        enrolled = pki.tfa_secrets()
        missing = [n for n, c in certs.items() if c["cert"]["state"] == "valid" and n not in enrolled]
        if missing:
            warnings.append(f"2FA is enforced but {len(missing)} client(s) have no TOTP secret: "
                            + ", ".join(sorted(missing)[:5]) + ("..." if len(missing) > 5 else ""))
    return {
        "range": range,
        "live": live,
        "totals": {"bytes_in": total_in, "bytes_out": total_out,
                   "sessions": int(sess["n"]) if sess else 0, "clients": int(sess["c"]) if sess else 0},
        "top": [{"name": n, "bytes_in": v[0], "bytes_out": v[1]} for n, v in top],
        "hour": fill_series(db.series(hour_start, now + 60, 60), hour_start, now + 60, 60),
        "series": fill_series(db.series(start, end, bucket_for(range), tz_offset=tz), start, end,
                              bucket_for(range), tz),
        "bucket": bucket_for(range),
        "counts": counts,
        "warnings": warnings,
        "tfa_enforced": pki.tfa_enforced(),
    }


@app.get("/api/stream")
def stream(user: dict[str, Any] = Authed):
    q = collector.subscribe()

    def gen() -> Iterator[str]:
        try:
            yield "data: " + json.dumps(collector.snapshot()) + "\n\n"
            while True:
                try:
                    item = q.get(timeout=15)
                    yield "data: " + json.dumps(item) + "\n\n"
                except queue.Empty:
                    yield ": keepalive\n\n"
        finally:
            collector.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# -- clients ----------------------------------------------------------------------
@app.get("/api/clients")
def list_clients(range: str = "today", tz: int = 0, user: dict[str, Any] = Authed):
    return {"range": range, "clients": clients_payload(range, tz)}


@app.post("/api/clients", status_code=201, dependencies=[Csrf])
def create_client(body: NewClientBody, user: dict[str, Any] = Authed):
    name = pki.validate_name(body.name.strip())
    existing = pki.list_clients(set()).get(name)
    if existing and existing["cert"]["state"] == "valid":
        raise HTTPException(409, "A client with this name already exists")
    pki.create_client(name, body.days, body.passphrase or None, (body.static_ip or "").strip() or None)
    db.execute("INSERT INTO clients (name, note, created_at) VALUES (?, ?, ?) "
               "ON CONFLICT(name) DO UPDATE SET note = excluded.note",
               (name, body.note.strip(), int(time.time())))
    tfa_uri = None
    if body.tfa:
        tfa_uri = pki.enable_tfa(name)
    event("client_created", user, name, f"static_ip={body.static_ip or '-'} tfa={body.tfa}")
    return {"client": find_client(name), "tfa_uri": tfa_uri}


@app.get("/api/clients/{name}")
def client_detail(name: str, tz: int = 0, user: dict[str, Any] = Authed):
    row = find_client(name)
    now = int(time.time())
    start = now - 30 * 86400
    sessions = db.query("SELECT * FROM vpn_sessions WHERE client_name = ? ORDER BY connected_at DESC LIMIT 100",
                        (name,))
    row["sessions"] = [dict(s) for s in sessions]
    row["daily"] = fill_series(db.series(start, now + 1, 86400, name, tz), start, now + 1, 86400, tz)
    row["tfa_uri"] = pki.tfa_uri(name) if row["tfa"] else None
    return row


@app.get("/api/clients/{name}/ovpn")
def download_profile(name: str, user: dict[str, Any] = Authed):
    pki.validate_name(name)
    if not (settings.pki_dir / "issued" / f"{name}.crt").exists():
        raise HTTPException(404, "This client has no valid certificate")
    content = pki.build_profile(name)
    event("profile_downloaded", user, name)
    return PlainTextResponse(content, headers={"Content-Disposition": f'attachment; filename="{name}.ovpn"'},
                             media_type="application/x-openvpn-profile")


@app.get("/api/clients/{name}/tfa/qr.svg")
def tfa_qr(name: str, user: dict[str, Any] = Authed):
    pki.validate_name(name)
    uri = pki.tfa_uri(name)
    if not uri:
        raise HTTPException(404, "2FA is not enabled for this client")
    return Response(pki.tfa_qr_svg(uri), media_type="image/svg+xml", headers={"Cache-Control": "no-store"})


@app.post("/api/clients/{name}/tfa", dependencies=[Csrf])
def set_tfa(name: str, body: TfaBody, user: dict[str, Any] = Authed):
    find_client(name)
    if body.enabled:
        uri = pki.enable_tfa(name)
        event("tfa_enabled", user, name)
        return {"enabled": True, "tfa_uri": uri}
    pki.disable_tfa(name)
    event("tfa_disabled", user, name)
    return {"enabled": False, "tfa_uri": None}


@app.post("/api/clients/{name}/revoke", dependencies=[Csrf])
def revoke(name: str, body: ReasonBody, user: dict[str, Any] = Authed):
    row = find_client(name)
    if row["state"] == "revoked":
        raise HTTPException(400, "Already revoked")
    pki.revoke_client(name, body.reason or None)
    killed = ""
    try:
        killed = mgmt.kill(name)
    except ManagementError as exc:
        if "not found" not in str(exc).lower():
            log.warning("could not disconnect %s after revocation: %s", name, exc)
    event("client_revoked", user, name, body.reason or None)
    return {"client": find_client(name), "disconnected": killed}


@app.post("/api/clients/{name}/renew", dependencies=[Csrf])
def renew(name: str, body: DaysBody, user: dict[str, Any] = Authed):
    row = find_client(name)
    if row["state"] == "revoked":
        raise HTTPException(400, "Cannot renew a revoked certificate; create a new client instead")
    pki.renew_client(name, body.days)
    event("client_renewed", user, name)
    return {"client": find_client(name)}


@app.post("/api/clients/{name}/revoke-previous", dependencies=[Csrf])
def revoke_previous(name: str, user: dict[str, Any] = Authed):
    row = find_client(name)
    if not row["previous"]:
        raise HTTPException(400, "No previous certificate pending revocation")
    pki.revoke_previous(name)
    event("previous_cert_revoked", user, name)
    return {"client": find_client(name)}


@app.delete("/api/clients/{name}", dependencies=[Csrf])
def delete_client(name: str, user: dict[str, Any] = Authed):
    row = find_client(name)
    if row["state"] != "revoked":
        raise HTTPException(400, "Revoke the certificate before deleting the client")
    pki.remove_client(name)
    serials = [row["cert"]["serial"]] + [h["serial"] for h in row["history"]]
    with db.tx() as conn:
        for serial in serials:
            conn.execute("INSERT OR IGNORE INTO hidden_certs (serial, name, hidden_at) VALUES (?, ?, ?)",
                         (serial, name, int(time.time())))
        conn.execute("DELETE FROM clients WHERE name = ?", (name,))
    event("client_deleted", user, name)
    return {"ok": True}


@app.post("/api/clients/{name}/disconnect", dependencies=[Csrf])
def disconnect(name: str, body: DisconnectBody, user: dict[str, Any] = Authed):
    pki.validate_name(name)
    result = mgmt.client_kill(body.cid) if body.cid is not None else mgmt.kill(name)
    event("client_disconnected", user, name, result)
    return {"result": result}


@app.put("/api/clients/{name}/static-ip", dependencies=[Csrf])
def static_ip(name: str, body: StaticIpBody, user: dict[str, Any] = Authed):
    find_client(name)
    ip = (body.ip or "").strip() or None
    pki.set_static_ip(name, ip)
    event("static_ip_set", user, name, ip or "removed")
    return {"static_ip": ip, "note": "Applies the next time the client connects"}


@app.put("/api/clients/{name}/note", dependencies=[Csrf])
def set_note(name: str, body: NoteBody, user: dict[str, Any] = Authed):
    find_client(name)
    db.execute("INSERT INTO clients (name, note, created_at) VALUES (?, ?, ?) "
               "ON CONFLICT(name) DO UPDATE SET note = excluded.note", (name, body.note.strip(), int(time.time())))
    return {"note": body.note.strip()}


# -- sessions / traffic -----------------------------------------------------------
@app.get("/api/sessions")
def sessions(name: str | None = None, limit: int = 100, offset: int = 0, active: bool = False,
             user: dict[str, Any] = Authed):
    limit = max(1, min(limit, 500))
    where, params = [], []
    if name:
        pki.validate_name(name)
        where.append("client_name = ?")
        params.append(name)
    if active:
        where.append("disconnected_at IS NULL")
    sql = "SELECT * FROM vpn_sessions" + (" WHERE " + " AND ".join(where) if where else "")
    total = db.one(f"SELECT COUNT(*) AS n FROM ({sql})", params)
    rows = db.query(sql + " ORDER BY connected_at DESC LIMIT ? OFFSET ?", params + [limit, max(0, offset)])
    return {"total": int(total["n"]) if total else 0, "sessions": [dict(r) for r in rows]}


@app.get("/api/traffic")
def traffic(range: str = "7d", name: str | None = None, tz: int = 0, user: dict[str, Any] = Authed):
    if name:
        pki.validate_name(name)
    start, end = range_bounds(range, tz)
    bucket = bucket_for(range)
    total_in, total_out = db.totals(start, end, name)
    return {"range": range, "bucket": bucket,
            "series": fill_series(db.series(start, end, bucket, name, tz), start, end, bucket, tz),
            "totals": {"bytes_in": total_in, "bytes_out": total_out}}


# -- server ---------------------------------------------------------------------
@app.get("/api/server")
def server_info(user: dict[str, Any] = Authed):
    live = collector.snapshot()
    conf = settings.server_conf
    try:
        mtime = int(conf.stat().st_mtime)
    except OSError:
        mtime = None
    return {
        "live": live,
        "pki": pki.pki_status(),
        "tfa_enforced": pki.tfa_enforced(),
        "remote": pki.get_remote(),
        "config_mtime": mtime,
        "dco": (live.get("stats") or {}).get("dco_enabled"),
        "management": {"host": _mgmt_host, "port": _mgmt_port, "password": bool(mgmt.password)},
        "ui_version": __version__,
    }


@app.get("/api/server/config/{which}")
def get_config(which: str, user: dict[str, Any] = Authed):
    return {"which": which, "path": str(pki.config_path(which)), "content": pki.read_config(which)}


@app.put("/api/server/config/{which}", dependencies=[Csrf])
def put_config(which: str, body: ConfigBody, user: dict[str, Any] = Authed):
    pki.write_config(which, body.content)
    event("config_saved", user, None, which)
    if which == "client":
        pki.regenerate_profiles()
    return {"ok": True, "restart_required": which == "server"}


@app.post("/api/server/restart", dependencies=[Csrf])
def restart(user: dict[str, Any] = Authed):
    result = mgmt.signal("SIGTERM")
    event("server_restart", user, None, result)
    return {"result": result, "note": "OpenVPN is restarting; clients reconnect automatically"}


@app.get("/api/server/log")
def server_log(which: str = "openvpn", lines: int = 200, user: dict[str, Any] = Authed):
    files = {"openvpn": settings.log_dir / "openvpn.log", "oath": settings.log_dir / "oath.log",
             "status": settings.log_dir / "openvpn-status.log"}
    if which not in files:
        raise HTTPException(400, "Unknown log")
    return PlainTextResponse(pki.tail_file(files[which], max(10, min(lines, 2000))))


@app.post("/api/server/crl", dependencies=[Csrf])
def regenerate_crl(user: dict[str, Any] = Authed):
    pki.gen_crl()
    event("crl_regenerated", user)
    return {"crl": pki.crl_info()}


@app.put("/api/server/tfa", dependencies=[Csrf])
def enforce_tfa(body: TfaEnforceBody, user: dict[str, Any] = Authed):
    pki.set_tfa_enforced(body.enforced)
    pki.regenerate_profiles()
    event("tfa_enforced" if body.enforced else "tfa_unenforced", user)
    return {"enforced": body.enforced, "restart_required": True}


@app.get("/api/events")
def events(limit: int = 100, user: dict[str, Any] = Authed):
    rows = db.query("SELECT * FROM events ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),))
    return {"events": [dict(r) for r in rows]}


@app.get("/api/settings")
def get_settings(user: dict[str, Any] = Authed):
    return {"remote": pki.get_remote(), "tfa_issuer": settings.tfa_issuer,
            "poll_interval": settings.poll_interval, "version": __version__}


@app.put("/api/settings", dependencies=[Csrf])
def put_settings(body: RemoteBody, user: dict[str, Any] = Authed):
    pki.set_remote(body.host, body.port, body.proto)
    event("remote_changed", user, None, f"{body.host}:{body.port}/{body.proto}")
    return {"remote": pki.get_remote()}


# -- misc -----------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    return {"ok": True, "openvpn": collector.snapshot()["connected"]}


@app.get("/")
def index():
    return FileResponse(STATIC_DIR / "index.html", headers={"Cache-Control": "no-cache"})


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
