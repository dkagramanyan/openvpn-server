"""HTTP API and static frontend."""
from __future__ import annotations

import asyncio
import base64
import datetime
import functools
import hashlib
import hmac
import html
import json
import logging
import re
import secrets
import subprocess
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, AsyncIterator, Literal
from urllib.parse import urlsplit, parse_qs

import psycopg
from fastapi import Depends, FastAPI, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.exception_handlers import request_validation_exception_handler, http_exception_handler
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from starlette.concurrency import run_in_threadpool
from pydantic import BaseModel, Field

from . import __version__, auth, backup, configs, guest_check, pki, relay, relay_devices, relay_services, relay_history, sections, telegram_bot, watchdog, xray, network, network_discovery
from .collector import Collector, Maintenance
from .db import Database, HOUR_RETENTION, MINUTE_RETENTION, RELAY_FLOW_RETENTION, _TRAFFIC_UNION, empty_point
from .mgmt import Management, ManagementError
from .pki import PkiError
from .portal_boundary import PortalBoundary
from .settings import settings

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("openvpn-ui")

COOKIE = "ovpn_session"
STATIC_DIR = Path(__file__).parent / "static"
EXPIRING_DAYS = 30
BACKUP_WARN_DAYS = 3
STARTED = time.time()
IP_ATTEMPTS = 20        # failed logins from one address, whatever the user name, before it has to wait
SESSION_RECHECK = 60    # seconds between two looks at the session of an open live stream
# Calendar periods in the browser's time zone; "custom" takes from/to dates. The rolling
# periods of earlier releases are still accepted.
PERIODS = ("today", "yesterday", "week", "month", "last_month", "all", "custom")
ROLLING = {"24h": 86400, "7d": 7 * 86400, "30d": 30 * 86400, "90d": 90 * 86400}

db = Database(settings.database_url, schema=settings.database_schema)
_mgmt_host, _mgmt_port, _ = settings.management_endpoint()
mgmt = Management(_mgmt_host, _mgmt_port, settings.management_password)
collector = Collector(db, mgmt, settings.poll_interval, settings.status_file,
                      (settings.log_dir / "openvpn.log", settings.log_dir / "oath.log"))
maintenance = Maintenance(db, [lambda: pki.ensure_crl_fresh(), backup.ensure_recent, lambda: xray.reconcile(db)])


def bot_info(name: str) -> dict:
    cert = relay.eligible(name)
    gateway = network.get_settings(db)["gateway"]
    config = relay.get_settings(db)
    return {"valid": bool(cert), "guest": relay.is_guest(name), "expires_at": cert["not_after"] if cert else None,
            "relay": config["enabled"], "xray": xray.enabled(db), "configs": (config["enabled"] and config["devices"]) or xray.enabled(db), "portal_url": f"https://{gateway['openvpn_host']}/portal" if gateway["openvpn_host"] else "the website of this server"}


def bot_link(name: str, kind: str) -> dict:
    if not share_base()[1]:         # no public address: a link would be useless, so none is made
        return {"public": False}
    link = create_share_link(name, kind, 1, "telegram")
    db.add_event("profile_link_created", name, "telegram", f"{kind}, valid 1 h")
    return link


def bot_configs(name: str) -> dict:
    """The client's relay devices and Xray keys for "Мои подключения", oldest first. key: what the
    bot's buttons carry (64 bytes at most): the device id, or the part of the Xray key after "~"."""
    items = [{"kind": "relay", "id": d["id"], "key": d["id"], "state": d["state"],
              "since": d["enrolled_at"] or d["created_at"], "last_seen": d["last_seen"]}
             for d in relay_devices.listing(db, name) if d["state"] in ("active", "waiting")]
    items += [{"kind": "xray", "id": k["id"], "key": k["id"].partition("~")[2] or "-", "state": "active",
               "since": k["created_at"], "last_seen": None} for k in xray.keys(db, name)]
    items.sort(key=lambda item: item["since"])
    return {"used": configs.used(db, name), "limit": configs.limit(db, name), "items": items}


def bot_remove_config(name: str, kind: str, key: str) -> None:
    if kind == "relay":
        relay_devices.revoke(db, name, key)
    elif kind == "xray":
        xray.remove_key(db, name, name if key == "-" else f"{name}~{key}")


def telegram_config() -> dict:
    """Settings → Telegram; the token from OVPN_TELEGRAM_BOT_TOKEN until one is saved there."""
    saved = json.loads(db.get_setting("telegram", "{}"))
    return {"token": saved.get("token") or settings.telegram_token, "admin_chat_id": saved.get("admin_chat_id"),
            "token_from_env": not saved.get("token") and bool(settings.telegram_token)}


_tg = telegram_config()
bot = telegram_bot.Bot(telegram_bot.Api(_tg["token"]) if _tg["token"] else None, db, link=bot_link,
                       password=lambda name: issue_portal_password(name), info=bot_info, admin_chat=_tg["admin_chat_id"],
                       configs=bot_configs, remove=bot_remove_config)
relay_collector = relay_history.RelayCollector(db, collector.set_relay)
section_collector = sections.SectionCollector(db)
limiter = auth.LoginLimiter()


# -- startup ---------------------------------------------------------------------
def bootstrap() -> None:
    settings.network_file.parent.mkdir(parents=True, exist_ok=True)
    # Ensure mount targets before the policy container masks private key areas.
    for relative in ("private", "renewed", "revoked"):
        (settings.pki_dir / relative).mkdir(parents=True, exist_ok=True)
    for d in (settings.clients_dir, settings.static_dir, settings.guests_dir, settings.db_path.parent):
        d.mkdir(parents=True, exist_ok=True)
    if settings.db_path.exists() and db.get_setting("migration:legacy_sqlite") is None and db.get_setting("migration:postgres_dump") is None:
        raise RuntimeError("Legacy state needs migration: run bin/upgrade-relay.sh before starting this UI")
    migrate()
    remember_pushed_routes()
    if db.one("SELECT 1 FROM users LIMIT 1") is None:
        password = settings.admin_password or secrets.token_urlsafe(12)
        db.execute("INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                   (settings.admin_username, auth.hash_password(password), int(time.time())))
        if settings.admin_password:
            log.info("created admin user '%s'", settings.admin_username)
        else:
            log.warning("created admin user '%s' with generated password: %s  (change it in Settings)",
                        settings.admin_username, password)
    try:
        # Also when client.conf is back to the template's placeholder (e.g. after a git checkout).
        placeholder = pki.get_remote()["host"] in ("", "127.0.0.1", "localhost")
        if settings.public_host and (placeholder or db.get_setting("remote_from_env") != settings.public_host):
            pki.set_remote(settings.public_host)
            db.set_setting("remote_from_env", settings.public_host)
            log.info("client profiles now point at %s", settings.public_host)
        elif pki.sync_remotes():
            log.info("client profiles now list every protocol OpenVPN listens on")
    except PkiError as exc:
        log.error("cannot update the client profiles' address: %s", exc)


def remember_pushed_routes() -> None:
    """For the relay's policy service, which cannot read server.conf: the routes it pushes are closed
    to guests there as in the OpenVPN firewall, also before the network settings were ever saved."""
    db.set_setting("pushed_routes", json.dumps(network.pushed_routes()))


def migrate() -> None:
    """One-time data fixes for databases and client files from earlier releases."""
    db.purge_client("UNDEF")          # handshakes in progress that 1.3 recorded as sessions
    moved = pki.migrate_guest_static_ips()
    if moved:
        log.info("guests now get an address per device: %s", ", ".join(moved))
    if db.get_setting("migration:identities") != "1":
        # Up to 1.3 a client created again under an old name inherited the old history.
        for name in pki.list_clients(set()):
            start = pki.identity_start(name)
            if start and db.archive_client_history(name, before=start):
                log.info("history of an earlier '%s' archived", name)
        db.set_setting("migration:identities", "1")
    booked = relay_history.backfill_traffic(db)
    if booked:
        log.info("traffic of %d earlier relay sessions added to the statistics", booked)
    grouped = db.group_sessions()
    if grouped:
        log.info("%d earlier sessions merged into visits", grouped)
    # Up to 1.4 every VPN connection also wrote two audit events, which buried the admin's own.
    db.execute("DELETE FROM events WHERE kind IN ('vpn_connect', 'vpn_disconnect')")


@asynccontextmanager
async def lifespan(_: FastAPI):
    bootstrap()
    if not mgmt.password:
        log.warning("no management password found (%s); connecting without one",
                    settings.management_endpoint()[2])
    collector.start()
    maintenance.start()
    relay_collector.start()
    section_collector.start()
    dog = watchdog.start()
    bot.start()
    yield
    bot.stop()
    if dog:
        dog.stop()
    collector.stop()
    maintenance.stop()
    relay_collector.stop()
    section_collector.stop()
    mgmt.close()


app = FastAPI(title="OpenVPN UI", version=__version__, lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None)
app.add_middleware(network.NetworkProxyHeaders)
app.add_middleware(PortalBoundary)


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
    if request.url.path.startswith(("/api/", "/p/")):
        h["Cache-Control"] = "no-store"
    elif request.url.path.startswith("/static/"):
        h["Cache-Control"] = "no-cache"
    return response


@app.exception_handler(RequestValidationError)
async def validation_error(request: Request, exc: RequestValidationError):
    if request.url.path == "/api/relay/signing":
        return JSONResponse({"detail": "Invalid signing settings"}, status_code=422, headers={"Cache-Control": "no-store"})
    return await request_validation_exception_handler(request, exc)


@app.exception_handler(relay_devices.DeviceLimit)
async def device_limit_error(request: Request, exc: relay_devices.DeviceLimit):
    if getattr(request.state, "native_profile_download", False):
        return profile_download_error(str(exc), 409, request.url.path.startswith("/api/portal/"))
    return JSONResponse({"detail": str(exc)}, status_code=409)


@app.exception_handler(PkiError)
async def pki_error(request: Request, exc: PkiError):
    if getattr(request.state, "native_profile_download", False):
        return profile_download_error(str(exc), 400, request.url.path.startswith("/api/portal/"))
    return JSONResponse({"detail": str(exc)}, status_code=400)


@app.exception_handler(relay_services.SigningUnavailable)
async def signing_error(request: Request, exc: relay_services.SigningUnavailable):
    if getattr(request.state, "native_profile_download", False):
        return profile_download_error(str(exc), 503, request.url.path.startswith("/api/portal/"))
    return JSONResponse({"detail": str(exc)}, status_code=503, headers={"Cache-Control": "no-store", "Retry-After": "5"})


@app.exception_handler(HTTPException)
async def friendly_download_error(request: Request, exc: HTTPException):
    if getattr(request.state, "native_profile_download", False):
        return profile_download_error(str(exc.detail), exc.status_code, request.url.path.startswith("/api/portal/"))
    return await http_exception_handler(request, exc)


def profile_download_error(message, status, portal=True):
    back = "/portal" if portal else "/#/clients"
    return HTMLResponse('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Profile download unavailable</title><link rel="stylesheet" href="/static/app.css"><main class="download-help">'
        '<h1>Your profile could not be downloaded</h1><p>' + html.escape(message) + '</p>'
        '<p>Stay connected to your approved Wi-Fi, VPN or relay, then try again. If this continues, contact your administrator.</p>'
        '<a class="btn primary" href="' + back + '">Back to my profiles</a></main></html>', status_code=status, headers={"Cache-Control": "no-store"})


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


def portal_only(request: Request) -> bool:
    """A request through the gateway's guest portal listener (the gateway sets this header)."""
    return request.headers.get("x-openvpn-portal-only") == "1"


def signed_in_user(request: Request) -> dict[str, Any]:
    user = auth.get_session_user(db, request.cookies.get(COOKIE), settings.session_ttl)
    # The guest portal listener is for client accounts only.
    if user is None or (user["role"] == "admin" and portal_only(request)):
        raise HTTPException(401, "Not authenticated")
    if user["role"] == "client":
        cert = relay.eligible(user["client_name"])
        if not cert or cert["serial"] != user["client_serial"]:
            auth.delete_session(db, request.cookies.get(COOKIE))
            raise HTTPException(401, "Client access is no longer valid")
    return user


def current_user(request: Request) -> dict[str, Any]:
    user = signed_in_user(request)
    if user["role"] != "admin":
        raise HTTPException(403, "Administrator access required")
    return user


def csrf_check(request: Request) -> None:
    if request.headers.get("x-requested-with") != "fetch":
        raise HTTPException(403, "Missing X-Requested-With header")
    origin = request.headers.get("origin")
    if origin and origin != "null":
        if urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
            raise HTTPException(403, "Cross-origin request rejected")


Authed = Depends(current_user)
SignedIn = Depends(signed_in_user)
Csrf = Depends(csrf_check)


def profile_download_token(request, path):
    # A session-bound form token; never expose the HttpOnly session cookie.
    return hmac.new(request.cookies.get(COOKIE, "").encode(), ("profile-download:" + path).encode(), hashlib.sha256).hexdigest()


async def profile_download_csrf(request: Request):
    if request.headers.get("x-requested-with") == "fetch":
        csrf_check(request)
        return
    request.state.native_profile_download = request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded")
    origin = request.headers.get("origin")
    if origin and origin != "null" and urlsplit(origin).netloc.lower() != request.headers.get("host", "").lower():
        raise HTTPException(403, "Cross-origin request rejected")
    body = bytearray()
    async for chunk in request.stream():
        body.extend(chunk)
        if len(body) > 256:
            raise HTTPException(413, "Refresh the page before downloading your profile")
    try:
        token = parse_qs(body.decode("utf-8"), max_num_fields=1).get("csrf", [""])[0]
    except (ValueError, UnicodeError):
        token = ""
    if not request.cookies.get(COOKIE) or not hmac.compare_digest(token.encode(), profile_download_token(request, request.url.path).encode()):
        raise HTTPException(403, "Refresh the page before downloading your profile")
    request.state.native_profile_download = True


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
    guest: bool = False
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


class AccessBody(BaseModel):
    guest: bool


class TelegramSettingsBody(BaseModel):
    token: str | None = Field(default=None, max_length=128)    # None keeps the saved token, "" removes it
    admin_chat_id: int | None = None


class XrayBody(BaseModel):
    enabled: bool
    inbound_id: int | None = None


class TelegramBody(BaseModel):
    username: str = Field(max_length=64)


class RouterBody(BaseModel):
    address: str = Field(default="", max_length=300)


class RouterKeyBody(BaseModel):
    replace: bool = False


class ShareBody(BaseModel):
    hours: int = Field(default=24, ge=1, le=24 * 30)
    kind: Literal["openvpn", "relay", "xray"] = "openvpn"


class ControlChannelBody(BaseModel):
    per_client: bool


class RemoteBody(BaseModel):
    host: str = Field(min_length=1, max_length=253)
    ports: dict[str, int] = {}          # public port per protocol, e.g. {"udp": 1197, "tcp": 1196}


# -- helpers --------------------------------------------------------------------
def range_bounds(name: str, tz: int, date_from: str | None = None, date_to: str | None = None,
                 now: int | None = None) -> tuple[int, int]:
    """[start, end) of a period, in seconds. tz is the browser's offset east of UTC: days, weeks
    (from Monday) and months begin at its local midnight."""
    now = int(time.time()) if now is None else now
    if name in ROLLING:
        return now - ROLLING[name], now + 1
    if name not in PERIODS or abs(tz) > 14 * 3600:
        raise HTTPException(400, "Unknown range")
    utc = datetime.timezone.utc
    local = datetime.datetime.fromtimestamp(now + tz, utc)      # wall-clock time of the browser
    stamp = lambda d: int(datetime.datetime(d.year, d.month, d.day, tzinfo=utc).timestamp()) - tz
    today = local.date()
    if name == "today":
        return stamp(today), now + 1
    if name == "yesterday":
        return stamp(today - datetime.timedelta(days=1)), stamp(today)
    if name == "week":
        return stamp(today - datetime.timedelta(days=today.weekday())), now + 1
    if name == "month":
        return stamp(today.replace(day=1)), now + 1
    if name == "last_month":
        first = today.replace(day=1)
        return stamp((first - datetime.timedelta(days=1)).replace(day=1)), stamp(first)
    if name == "all":
        return db.first_traffic_ts() or now - 86400, now + 1
    try:
        first, last = datetime.date.fromisoformat(date_from or ""), datetime.date.fromisoformat(date_to or "")
    except ValueError:
        raise HTTPException(400, "A custom period needs from and to dates (YYYY-MM-DD)") from None
    start, end = stamp(first), min(stamp(last + datetime.timedelta(days=1)), now + 1)
    if first > last or start >= end:
        raise HTTPException(400, "The period must start before it ends, and not in the future")
    return start, end


def bucket_for(start: int, end: int, now: int | None = None) -> int:
    """Chart step for a period: ten minutes up to two days, an hour up to two weeks, else a day;
    never finer than the stored data (minutes for two days, hours for 90)."""
    now = int(time.time()) if now is None else now
    span = end - start
    bucket = 600 if span <= 2 * 86400 + 1 else 3600 if span <= 14 * 86400 + 1 else 86400
    if start < now - HOUR_RETENTION:
        return 86400
    if start < now - MINUTE_RETENTION:
        return max(bucket, 3600)
    return bucket


class Period:
    def __init__(self, range: str = "today", tz: int = 0, date_from: str | None = Query(None, alias="from"),
                 date_to: str | None = Query(None, alias="to")) -> None:
        self.name, self.tz = range, tz
        self.start, self.end = range_bounds(range, tz, date_from, date_to)
        self.bucket = 86400 if range == "all" else bucket_for(self.start, self.end)

    def info(self) -> dict[str, Any]:
        return {"range": self.name, "start": self.start, "end": self.end, "bucket": self.bucket}

    def series(self, client: str | None = None) -> list[dict[str, int]]:
        return fill_series(db.series(self.start, self.end, self.bucket, client, self.tz),
                           self.start, self.end, self.bucket, self.tz)


def hidden_serials() -> set[str]:
    return {r["serial"] for r in db.query("SELECT serial FROM hidden_certs")}


def fill_series(points: list[dict[str, int]], start: int, end: int, bucket: int, tz: int = 0) -> list[dict[str, int]]:
    by_ts = {p["ts"]: p for p in points}
    t = ((start + tz) // bucket) * bucket - tz
    out = []
    while t < end:
        out.append(by_ts.get(t) or empty_point(t))
        t += bucket
    return out


def split(by_source: dict[str, tuple[int, int]]) -> dict[str, Any]:
    """Traffic of one client or period: the total and its OpenVPN and relay parts."""
    parts = {source: {"bytes_in": by_source.get(source, (0, 0))[0], "bytes_out": by_source.get(source, (0, 0))[1]}
             for source in ("vpn", "relay")}
    return {"bytes_in": sum(p["bytes_in"] for p in parts.values()),
            "bytes_out": sum(p["bytes_out"] for p in parts.values()), **parts}


SPARK_POINTS = 24


def client_sparks(start: int, end: int) -> dict[str, list[int]]:
    """{client: bytes (both directions) in up to 24 equal steps of [start, end)}, one query for everyone."""
    step = max(60, -(-(end - start) // SPARK_POINTS))
    points = max(1, min(SPARK_POINTS, -(-(end - start) // step)))
    out: dict[str, list[int]] = {}
    for r in db.query(f"SELECT client_name, CAST((ts - ?) / ? AS INTEGER) AS b, SUM(bytes_in + bytes_out) AS n "
                      f"FROM ({_TRAFFIC_UNION}) GROUP BY client_name, b", (start, step, *((start, end) * 3))):
        if 0 <= r["b"] < points:
            out.setdefault(r["client_name"], [0] * points)[r["b"]] = int(r["n"] or 0)
    return out


def client_top_sections(start: int, end: int) -> dict[str, dict[str, Any]]:
    """{client: {"section", "share"}}: the podkop section with the most traffic in [start, end), as a share of
    the client's counted traffic. Direct ('') and unknown ('?') only when the client has no named section."""
    by_client: dict[str, dict[str, int]] = {}
    for r in db.query("SELECT client_name, section, SUM(bytes_in + bytes_out) AS n FROM section_traffic "
                      "WHERE ts >= ? AND ts < ? GROUP BY client_name, section", (start, end)):
        by_client.setdefault(r["client_name"], {})[r["section"]] = int(r["n"] or 0)
    out = {}
    for name, parts in by_client.items():
        total = sum(parts.values())
        named = {k: v for k, v in parts.items() if k not in ("", "?") and v > 0}
        pick = named or {k: v for k, v in parts.items() if v > 0}
        if total > 0 and pick:
            section = max(pick, key=lambda k: (pick[k], k))
            out[name] = {"section": section, "share": round(pick[section] / total, 3)}
    return out


def clients_payload(period: Period | None = None, extras: bool = False) -> list[dict[str, Any]]:
    """extras: the list page's sparkline and top section for the period (two more queries)."""
    period = period or Period("today", 0, None, None)
    sparks = client_sparks(period.start, period.end) if extras else {}
    top_sections = client_top_sections(period.start, period.end) if extras else {}
    certs = pki.list_clients(hidden_serials())
    statics = pki.static_ips()
    guests = pki.guests()
    relay_enabled = relay.get_settings(db)["enabled"]
    xray_enabled = xray.enabled(db)
    tfa = pki.tfa_secrets()
    live = collector.snapshot()
    online: dict[str, list[dict[str, Any]]] = {}
    for c in live["clients"]:
        online.setdefault(c["cn"], []).append(c)
    relay_live = {c["client"]: c for c in live.get("relay", [])}
    traffic = db.traffic_by_client(period.start, period.end)
    totals = db.session_stats_by_client()
    relay_totals = relay_history.stats_by_client(db)
    notes = {r["name"]: r["note"] for r in db.query("SELECT name, note FROM clients")}
    now = int(time.time())
    rows = []
    for name, c in certs.items():
        cert = c["cert"]
        t, r = totals.get(name, {}), relay_totals.get(name, {})
        via = [source for source, on in (("vpn", name in online), ("relay", name in relay_live)) if on]
        seen = [x for x in (t.get("last_seen"), r.get("last_seen")) if x]
        first = [x for x in (t.get("first_seen"), r.get("first_seen")) if x]
        rows.append({
            "name": name,
            "state": cert["state"],
            "cert": cert,
            "previous": c["previous"],
            "history": c["history"],
            "expires": cert["not_after"],
            "days_left": (cert["not_after"] - now) // 86400 if cert["not_after"] else None,
            "static_ip": statics.get(name),
            "guest": name in guests,
            "relay_available": relay_enabled and cert["state"] == "valid",
            "xray_available": xray_enabled and cert["state"] == "valid",
            "tfa": name in tfa,
            # Online = an OpenVPN connection or an open relay connection.
            "online": bool(via),
            "online_via": via,
            "sessions_live": online.get(name, []),
            # The oldest OpenVPN connection that is still open (the relay reports no start).
            "online_since": min((x["connected_since"] for x in online.get(name, []) if x.get("connected_since")), default=None),
            "relay_live": relay_live.get(name),
            "traffic": split(traffic.get(name, {})),
            # All time. "sessions" = OpenVPN visits (reconnects merged) + relay sessions.
            "total": {**split({"vpn": (t.get("bytes_in", 0), t.get("bytes_out", 0)),
                               "relay": (r.get("bytes_in", 0), r.get("bytes_out", 0))}),
                      "sessions": t.get("visits", 0) + r.get("sessions", 0),
                      "vpn_visits": t.get("visits", 0), "vpn_connections": t.get("sessions", 0),
                      "relay_sessions": r.get("sessions", 0),
                      "last_seen": max(seen) if seen else None, "first_seen": min(first) if first else None,
                      "online_seconds": t.get("online_seconds", 0)},
            "note": notes.get(name, ""),
            **({"spark": sparks.get(name, []), "top_section": top_sections.get(name)} if extras else {}),
        })
    order = {"valid": 0, "expired": 1, "revoked": 2}
    rows.sort(key=lambda r: (not r["online"], order.get(r["state"], 3), r["name"].lower()))
    return rows


def find_client(name: str) -> dict[str, Any]:
    pki.validate_name(name)
    for row in clients_payload():
        if row["name"] == name:
            return row
    raise HTTPException(404, "Client not found")


def drop_share_links(name: str) -> None:
    db.execute("DELETE FROM share_tokens WHERE client_name = ?", (name,))


def event(kind: str, user: dict[str, Any] | None, client: str | None = None, detail: str | None = None) -> None:
    db.add_event(kind, client, user["username"] if user else None, detail)


# -- auth endpoints -------------------------------------------------------------
# One sign-in for administrators and client accounts; the answer's "role" tells
# the page which view to show. /api/portal/login is the same endpoint under the
# path the guest portal listener lets through, where administrators are refused.
@app.post("/api/login", dependencies=[Csrf])
@app.post("/api/portal/login", dependencies=[Csrf])
def login(body: LoginBody, request: Request, response: Response):
    ip = client_ip(request)
    key = f"{ip}|{body.username.lower()}"
    wait = limiter.attempt({ip: IP_ATTEMPTS, key: limiter.threshold})
    if wait:
        raise HTTPException(429, f"Too many attempts, try again in {wait}s", headers={"Retry-After": str(wait)})
    row = db.one("SELECT * FROM users WHERE username = ?", (body.username,))
    if row is None:
        auth.verify_unknown_user(body.password)
    valid_client = True
    if row is not None and row["client_name"] is not None:
        cert = relay.eligible(row["client_name"])
        valid_client = bool(cert and cert["serial"] == row["client_serial"])
    admin_on_guest_listener = row is not None and row["client_name"] is None and portal_only(request)
    if row is None or not auth.verify_password(body.password, row["password_hash"]) or not valid_client or admin_on_guest_listener:
        db.add_event("login_failed", None, body.username[:64], ip)
        raise HTTPException(401, "Invalid username or password")
    limiter.success(ip)
    limiter.success(key)
    if auth.needs_rehash(row["password_hash"]):
        db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (auth.hash_password(body.password), row["id"]))
    token = auth.create_session(db, row["id"], settings.session_ttl, client_ip(request),
                                request.headers.get("user-agent"))
    db.execute("UPDATE users SET last_login = ? WHERE id = ?", (int(time.time()), row["id"]))
    db.add_event("login", None, row["username"], client_ip(request))
    response.set_cookie(COOKIE, token, max_age=settings.session_ttl, httponly=True, samesite="strict",
                        secure=cookie_secure(request), path="/")
    admin = row["client_name"] is None
    return {"username": row["username"], "guest_sub": settings.guest_sub,
            "role": "admin" if admin else "client", "client_name": row["client_name"], "xui_url": xui_url() if admin else None}


def xui_url() -> str | None:
    """Where the gateway serves the 3x-ui panel (next to this website), for the admin sidebar."""
    xui = xray.panel(network.get_settings(db)["gateway"])
    return xui["url"] if xui else None


@app.post("/api/logout", dependencies=[Csrf])
@app.post("/api/portal/logout", dependencies=[Csrf])
def logout(request: Request, response: Response):
    auth.delete_session(db, request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/")
    return {"ok": True}


@app.get("/api/me")
@app.get("/api/portal/me")
def me(user: dict[str, Any] = SignedIn):
    return {"username": user["username"], "version": __version__, "guest_sub": settings.guest_sub,
            "role": user["role"], "client_name": user["client_name"],
            "xui_url": xui_url() if user["role"] == "admin" else None}


@app.post("/api/me/password", dependencies=[Csrf])
def change_password(body: PasswordBody, request: Request, user: dict[str, Any] = SignedIn):
    if user["role"] == "client":        # client passwords come from the Telegram bot
        raise HTTPException(403, "Ask the Telegram bot for a new password")
    row = db.one("SELECT password_hash FROM users WHERE id = ?", (user["id"],))
    if row is None or not auth.verify_password(body.current, row["password_hash"]):
        raise HTTPException(400, "Current password is incorrect")
    db.execute("UPDATE users SET password_hash = ? WHERE id = ?", (auth.hash_password(body.new), user["id"]))
    auth.delete_user_sessions(db, user["id"], keep_token=request.cookies.get(COOKIE))
    event("password_changed", user)
    return {"ok": True}


def disable_portal(name):
    row = db.one("SELECT id FROM users WHERE client_name = ?", (name,))
    if row:
        auth.delete_user_sessions(db, row["id"])
        db.execute("DELETE FROM users WHERE id = ?", (row["id"],))


@app.get("/api/clients/{name}/portal")
def portal_account(name: str, user: dict[str, Any] = Authed):
    """The client's portal login and Telegram binding."""
    find_client(name)
    row = db.one("SELECT username FROM users WHERE client_name = ?", (name,))
    tg = db.one("SELECT telegram, telegram_id, telegram_name FROM clients WHERE name = ?", (name,)) or {}
    return {"enabled": bool(row), "username": row["username"] if row else name,
            "telegram": tg.get("telegram") or "", "telegram_linked": tg.get("telegram_id") is not None,
            "telegram_name": tg.get("telegram_name") or "",
            "bot": bot.configured, "bot_username": bot.username}


def issue_portal_password(name: str) -> tuple[str, str]:
    """(username, password): a new generated portal password for a valid client, creating its login
    (username = client name) if it has none. Its earlier sign-ins end."""
    cert = relay.eligible(name)
    if not cert:
        raise HTTPException(400, "Portal access requires a valid client certificate")
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    password = "-".join("".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(4))
    password_hash = auth.hash_password(password)
    with db.tx() as conn:
        row = conn.execute("SELECT id, username FROM users WHERE client_name = ?", (name,)).fetchone()
        if row:
            username = row["username"]
            conn.execute("DELETE FROM web_sessions WHERE user_id = ?", (row["id"],))
            conn.execute("UPDATE users SET password_hash = ?, client_serial = ? WHERE id = ?",
                         (password_hash, cert["serial"], row["id"]))
        else:
            username = name
            if conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone():
                raise HTTPException(400, "Another account already uses this client's name as its username")
            conn.execute("INSERT INTO users (username, password_hash, created_at, client_name, client_serial) VALUES (?, ?, ?, ?, ?)",
                         (username, password_hash, int(time.time()), name, cert["serial"]))
    return username, password


@app.post("/api/clients/{name}/portal/password", dependencies=[Csrf])
def new_portal_password(name: str, user: dict[str, Any] = Authed):
    """For a client without Telegram: a generated password, shown to the admin once."""
    find_client(name)
    username, password = issue_portal_password(name)
    event("portal_password_issued", user, name)
    return {"enabled": True, "username": username, "password": password}


@app.put("/api/clients/{name}/telegram", dependencies=[Csrf])
def set_telegram(name: str, body: TelegramBody, user: dict[str, Any] = Authed):
    """The client's Telegram username; empty removes it. A new username unbinds the old account."""
    find_client(name)
    try:
        username = telegram_bot.normalize(body.username) if body.username.strip() else None
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    try:
        with db.tx() as conn:
            taken = conn.execute("SELECT name FROM clients WHERE telegram = ? AND name != ?", (username, name)).fetchone() if username else None
            if taken:
                raise HTTPException(400, f"@{username} is already set for {taken['name']}")
            conn.execute("INSERT INTO clients (name, created_at, telegram) VALUES (?, ?, ?) ON CONFLICT(name) DO UPDATE SET "
                         "telegram_id = CASE WHEN clients.telegram IS NOT DISTINCT FROM excluded.telegram THEN clients.telegram_id END, "
                         "telegram_name = CASE WHEN clients.telegram IS NOT DISTINCT FROM excluded.telegram THEN clients.telegram_name END, "
                         "telegram = excluded.telegram", (name, int(time.time()), username))
    except psycopg.errors.UniqueViolation:      # the same username saved for another client at the same moment
        raise HTTPException(400, f"@{username} is already set for another client")
    event("telegram_set", user, name, f"@{username}" if username else "removed")
    return portal_account(name, user)


@app.delete("/api/clients/{name}/portal", dependencies=[Csrf])
def remove_portal_account(name: str, user: dict[str, Any] = Authed):
    find_client(name)
    disable_portal(name)
    event("portal_access_disabled", user, name)
    return {"enabled": False}


@app.get("/api/portal")
def own_profile_info(request: Request, user: dict[str, Any] = SignedIn):
    if user["role"] != "client":
        raise HTTPException(400, "This page is for client accounts")
    cert = relay.eligible(user["client_name"])
    if not cert:
        raise HTTPException(401, "Client access is no longer valid")
    guest = relay.is_guest(user["client_name"])
    return {"name": user["client_name"], "guest": guest, "expires_at": cert["not_after"],
            "links": network.guest_links() if guest else [],
            "telegram_bot": bot.username if bot.configured else None,
            "relay_available": relay.get_settings(db)["enabled"], "signed_profiles": bool(relay_services.signing_config(db)["url"]),
            "relay_download": {"url": "/api/portal/relay.mobileconfig", "csrf": profile_download_token(request, "/api/portal/relay.mobileconfig")}}


@app.get("/api/portal/ovpn")
def own_openvpn_profile(user: dict[str, Any] = SignedIn):
    if user["role"] != "client":
        raise HTTPException(400, "This page is for client accounts")
    name = user["client_name"]
    content = pki.build_profile(name)
    event("portal_openvpn_downloaded", user, name)
    return Response(content, media_type="application/x-openvpn-profile",
                    headers={"Content-Disposition": f'attachment; filename="{name}.ovpn"'})


@app.get("/api/portal/sections")
def own_sections(period: Period = Depends(), user: dict[str, Any] = SignedIn):
    """The signed-in client's own traffic by podkop section, with its own domains."""
    if user["role"] != "client":
        raise HTTPException(400, "This page is for client accounts")
    return {**period.info(), **sections.report(db, period.start, period.end, user["client_name"], domains=True)}


@app.get("/api/portal/relay/status")
def own_relay_status(user: dict[str, Any] = SignedIn):
    if user["role"] != "client":
        raise HTTPException(400, "This page is for client accounts")
    name = user["client_name"]
    status = relay_services.runtime_status(client=name)
    # Filter again at the trust boundary, even when an older backend ignores
    # the client query. Never send another client's destinations to this login.
    return {"ready": bool(status.get("ready")), "policy_ready": status.get("policy_ready", False),
            "sessions": relay_history.sessions(db, client=name, credential=relay.credential_ids(db, name)),
            "flows": relay_history.flows(db, name, credential=relay.credential_ids(db, name), limit=100)[1],
            **{key: [row for row in status.get(key, []) if row.get("client") == name]
               for key in ("clients", "active", "events")}}


@app.post("/api/portal/relay.mobileconfig", dependencies=[Depends(profile_download_csrf)])
def own_relay_profile(user: dict[str, Any] = SignedIn):
    if user["role"] != "client":
        raise HTTPException(400, "This page is for client accounts")
    name = user["client_name"]
    try:
        content = relay.profile(db, name)
    except relay_devices.DeviceLimit:
        raise
    except PkiError:
        if relay_services.signing_config(db)["required"] or relay_services.signing_config(db)["url"]:
            raise HTTPException(503, "Signed relay profiles are temporarily unavailable. Please retry or contact the administrator.")
        raise
    event("portal_relay_downloaded", user, name)
    return Response(content, media_type="application/x-apple-aspen-config",
                    headers={"Content-Disposition": f'attachment; filename="{name}-relay.mobileconfig"', "Cache-Control": "no-store", "X-Profile-Signed": "false" if content.startswith(b"<?xml") else "true"})


# -- overview / live --------------------------------------------------------------
@app.get("/api/overview")
def overview(period: Period = Depends(), user: dict[str, Any] = Authed):
    start, end = period.start, period.end
    now = int(time.time())
    live = collector.snapshot()
    by_client = db.traffic_by_client(start, end)
    by_source = {source: (sum(v.get(source, (0, 0))[0] for v in by_client.values()),
                          sum(v.get(source, (0, 0))[1] for v in by_client.values())) for source in ("vpn", "relay")}
    top = sorted(by_client.items(), key=lambda kv: sum(a + b for a, b in kv[1].values()), reverse=True)[:8]
    # Visits (reconnects of one client from one address merged) that overlap the period.
    visits = db.one("SELECT COUNT(DISTINCT grp) AS n, COUNT(*) AS c FROM vpn_sessions "
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
    remote, listen = pki.get_remote(), pki.server_listen()
    if remote["host"] in ("", "127.0.0.1", "localhost", "::1"):
        warnings.append("Client profiles point at " + (remote["host"] or "no address")
                        + " - set this server's public address under Settings, then hand out the profiles again")
    dial = {r["proto"]: r["port"] for r in remote["remotes"]}
    for sock in listen:
        port, proto = sock["port"], sock["proto"]
        if proto not in dial:
            warnings.append(f"OpenVPN listens on {port}/{proto} but client profiles have no {proto.upper()} "
                            "address - save the public address again under Settings")
        elif dial[proto] != port:
            warnings.append(f"Client profiles dial {dial[proto]}/{proto} but OpenVPN listens on {port}/{proto}"
                            " - correct it under Settings, unless a router forwards one port to the other")
    crl = status["crl"]
    if crl["exists"] and crl["next_update"] and crl["next_update"] - now < EXPIRING_DAYS * 86400:
        warnings.append("The certificate revocation list expires soon - regenerate it on the Server page")
    if status["server"] and status["server"]["not_after"] and status["server"]["not_after"] - now < EXPIRING_DAYS * 86400:
        warnings.append("The server certificate expires within 30 days")
    if status["ca"] and status["ca"]["not_after"] and status["ca"]["not_after"] - now < 90 * 86400:
        warnings.append("The certificate authority expires within 90 days")
    if counts["expiring"]:
        warnings.append(f"{counts['expiring']} client certificate(s) expire within {EXPIRING_DAYS} days")
    bak = backup.status()
    # The first archive is written a minute after the start, so a missing one only counts later.
    if bak["enabled"] and now - (bak["last"] or STARTED) > BACKUP_WARN_DAYS * 86400:
        warnings.append(f"No backup for more than {BACKUP_WARN_DAYS} days - see the Server page and the UI log")
    bad_ips = [f"{n} ({ip})" for n, ip in sorted(pki.static_ips().items())
               if n in certs and certs[n]["cert"]["state"] == "valid" and pki.static_ip_problem(n, ip)]
    if bad_ips:
        warnings.append("OpenVPN cannot hand out these static IPs - set new ones on the client pages: "
                        + ", ".join(bad_ips))
    if pki.tfa_enforced():
        enrolled = pki.tfa_secrets()
        missing = [n for n, c in certs.items() if c["cert"]["state"] == "valid" and n not in enrolled]
        if missing:
            warnings.append(f"2FA is enforced but {len(missing)} client(s) have no TOTP secret: "
                            + ", ".join(sorted(missing)[:5]) + ("..." if len(missing) > 5 else ""))
    return {
        **period.info(),
        "live": live,
        # "clients": active users, the clients with traffic in the period over OpenVPN or the relay.
        "totals": {**split(by_source), "clients": len(by_client),
                   "vpn_clients": sum(1 for v in by_client.values() if "vpn" in v),
                   "relay_clients": sum(1 for v in by_client.values() if "relay" in v),
                   "vpn_visits": int(visits["n"]) if visits else 0,
                   "vpn_connections": int(visits["c"]) if visits else 0,
                   "relay_sessions": relay_history.count_between(db, start, end)},
        "top": [{"name": n, **split(v)} for n, v in top],
        "hour": fill_series(db.series(hour_start, now + 60, 60), hour_start, now + 60, 60),
        "series": period.series(),
        "counts": counts,
        "warnings": warnings,
        "tfa_enforced": pki.tfa_enforced(),
        "rejections": db.rejections(now - 86400),
    }


@app.get("/api/stream")
async def stream(request: Request, user: dict[str, Any] = Authed):
    token = request.cookies.get(COOKIE)

    # Async on purpose: a sync generator would hold one of the 40 worker threads for as long as
    # the stream is open, and enough open tabs (or proxy connections) would stall every endpoint.
    async def gen() -> AsyncIterator[str]:
        q = collector.subscribe()
        checked = time.monotonic()
        try:
            yield "data: " + json.dumps(collector.snapshot()) + "\n\n"
            while True:
                if time.monotonic() - checked > SESSION_RECHECK:
                    # A stream opened before a sign-out or a password change ends with the session.
                    if auth.get_session_user(db, token, settings.session_ttl, extend=False) is None:
                        return
                    checked = time.monotonic()
                try:
                    item = await asyncio.wait_for(q.get(), 15)
                    yield "data: " + json.dumps(item) + "\n\n"
                except TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            collector.unsubscribe(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


# -- clients ----------------------------------------------------------------------
@app.get("/api/clients")
def list_clients(period: Period = Depends(), user: dict[str, Any] = Authed):
    return {**period.info(), "clients": clients_payload(period, extras=True)}


@app.post("/api/clients", status_code=201, dependencies=[Csrf])
def create_client(body: NewClientBody, user: dict[str, Any] = Authed):
    with pki.lock:      # a second click waits here and then finds the client created
        return _create_client(body, user)


def _create_client(body: NewClientBody, user: dict[str, Any]) -> dict[str, Any]:
    name = pki.validate_name(body.name.strip())
    existing = pki.list_clients(set()).get(name)
    if existing and existing["cert"]["state"] == "valid":
        raise HTTPException(409, "A client with this name already exists")
    if existing and existing["cert"]["state"] == "expired":
        raise HTTPException(409, "This client's certificate has expired - renew it on the client's page")
    static_ip = (body.static_ip or "").strip() or None
    if body.guest and static_ip:
        raise HTTPException(400, "Guests get an address from the guest range for each device, not a static IP")
    pki.create_client(name, body.days, body.passphrase or None, static_ip)
    # A new certificate is a new client: history, access and 2FA of an earlier one with this name stay behind.
    db.archive_client_history(name)
    drop_share_links(name)
    xray.forget(db, name)
    pki.set_guest(name, body.guest)
    if not static_ip:
        pki.set_static_ip(name, None)
    db.execute("INSERT INTO clients (name, note, created_at) VALUES (?, ?, ?) "
               # A reused name is a new person: the old Telegram binding must not carry over.
               "ON CONFLICT(name) DO UPDATE SET note = excluded.note, created_at = excluded.created_at, "
               "telegram = NULL, telegram_id = NULL, telegram_name = NULL",
               (name, body.note.strip(), int(time.time())))
    tfa_uri = None
    if body.tfa:
        tfa_uri = pki.enable_tfa(name)
    elif name in pki.tfa_secrets():
        pki.disable_tfa(name)
    event("client_created", user, name, f"static_ip={static_ip or '-'} guest={body.guest} tfa={body.tfa}")
    return {"client": find_client(name), "tfa_uri": tfa_uri}


def relay_visit(row: dict[str, Any]) -> dict[str, Any]:
    """A relay session in the shape of an OpenVPN visit (relay up = bytes_in, down = bytes_out)."""
    return {"via": "relay", "id": row["id"], "client_name": row["client"], "connected_at": row["started_at"],
            "disconnected_at": row["ended_at"], "last_seen": row["last_seen"], "state": row["state"],
            "open": int(row["active"] or 0), "connections": int(row["accepted"] or 0),
            "denied": int(row["denied"] or 0), "failed": int(row["failed"] or 0),
            "bytes_in": int(row["bytes_up"] or 0), "bytes_out": int(row["bytes_down"] or 0),
            "transport": row.get("transport") or ""}


def merged_sessions(name: str | None, via: str, limit: int, offset: int, active: bool = False,
                    merge: bool = True) -> tuple[int, list[dict[str, Any]]]:
    """OpenVPN visits (or single connections) and relay sessions in one list, newest first."""
    if via not in ("all", "vpn", "relay"):
        raise HTTPException(400, "Unknown connection type")
    total, rows = 0, []
    reach = limit + offset if via == "all" else limit       # a merged page may come from either source
    skip = 0 if via == "all" else offset
    if via in ("all", "vpn"):
        where, params = (["client_name = ?"], [name]) if name else ([], [])
        if merge:
            n, found = db.visits(" WHERE " + " AND ".join(where) if where else "", params, reach, skip, active)
        else:
            if active:
                where.append("disconnected_at IS NULL")
            sql = "SELECT * FROM vpn_sessions" + (" WHERE " + " AND ".join(where) if where else "")
            n = int(db.one(f"SELECT COUNT(*) AS n FROM ({sql})", params)["n"])
            found = [dict(r) for r in db.query(sql + " ORDER BY connected_at DESC, id DESC LIMIT ? OFFSET ?",
                                               params + [reach, skip])]
        total += n
        rows += [{"via": "vpn", **r} for r in found]
    if via in ("all", "relay"):
        n, found = relay_history.visits(db, client=name, active=active, limit=reach, offset=skip)
        total += n
        rows += [relay_visit(r) for r in found]
    if via == "all":
        rows.sort(key=lambda r: r["connected_at"], reverse=True)
        rows = rows[offset:offset + limit]
    return total, rows


@app.get("/api/clients/{name}")
def client_detail(name: str, tz: int = 0, user: dict[str, Any] = Authed):
    row = find_client(name)
    now = int(time.time())
    start = now - 30 * 86400
    row["sessions"] = merged_sessions(name, "all", 100, 0)[1]
    row["daily"] = fill_series(db.series(start, now + 1, 86400, name, tz), start, now + 1, 86400, tz)
    row["tfa_uri"] = pki.tfa_uri(name) if row["tfa"] else None
    row["rejections"] = db.rejections(now - 30 * 86400, name)
    return row


@app.get("/api/sections")
def sections_overview(period: Period = Depends(), user: dict[str, Any] = Authed):
    """Every client's traffic by podkop section in a period, with the top clients of each."""
    return {**period.info(), **sections.report(db, period.start, period.end), "router": router_status()}


@app.get("/api/clients/{name}/sections")
def client_sections(name: str, period: Period = Depends(), user: dict[str, Any] = Authed):
    """A client's traffic by podkop section; top domains while the period lies in the last 7 days."""
    pki.validate_name(name)
    return {**period.info(), **sections.report(db, period.start, period.end, name, domains=True)}


def router_status() -> dict[str, Any]:
    config = sections.get_router(db)
    status = section_collector.status
    pending = db.one("SELECT COUNT(*) AS n, MIN(queued_at) AS oldest FROM section_pending")
    return {"address": config.get("address", ""), "key": sections.key_path().is_file(),
            "line": sections.authorized_line(), "command": sections.router_command(), "last_ok": status.get("last_ok"), "last_error": status.get("last_error"),
            "error": status.get("error"), "agent": status.get("agent"), "sections": section_collector.sections,
            "subnets": len(section_collector.ranges) if section_collector.ranges is not None else None,
            "pending": int(pending["n"]) if pending else 0, "unmapped": status.get("unmapped", 0)}


@app.get("/api/router")
def get_router(user: dict[str, Any] = Authed):
    return router_status()


@app.put("/api/router", dependencies=[Csrf])
def put_router(body: RouterBody, user: dict[str, Any] = Authed):
    try:
        address = sections.validate_address(body.address)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    db.set_setting("router_sections", json.dumps({"address": address}))
    event("router_sections_changed", user, detail=address or "off")
    if address and not sections.key_path().is_file():      # the command for the router is ready at once
        try:
            sections.create_key()
            event("router_key_created", user)
        except (OSError, ValueError, subprocess.SubprocessError):
            log.warning("could not create the router key")
    return router_status()


@app.post("/api/router/key", dependencies=[Csrf])
def create_router_key(body: RouterKeyBody, user: dict[str, Any] = Authed):
    """A new key for the router lookup. Only the public half and its authorized_keys line leave the server."""
    try:
        sections.create_key(replace=body.replace)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from None
    except (OSError, subprocess.SubprocessError):
        raise HTTPException(500, "Could not create the key (is ssh-keygen installed?)") from None
    event("router_key_created", user)
    return router_status()


@app.post("/api/router/test", dependencies=[Csrf])
def test_router(user: dict[str, Any] = Authed):
    address = sections.get_router(db).get("address")
    if not address:
        raise HTTPException(400, "Set the router address first")
    try:
        data = sections.ssh_call(address, {"domains": [], "addresses": [], "subnets": True})
    except sections.SectionsUnavailable as exc:
        return {"ok": False, "error": str(exc)}
    names = [s for s in data.get("sections") or [] if isinstance(s, str)]
    return {"ok": True, "agent": data.get("agent"), "sections": names, "subnets": len(data.get("subnets") or []), "boot_id": bool(data.get("boot_id"))}


@app.get("/api/clients/{name}/relay-flows")
def client_relay_flows(name: str, limit: int = 100, offset: int = 0, q: str = "", user: dict[str, Any] = Authed):
    """The client's saved relay connections (kept 7 days), newest first, and the open ones."""
    pki.validate_name(name)
    total, rows = relay_history.flows(db, name, q=q.strip()[:253], limit=max(1, min(limit, 500)), offset=max(0, offset))
    status = relay_services.runtime_status(client=name)
    return {"total": total, "flows": rows, "retention_days": RELAY_FLOW_RETENTION // 86400,
            "ready": bool(status.get("ready")),
            "active": [f for f in status.get("active", []) if f.get("client") == name]}


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
    return Response(pki.qr_svg(uri), media_type="image/svg+xml", headers={"Cache-Control": "no-store"})


@app.get("/api/relay/settings")
def get_relay_settings(user: dict[str, Any] = Authed):
    return relay.get_settings(db)


@app.get("/api/telegram/settings")
def get_telegram_settings(user: dict[str, Any] = Authed):
    config = telegram_config()      # the token itself never goes back to the browser
    return {"configured": bot.configured, "bot_username": bot.username, "token_from_env": config["token_from_env"],
            "admin_chat_id": config["admin_chat_id"]}


@app.put("/api/telegram/settings", dependencies=[Csrf])
def set_telegram_settings(body: TelegramSettingsBody, user: dict[str, Any] = Authed):
    saved = json.loads(db.get_setting("telegram", "{}"))
    token = saved.get("token", "") if body.token is None else body.token.strip()
    username = None
    effective = token or settings.telegram_token
    if effective:
        try:        # a wrong token is refused here, not found out by the poller later
            username = telegram_bot.Api(effective).call("getMe")["username"]
        except telegram_bot.ApiError as exc:
            raise HTTPException(400, f"Telegram refused this token ({exc})")
    db.set_setting("telegram", json.dumps({"token": token, "admin_chat_id": body.admin_chat_id}))
    bot.configure(telegram_bot.Api(effective) if effective else None, body.admin_chat_id, username)
    event("telegram_settings_changed", user, None, "token changed" if body.token is not None else None)
    return get_telegram_settings(user)


@app.post("/api/telegram/test", dependencies=[Csrf])
def test_telegram(user: dict[str, Any] = Authed):
    if not bot.configured or bot.admin_chat is None:
        raise HTTPException(400, "Save a bot token and your chat ID first")
    try:
        bot.send(bot.admin_chat, "Тестовое сообщение от сервера доступа. Уведомления будут приходить в этот чат.")
    except telegram_bot.ApiError as exc:
        raise HTTPException(400, f"Telegram did not deliver it ({exc}). Open the bot and press Start first.")
    return {"sent": True}


@app.get("/api/xray/settings")
def get_xray_settings(user: dict[str, Any] = Authed):
    """The saved choice, and what 3x-ui offers (or why it cannot be asked)."""
    try:
        inbounds, error = xray.inbounds(), None
    except PkiError as exc:
        inbounds, error = [], str(exc)
    xui = xray.panel(network.get_settings(db)["gateway"])
    return {**xray.get_settings(db), "inbounds": inbounds, "error": error, "panel_url": xui["url"] if xui else None}


@app.put("/api/xray/settings", dependencies=[Csrf])
def set_xray_settings(body: XrayBody, user: dict[str, Any] = Authed):
    saved = xray.save_settings(db, body.enabled, body.inbound_id)
    xray.reconcile(db)          # the routing rule now, not in an hour
    event("xray_settings_changed", user, None, "on" if body.enabled else "off")
    return saved


@app.get("/api/relay/status")
def relay_status(user: dict[str, Any] = Authed):
    return {**relay_services.runtime_status(), "sessions": relay_history.sessions(db),
            "session_idle_seconds": relay_history.IDLE_SECONDS}


@app.get("/api/relay/signing")
def relay_signing(user: dict[str, Any] = Authed):
    return relay_services.signing_status(db)


@app.put("/api/relay/signing", dependencies=[Csrf])
def save_relay_signing(body: relay_services.SigningSettings, user: dict[str, Any] = Authed):
    status = relay_services.save_signing(db, body)
    event("relay_signing_changed", user)  # No URL/token/profile contents in audit detail.
    return status


@app.put("/api/relay/settings", dependencies=[Csrf])
def put_relay_settings(body: relay.RelaySettings, user: dict[str, Any] = Authed):
    if body.devices and "devices" in body.model_fields_set and not relay.get_settings(db)["devices"]:
        relay.device_self_test(db, {**relay.get_settings(db), **body.model_dump(exclude_unset=True)})
    config = relay.save_settings(db, body)
    event("relay_settings_changed", user)
    return config


@app.get("/api/clients/{name}/relay-download")
def relay_download_form(name: str, request: Request, user: dict[str, Any] = Authed):
    find_client(name)
    path = "/api/clients/" + name + "/relay.mobileconfig"
    return {"url": path, "csrf": profile_download_token(request, path)}


@app.post("/api/clients/{name}/relay.mobileconfig", dependencies=[Depends(profile_download_csrf)])
def download_relay_profile(name: str, user: dict[str, Any] = Authed):
    find_client(name)
    content = relay.profile(db, name)
    event("relay_profile_downloaded", user, name)
    return Response(content, media_type="application/x-apple-aspen-config",
                    headers={"Content-Disposition": f'attachment; filename="{name}-relay.mobileconfig"', "Cache-Control": "no-store", "X-Profile-Signed": "false" if content.startswith(b"<?xml") else "true"})


@app.delete("/api/clients/{name}/relay", dependencies=[Csrf])
def revoke_relay(name: str, user: dict[str, Any] = Authed):
    find_client(name)
    relay.revoke(db, name)
    event("relay_access_revoked", user, name)
    return {"ok": True}


@app.get("/api/clients/{name}/relay-devices")
def relay_device_list(name: str, user: dict[str, Any] = Authed):
    """The client's device-bound relay profiles, and whether its unbound profiles still work."""
    find_client(name)
    config = relay.get_settings(db)
    return {"bound": config["devices"], "limit": configs.limit(db, name), "default_limit": configs.default_limit(db),
            "own_limit": configs.override(db, name), "used": configs.used(db, name),
            "shared": relay.has_shared(db, name), "devices": relay_devices.listing(db, name),
            "xray": xray.enabled(db), "xray_keys": xray.keys(db, name)}


class ConfigLimitBody(BaseModel):
    limit: int | None = Field(default=None, ge=0, le=100)     # None: the default of Settings


@app.put("/api/clients/{name}/config-limit", dependencies=[Csrf])
def set_config_limit(name: str, body: ConfigLimitBody, user: dict[str, Any] = Authed):
    """How many configs (relay devices and Xray keys together) this client may have."""
    find_client(name)
    configs.set_override(db, name, body.limit)
    event("config_limit_changed", user, name, "default" if body.limit is None else str(body.limit))
    return {"limit": configs.limit(db, name), "own_limit": body.limit}


@app.post("/api/clients/{name}/xray-keys", dependencies=[Csrf])
def new_xray_key(name: str, user: dict[str, Any] = Authed):
    """A new Xray key for the client, shown to the admin with its QR code."""
    row = find_client(name)
    if row["state"] != "valid":
        raise HTTPException(400, "Only a client with a valid certificate gets Xray keys")
    link = xray.link(db, name)
    event("xray_key_issued", user, name)
    return {"link": link, "qr_svg": pki.qr_svg(link)}


@app.get("/api/clients/{name}/xray-keys/{key}")
def show_xray_key(name: str, key: str, user: dict[str, Any] = Authed):
    find_client(name)
    link = xray.key_link(db, name, key)
    event("xray_key_shown", user, name)
    return {"link": link, "qr_svg": pki.qr_svg(link)}


@app.delete("/api/clients/{name}/xray-keys/{key}", dependencies=[Csrf])
def remove_xray_key(name: str, key: str, user: dict[str, Any] = Authed):
    find_client(name)
    xray.remove_key(db, name, key)
    event("xray_key_removed", user, name)
    return {"ok": True}


@app.delete("/api/clients/{name}/relay-devices/{device}", dependencies=[Csrf])
def revoke_relay_device(name: str, device: str, user: dict[str, Any] = Authed):
    find_client(name)
    if not relay_devices.revoke(db, name, device) and not any(d["id"] == device for d in relay_devices.listing(db, name)):
        raise HTTPException(404, "No such device")
    event("relay_device_revoked", user, name, device)
    return {"ok": True}


@app.delete("/api/clients/{name}/relay-shared", dependencies=[Csrf])
def revoke_relay_shared(name: str, user: dict[str, Any] = Authed):
    """Profiles without device binding stop working; device-bound ones keep working."""
    find_client(name)
    relay.revoke_shared(db, name)
    event("relay_shared_revoked", user, name)
    return {"ok": True}


# -- ACME for device-bound relay profiles (public, like /p/) ------------------------------------
acme = relay_devices.Acme(db, lambda: relay.acme_base(db))
ACME_BODY = 64 * 1024


def acme_reply(body, status=200, location=None, link=None, content_type="application/json"):
    headers = {"Replay-Nonce": acme.nonce(), "Cache-Control": "no-store",
               "Link": f'<{acme.url("directory")}>;rel="index"'}
    if location:
        headers["Location"] = location
    if link:
        headers["Link"] += f', <{link}>;rel="up"'
    if isinstance(body, bytes):
        return Response(body, status_code=status, media_type=content_type, headers=headers)
    return JSONResponse(body, status_code=status, headers=headers)


def acme_problem(exc: relay_devices.AcmeError):
    response = acme_reply({"type": "urn:ietf:params:acme:error:" + exc.kind, "detail": exc.detail}, exc.status)
    response.headers["Content-Type"] = "application/problem+json"
    return response


def acme_ready():
    if not relay.acme_base(db):
        raise HTTPException(404, "Not found")


@app.get("/acme/directory")
def acme_directory():
    acme_ready()
    return JSONResponse(acme.directory(), headers={"Cache-Control": "no-store"})


@app.api_route("/acme/new-nonce", methods=["GET", "HEAD"])
def acme_new_nonce(request: Request):
    acme_ready()
    return Response(status_code=200 if request.method == "HEAD" else 204,
                    headers={"Replay-Nonce": acme.nonce(), "Cache-Control": "no-store",
                             "Link": f'<{acme.url("directory")}>;rel="index"'})


@app.post("/acme/{resource:path}")
async def acme_post(resource: str, request: Request):
    acme_ready()
    if int(request.headers.get("content-length") or 0) > ACME_BODY:
        return acme_problem(relay_devices.AcmeError(413, "malformed", "Request too large"))
    body = await request.body()
    if len(body) > ACME_BODY:
        return acme_problem(relay_devices.AcmeError(413, "malformed", "Request too large"))
    try:
        return await run_in_threadpool(acme_handle, resource, body)
    except relay_devices.AcmeError as exc:
        return acme_problem(exc)
    except PkiError:
        return acme_problem(relay_devices.AcmeError(500, "serverInternal", "Enrolment failed; try again"))


def acme_handle(resource: str, body: bytes):
    if resource == "new-account":
        payload, jwk, account = acme.verify(body, resource, new_account=True)
        return acme_reply({"status": "valid"}, 201 if not (payload or {}).get("onlyReturnExisting") else 200, location=account)
    payload, jwk, _ = acme.verify(body, resource)
    if resource == "new-order":
        row = acme.new_order(payload, jwk)
        return acme_reply(acme.order(row), 201, location=acme.url("order/" + row["id"]))
    kind, _, rest = resource.partition("/")
    if kind == "order" and rest.endswith("/finalize"):
        row = acme.finalize(acme.device(rest[:-len("/finalize")]), payload, jwk)
        return acme_reply(acme.order(row), location=acme.url("order/" + row["id"]))
    if kind in ("order", "authz", "chall", "cert") and "/" not in rest:
        row = acme.device(rest)
        if kind == "order":
            acme.owned(row, jwk)
            return acme_reply(acme.order(row), location=acme.url("order/" + row["id"]))
        if kind == "authz":
            acme.owned(row, jwk)
            return acme_reply(acme.authz(row))
        if kind == "chall":
            return acme_reply(acme.answer(row, jwk), link=acme.url("authz/" + row["id"]))
        return acme_reply(acme.certificate(row, jwk), content_type="application/pem-certificate-chain")
    raise relay_devices.AcmeError(404, "malformed", "Unknown resource")


@app.post("/api/relay/authorize")
def authorize_relay(request: Request):
    # Machine endpoint: a relay credential, never an admin cookie, authorizes it.
    policy = relay.authorize(db, request.headers.get("authorization", ""))
    if policy is None:
        raise HTTPException(403, "Relay access denied")
    return policy


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
    relay.revoke(db, name)
    drop_share_links(name)
    xray.forget(db, name)
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
    relay.renewed(db, name, row["cert"]["serial"])
    cert = relay.eligible(name)
    if cert:
        db.execute("UPDATE users SET client_serial = ? WHERE client_name = ? AND client_serial = ?",
                   (cert["serial"], name, row["cert"]["serial"]))
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
    disable_portal(name)
    relay.revoke(db, name)
    relay_devices.forget(db, name)     # a new client with this name starts without them
    drop_share_links(name)
    xray.forget(db, name)
    serials = [row["cert"]["serial"]] + [h["serial"] for h in row["history"]]
    with db.tx() as conn:
        for serial in serials:
            conn.execute("INSERT INTO hidden_certs (serial, name, hidden_at) VALUES (?, ?, ?) ON CONFLICT DO NOTHING",
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


@app.put("/api/clients/{name}/access", dependencies=[Csrf])
def set_access(name: str, body: AccessBody, user: dict[str, Any] = Authed):
    find_client(name)
    changed = relay.is_guest(name) != body.guest
    pki.set_guest(name, body.guest)
    event("access_changed", user, name, "guest" if body.guest else "full")
    # One rule for both ways in. The relay re-reads it within seconds; an OpenVPN device keeps the
    # address range of its old role until it connects again, so its connections are ended now
    # (the device reconnects by itself).
    reconnected = False
    if changed:
        try:
            mgmt.kill(name)
            reconnected = True
        except ManagementError as exc:
            if "not found" not in str(exc).lower():
                log.warning("could not reconnect %s after an access change: %s", name, exc)
    return {"guest": body.guest, "reconnected": reconnected,
            "note": "Applies to OpenVPN and the relay alike: connected OpenVPN devices reconnect now, "
                    "the relay follows within seconds"}


@app.post("/api/clients/{name}/share", dependencies=[Csrf])
def share_profile(name: str, body: ShareBody, request: Request, user: dict[str, Any] = Authed):
    """A one-time link to the OpenVPN or the Apple relay profile, with a QR code."""
    row = find_client(name)
    if row["state"] != "valid":
        raise HTTPException(400, "Only a client with a valid certificate can be shared")
    link = create_share_link(name, body.kind, body.hours, user["username"], request)
    event("profile_link_created", user, name, f"{body.kind}, valid {body.hours} h")
    return {**link, "qr_svg": pki.qr_svg(link["import_url"] or link["url"])}


def create_share_link(name: str, kind: str, hours: int, created_by: str, request: Request | None = None) -> dict:
    """{"url", "import_url", "expires_at", "public"}: a one-time link to one profile of a valid client."""
    if kind == "relay" and not relay.get_settings(db)["enabled"]:
        raise HTTPException(400, "Apple relay profiles are not offered (Settings → Apple relay)")
    if kind == "xray" and not xray.enabled(db):
        raise HTTPException(400, "Xray is off (Settings → Xray)")
    if kind == "xray" or (kind == "relay" and relay.get_settings(db)["devices"]):
        configs.check(db, name)     # no link to a config the client has no room for
    token = secrets.token_urlsafe(24)
    now = int(time.time())
    db.execute("INSERT INTO share_tokens (token_hash, client_name, created_at, expires_at, created_by, kind) "
               "VALUES (?, ?, ?, ?, ?, ?)", (auth.token_hash(token), name, now, now + hours * 3600, created_by, kind))
    base, public = share_base(request)
    url = f"{base}/p/{token}"
    return {"url": url, "import_url": f"openvpn://import-profile/{url}/download" if kind == "openvpn" else "",
            "expires_at": now + hours * 3600, "public": public, "kind": kind}


def share_base(request: Request | None = None) -> tuple[str, bool]:
    """(base address of one-time links, whether it is a public one). OVPN_PROFILE_BASE_URL, else the
    website hostname of Settings → Network (the gateway routes /p/ there from anywhere), else the
    address the admin is using."""
    if settings.profile_base_url:
        return settings.profile_base_url, True
    host = network.get_settings(db)["gateway"]["openvpn_host"]
    if host:
        return "https://" + host, True
    return (str(request.base_url).rstrip("/") if request else ""), False


# A spent link keeps handing out the same file for a few minutes: iOS fetches a relay profile twice
# (Safari, then the profile installer), and a page closed by mistake can be opened again.
SHARE_GRACE = 600


def shared_link(token: str, request: Request) -> tuple[str, str]:
    """(client, kind) of a one-time link that is unused, or spent less than SHARE_GRACE ago.
    Wrong links from one address are slowed down."""
    key = f"share|{client_ip(request)}"
    wait = limiter.attempt(key)
    if wait:
        raise HTTPException(429, f"Too many attempts, try again in {wait}s", headers={"Retry-After": str(wait)})
    now = int(time.time())
    row = db.one("SELECT client_name, kind FROM share_tokens WHERE token_hash = ? AND "
                 "((used_at IS NULL AND expires_at > ?) OR served_until >= ?)", (auth.token_hash(token), now, now))
    if row is None or not (settings.pki_dir / "issued" / f"{row['client_name']}.crt").exists():
        raise HTTPException(404, "This link is invalid, expired or already used")
    limiter.success(key)
    return row["client_name"], row["kind"]


def share_content(token: str, name: str, kind: str, request: Request) -> bytes:
    """The file behind a link: made once, by the request that spends the link; the same bytes to
    every request within SHARE_GRACE. A failure leaves the link unused."""
    token_hash = auth.token_hash(token)
    now = int(time.time())
    with db.tx() as conn:
        claimed = conn.execute("UPDATE share_tokens SET used_at = ?, served_until = ? WHERE token_hash = ? "
                               "AND used_at IS NULL AND expires_at > ?", (now, now + SHARE_GRACE, token_hash, now)).rowcount
        if claimed:         # in the same transaction: a link is never spent without a trace
            db.add_event("profile_link_used", name, None, client_ip(request), conn=conn)
    if not claimed:         # spent already: wait for what the first request made (it may still be signing)
        for _ in range(60):
            row = db.one("SELECT content FROM share_tokens WHERE token_hash = ? AND served_until >= ?",
                         (token_hash, int(time.time())))
            if row is None:
                break
            if row["content"] is not None:
                return bytes(row["content"])
            time.sleep(0.5)
        raise HTTPException(404, "This link is invalid, expired or already used")
    try:
        if kind == "xray":
            content = xray.link(db, name).encode()      # a new key: one slot of the client's configs
        elif kind == "relay":
            try:
                content = relay.profile(db, name)
            except relay_devices.DeviceLimit:
                raise
            except PkiError:
                if relay_services.signing_config(db)["required"] or relay_services.signing_config(db)["url"]:
                    raise HTTPException(503, "The profile is temporarily unavailable. Please retry in a minute.")
                raise
        else:
            content = pki.build_profile(name).encode()
    except BaseException:
        db.execute("UPDATE share_tokens SET used_at = NULL, served_until = NULL WHERE token_hash = ?", (token_hash,))
        raise
    db.execute("UPDATE share_tokens SET content = ? WHERE token_hash = ?", (content, token_hash))
    return content


SHARE_CSS = ("body{font:17px/1.5 system-ui,sans-serif;max-width:26rem;margin:12vh auto;padding:0 20px;"
             "color:#16181d;background:#fff}h1{font-size:1.4rem}a{display:block;margin:14px 0;padding:13px 16px;"
             "border-radius:8px;text-align:center;text-decoration:none;font-weight:600;color:#fff;background:#1f6feb}"
             "a+a{color:#1f6feb;background:none;border:1px solid}"
             "textarea{width:100%;box-sizing:border-box;font:13px/1.4 ui-monospace,monospace;padding:8px}"
             "svg{display:block;width:100%;max-width:18rem;margin:16px auto;background:#fff}"
             "@media(prefers-color-scheme:dark){body{color:#e6e8eb;background:#111418}}")
SHARE_HEAD = ('<!doctype html><html lang="ru"><head><meta charset="utf-8">'
              '<meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">'
              "<title>TITLE</title><style>" + SHARE_CSS + "</style></head><body><h1>TITLE</h1>")
# The pages behind one-time links are for the people who get them: Russian, step by step.
SHARE_PAGES = {
    "openvpn": SHARE_HEAD.replace("TITLE", "Профиль OpenVPN")
    + "<p>Откройте эту страницу на том устройстве, где будет работать VPN. "
      "Сначала установите приложение OpenVPN Connect.</p>"
      '<a href="IMPORT_URL">Открыть в OpenVPN Connect</a><a href="DOWNLOAD_URL">Скачать файл .ovpn</a>'
      "<p>Если кнопка «Открыть» не сработала, скачайте файл и откройте его в OpenVPN Connect. "
      "Профиль выдаётся один раз.</p></body></html>",
    "relay": SHARE_HEAD.replace("TITLE", "Профиль Apple Relay")
    + "<p>Откройте эту страницу в Safari на iPhone, iPad или Mac, где будет работать защита.</p>"
      '<a href="DOWNLOAD_URL">Установить профиль</a>'
      "<p>Затем откройте Настройки → «Профиль загружен» → «Установить». На Mac: Системные настройки → Профили. "
      "Профиль выдаётся один раз.</p></body></html>",
    "xray": SHARE_HEAD.replace("TITLE", "Ключ Xray")
    + "<p>Откройте эту страницу на том устройстве, где будет работать Xray. Ключ показывается один раз. "
      "Не закрывайте следующую страницу, пока не добавите его в приложение.</p>"
      '<a href="DOWNLOAD_URL">Показать мой ключ</a></body></html>',
}
XRAY_KEY_HEAD = (SHARE_HEAD.replace("TITLE", "Ключ Xray")
                 + "<ol><li>Установите приложение: v2RayTun или Streisand (iPhone, Mac), v2RayTun или v2rayNG (Android), "
                   "Hiddify (Windows, macOS, Linux).</li>"
                   "<li>Скопируйте ключ ниже целиком.</li>"
                   "<li>В приложении нажмите «+» → «Импорт из буфера обмена» и подключитесь.</li></ol>"
                   "<p>Или отсканируйте QR-код приложением на другом устройстве.</p>")
XRAY_KEY_TAIL = "<p>Ключ личный, не пересылайте его. Через 10 минут эта страница перестанет открываться.</p></body></html>"
SHARE_ERRORS = {
    404: ("Ссылка недействительна", "Она уже использована или прошёл час. Запросите новую ссылку в боте или у администратора."),
    429: ("Слишком много попыток", "Подождите немного и откройте ссылку снова."),
}
SHARE_LIMIT = ("Слишком много устройств", "У вас уже столько подключений (Apple Relay и Xray), сколько разрешено. "
               "Каждый профиль и ключ работает на одном устройстве. Попросите администратора удалить старое "
               "и откройте ссылку снова.")
SHARE_FAILED = ("Профиль сейчас не готов", "Попробуйте ещё раз через минуту. Если не получится — напишите администратору.")


def share_errors(handler):
    """A failed one-time link shows a short page in the recipient's language, not an API error."""
    @functools.wraps(handler)
    def page(token: str, request: Request):
        try:
            return handler(token, request)
        except HTTPException as exc:
            status, headers = exc.status_code, dict(exc.headers or {})
        except relay_devices.DeviceLimit:
            status, headers = 409, {}
        except PkiError:
            status, headers = 400, {}
        title, text = SHARE_LIMIT if status == 409 else SHARE_ERRORS.get(status, SHARE_FAILED)
        return HTMLResponse(SHARE_HEAD.replace("TITLE", title) + f"<p>{text}</p></body></html>", status_code=status,
                            headers={**headers, "Content-Security-Policy": SHARE_CSP})
    return page


SHARE_CSP = ("default-src 'none'; style-src 'sha256-" + base64.b64encode(hashlib.sha256(SHARE_CSS.encode()).digest()).decode()
             + "'; frame-ancestors 'none'; base-uri 'none'")


@app.get("/p/{token}")
@share_errors
def shared_profile_page(token: str, request: Request):
    """Public: the page behind a one-time link. It only offers the profile, so that a messenger
    fetching the link for a preview does not use the link up. /p/ is the only path meant to be
    exposed by a proxy."""
    _, kind = shared_link(token, request)
    url = f"{share_base(request)[0]}/p/{token}/download"
    page = SHARE_PAGES[kind].replace("IMPORT_URL", html.escape("openvpn://import-profile/" + url, quote=True)).replace(
        "DOWNLOAD_URL", html.escape(url, quote=True))
    return HTMLResponse(page, headers={"Content-Security-Policy": SHARE_CSP})


@app.get("/p/{token}/download")
@share_errors
def shared_profile(token: str, request: Request):
    """Public: the profile itself, once (the same file again for SHARE_GRACE seconds)."""
    name, kind = shared_link(token, request)
    content = share_content(token, name, kind, request)
    if kind == "xray":
        content = content.decode()
        page = (XRAY_KEY_HEAD + '<textarea readonly rows="6" aria-label="Ключ Xray">' + html.escape(content) + "</textarea>"
                + pki.qr_svg(content, inline=True) + XRAY_KEY_TAIL)
        return HTMLResponse(page, headers={"Content-Security-Policy": SHARE_CSP})
    if kind == "relay":
        return Response(content, media_type="application/x-apple-aspen-config",
                        headers={"Content-Disposition": f'attachment; filename="{name}-relay.mobileconfig"'})
    return PlainTextResponse(content.decode(), media_type="application/x-openvpn-profile",
                             headers={"Content-Disposition": f'attachment; filename="{name}.ovpn"'})


@app.put("/api/clients/{name}/note", dependencies=[Csrf])
def set_note(name: str, body: NoteBody, user: dict[str, Any] = Authed):
    find_client(name)
    db.execute("INSERT INTO clients (name, note, created_at) VALUES (?, ?, ?) "
               "ON CONFLICT(name) DO UPDATE SET note = excluded.note", (name, body.note.strip(), int(time.time())))
    return {"note": body.note.strip()}


# -- sessions / traffic -----------------------------------------------------------
@app.get("/api/sessions")
def sessions(name: str | None = None, limit: int = 100, offset: int = 0, active: bool = False,
             merge: bool = False, via: str = "vpn", user: dict[str, Any] = Authed):
    """Sessions, newest first. via: "vpn", "relay" or "all" (both in one list); merge=true folds the
    OpenVPN reconnects of one client from one address into visits."""
    if name:
        pki.validate_name(name)
    total, rows = merged_sessions(name or None, via, max(1, min(limit, 500)), max(0, offset), active, merge)
    return {"total": total, "sessions": rows}


@app.get("/api/connections")
def connections(period: Period = Depends(), user: dict[str, Any] = Authed):
    """How the OpenVPN sessions of each client went in a period: count, length, endings, share over TCP."""
    return {**period.info(), "clients": db.connection_stats(period.start, period.end)}


@app.get("/api/traffic")
def traffic(name: str | None = None, period: Period = Depends(), user: dict[str, Any] = Authed):
    if name:
        pki.validate_name(name)
    by_source = {source: db.totals(period.start, period.end, name, source) for source in ("vpn", "relay")}
    return {**period.info(), "series": period.series(name), "totals": split(by_source)}


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
        "control_channel": pki.control_channel(),
        "remote": pki.get_remote(),
        "listen": pki.server_listen(),
        "config_mtime": mtime,
        "dco": (live.get("stats") or {}).get("dco_enabled"),
        "backup": backup.status(),
        "management": {"host": _mgmt_host, "port": _mgmt_port, "password": bool(mgmt.password)},
        "ui_version": __version__,
    }


@app.get("/api/server/config/{which}")
def get_config(which: str, user: dict[str, Any] = Authed):
    return {"which": which, "path": str(pki.config_path(which)), "content": pki.read_config(which)}


@app.put("/api/server/config/{which}", dependencies=[Csrf])
def put_config(which: str, body: ConfigBody, user: dict[str, Any] = Authed):
    with pki.lock:
        pki.check_edit(which, body.content)
        pki.write_config(which, body.content)
    event("config_saved", user, None, which)
    if which == "client":
        pki.regenerate_profiles()
    elif which == "server" and pki.sync_remotes():
        # server.conf changed the protocols, so the profiles have to follow them.
        event("remote_changed", user, None, "protocols now " + ", ".join(l["proto"] for l in pki.server_listen()))
    return {"ok": True, "restart_required": which == "server"}


@app.post("/api/server/restart", dependencies=[Csrf])
def restart(user: dict[str, Any] = Authed):
    result = mgmt.signal("SIGTERM")
    event("server_restart", user, None, result)
    remember_pushed_routes()      # the firewall reads server.conf again at this restart too
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


@app.post("/api/server/backup", dependencies=[Csrf])
def backup_now(user: dict[str, Any] = Authed):
    try:
        path = backup.create()
    except (OSError, ValueError) as exc:
        raise HTTPException(500, f"The backup failed: {exc}")
    event("backup_created", user, None, path.name)
    return {"backup": backup.status()}


@app.put("/api/server/tfa", dependencies=[Csrf])
def enforce_tfa(body: TfaEnforceBody, user: dict[str, Any] = Authed):
    pki.set_tfa_enforced(body.enforced)
    pki.regenerate_profiles()
    event("tfa_enforced" if body.enforced else "tfa_unenforced", user)
    return {"enforced": body.enforced, "restart_required": True}


@app.put("/api/server/control-channel", dependencies=[Csrf])
def control_channel(body: ControlChannelBody, user: dict[str, Any] = Authed):
    pki.set_control_channel(body.per_client)
    event("control_channel_changed", user, None, pki.control_channel())
    return {"control_channel": pki.control_channel(), "restart_required": True}


@app.get("/api/events")
def events(limit: int = 100, user: dict[str, Any] = Authed):
    rows = db.query("SELECT * FROM events ORDER BY id DESC LIMIT ?", (max(1, min(limit, 1000)),))
    return {"events": [dict(r) for r in rows]}


@app.get("/api/settings")
def get_settings(user: dict[str, Any] = Authed):
    return {"remote": pki.get_remote(), "listen": pki.server_listen(), "tfa_issuer": settings.tfa_issuer,
            "poll_interval": settings.poll_interval, "version": __version__}


@app.get("/api/network/settings")
def get_network_settings(user: dict[str, Any] = Authed):
    return JSONResponse(network.get_settings(db), headers={"Cache-Control": "no-store"})


@app.post("/api/network/discovery", dependencies=[Csrf])
def discover_network(body: network.NetworkSettings, request: Request, user: dict[str, Any] = Authed):
    data = network.with_defaults(body.model_dump(), db)
    peer = getattr(request.state, "network_peer", None)
    return JSONResponse(network_discovery.discover(data, peer=peer, proxied=bool(request.headers.get("x-forwarded-proto"))),
                        headers={"Cache-Control": "no-store"})


class NetworkUpdate(network.NetworkSettings):
    """The whole Settings → Network form: network settings, relay switch and URL, profile address."""
    relay_settings: relay.RelaySettings | None = Field(default=None, alias="relay")
    remote: RemoteBody | None = None


@app.put("/api/network/settings", dependencies=[Csrf])
def put_network_settings(body: NetworkUpdate, user: dict[str, Any] = Authed):
    # Validate every part before changing anything.
    relay_config = relay.validate_settings(body.relay_settings) if body.relay_settings is not None else None
    if (relay_config is not None and body.relay_settings.devices and "devices" in body.relay_settings.model_fields_set
            and not relay.get_settings(db)["devices"]):
        relay.device_self_test(db, {**relay.get_settings(db), **body.relay_settings.model_dump(exclude_unset=True)})
    if relay_config is not None:
        body.gateway.relay_public_url = relay_config["url"]
    if body.remote is not None:
        pki.validate_remote(body.remote.host, body.remote.ports)
    result = network.save_settings(network.NetworkSettings(**body.model_dump(exclude={"relay_settings", "remote"})))
    if relay_config is not None:
        result["relay"] = relay.save_settings(db, body.relay_settings)
    if body.remote is not None:
        current = pki.get_remote()
        ports = {item["proto"]: int(item["port"]) for item in current["remotes"]}
        if current["host"] != body.remote.host.strip() or any(ports.get(proto) != port for proto, port in body.remote.ports.items()):
            pki.set_remote(body.remote.host, body.remote.ports)
        result["remote"] = pki.get_remote()
    event("network_settings_changed", user)  # Never put network values in audit events.
    return result


@app.post("/api/network/guest-check", dependencies=[Csrf])
def check_guest_access(user: dict[str, Any] = Authed):
    """Read-only: whether guests reach the saved portal and guest links through the gateway."""
    return JSONResponse(guest_check.check(db), headers={"Cache-Control": "no-store"})


@app.get("/api/network/traefik.json")
def download_gateway_network(user: dict[str, Any] = Authed):
    exported = network.export_gateway(db)
    xui = xray.panel(network.get_settings(db)["gateway"])
    if xui:         # the gateway routes the 3x-ui panel next to the OpenVPN website
        exported["xui_panel"] = {"path": xui["path"], "backend": xui["backend"]}
    return JSONResponse(exported, headers={"Cache-Control": "no-store",
        "Content-Disposition": 'attachment; filename="network.private.json"'})


@app.put("/api/settings", dependencies=[Csrf])
def put_settings(body: RemoteBody, user: dict[str, Any] = Authed):
    pki.set_remote(body.host, body.ports)
    remote = pki.get_remote()
    event("remote_changed", user, None, remote["host"] + " " + ", ".join(f"{r['port']}/{r['proto']}" for r in remote["remotes"]))
    return {"remote": remote, "listen": pki.server_listen()}


# -- misc -----------------------------------------------------------------------
@app.get("/healthz")
def healthz():
    if not collector.alive():       # the thread died or hangs: no statistics are being recorded
        raise HTTPException(503, "The collector is not running")
    return {"ok": True, "openvpn": collector.snapshot()["connected"]}


@app.get("/")
@app.get("/portal")
def index():
    # Deployments can change assets without changing the release version.
    # Hash their contents so the browser cannot reuse a previous build's UI.
    def versioned(match: re.Match) -> str:
        digest = hashlib.sha256((STATIC_DIR / match[1]).read_bytes()).hexdigest()[:16]
        return f'"/static/{match[1]}?v={digest}"'

    html = re.sub(r'"/static/([\w.-]+)"', versioned, (STATIC_DIR / "index.html").read_text())
    return HTMLResponse(html, headers={"Cache-Control": "no-cache"})


app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")
