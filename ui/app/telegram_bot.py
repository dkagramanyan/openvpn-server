"""Telegram bot: a client gets its own profile links and portal password.

The admin writes the client's Telegram username on the client page. The first message from that
username binds its numeric Telegram id, which alone is trusted from then on (usernames can be
changed and taken by someone else). Long polling: no port to open, one poller per bot token.
"""
from __future__ import annotations

import collections
import http.client
import json
import logging
import re
import threading
import time
import urllib.error
import urllib.request
from typing import Callable

log = logging.getLogger("telegram")

USERNAME = re.compile(r"^[a-z0-9_]{5,32}$")
ACTIONS_PER_HOUR = 20       # links and passwords one Telegram account may ask for


def normalize(username: str) -> str:
    """Telegram username as stored: no "@", lower case. Raises ValueError when invalid."""
    value = username.strip().removeprefix("@").lower()
    if not USERNAME.match(value):
        raise ValueError("A Telegram username has 5–32 letters, digits or underscores")
    return value


class ApiError(Exception):
    pass


class Api:
    """The Bot API over HTTPS. The token is part of the URL: never log a URL or a request."""

    def __init__(self, token: str, base: str = "https://api.telegram.org"):
        self._url = f"{base.rstrip('/')}/bot{token}/"

    def call(self, method: str, timeout: float = 15, **params):
        request = urllib.request.Request(self._url + method, data=json.dumps(params).encode(),
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                body = json.load(response)
        except urllib.error.HTTPError as exc:
            try:
                body = json.load(exc)
            except ValueError:
                raise ApiError(f"{method}: HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError, ValueError, http.client.HTTPException) as exc:
            raise ApiError(f"{method}: {getattr(exc, 'reason', exc)}") from None
        if not body.get("ok"):
            raise ApiError(f"{method}: {body.get('description', 'error')}")
        return body["result"]


class Bot:
    """link(name, kind) -> {"url", "expires_at", "public"}; password(name) -> (username, password);
    info(name) -> {"valid", "guest", "expires_at", "relay", "portal_url"}."""

    def __init__(self, api: Api, db, link: Callable, password: Callable, info: Callable):
        self.api, self.db = api, db
        self.link, self.password, self.info = link, password, info
        self.username: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._recent: dict[int, collections.deque] = {}

    # -- lifecycle --------------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self.run, name="telegram-bot", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        offset, wait = None, 5
        while not self._stop.is_set():
            try:
                if self.username is None:
                    self.username = self.api.call("getMe")["username"]
                    log.info("Telegram bot @%s is polling", self.username)
                params = {"timeout": 50, "allowed_updates": ["message"]}
                if offset is not None:
                    params["offset"] = offset
                updates = self.api.call("getUpdates", timeout=60, **params)
                wait = 5
            except Exception as exc:     # ApiError, or anything unforeseen: the bot keeps polling
                log.warning("Telegram: %s; retrying in %d s", exc, wait)
                self._stop.wait(wait)
                wait = min(wait * 2, 300)
                continue
            for update in updates:
                offset = update["update_id"] + 1
                try:
                    self.handle(update.get("message"))
                except Exception:       # one bad message must not stop the bot
                    log.exception("Telegram: update %s failed", update["update_id"])
                    chat = ((update.get("message") or {}).get("chat") or {}).get("id")
                    try:
                        if chat:
                            self.send(chat, "Something went wrong. Try again later or ask the administrator.")
                    except ApiError:
                        pass

    # -- messages ---------------------------------------------------------------
    def send(self, chat_id: int, text: str, keyboard: list[list[str]] | None = None) -> None:
        params = {"chat_id": chat_id, "text": text, "link_preview_options": {"is_disabled": True}}
        if keyboard:
            params["reply_markup"] = {"keyboard": [[{"text": t} for t in row] for row in keyboard],
                                      "resize_keyboard": True, "is_persistent": True}
        self.api.call("sendMessage", **params)

    def client_for(self, sender: dict) -> str | None:
        """The client bound to this Telegram account; binds it on first contact by username."""
        row = self.db.one("SELECT name FROM clients WHERE telegram_id = ?", (sender["id"],))
        if row:
            return row["name"]
        username = (sender.get("username") or "").lower()
        if not username:
            return None
        display = " ".join(filter(None, (sender.get("first_name"), sender.get("last_name"))))[:128]
        with self.db.tx() as conn:
            bound = conn.execute("UPDATE clients SET telegram_id = ?, telegram_name = ? "
                                 "WHERE telegram = ? AND telegram_id IS NULL RETURNING name",
                                 (sender["id"], display, username)).fetchone()
            if bound:
                self.db.add_event("telegram_linked", bound["name"], "telegram", f"@{username} ({sender['id']})", conn=conn)
        return bound["name"] if bound else None

    def allowed(self, telegram_id: int) -> bool:
        now = time.monotonic()
        recent = self._recent.setdefault(telegram_id, collections.deque())
        while recent and recent[0] < now - 3600:
            recent.popleft()
        if len(recent) >= ACTIONS_PER_HOUR:
            return False
        recent.append(now)
        return True

    def handle(self, message: dict | None) -> None:
        if not message or message.get("chat", {}).get("type") != "private" or "from" not in message:
            return
        chat, sender = message["chat"]["id"], message["from"]
        text = (message.get("text") or "").strip()
        name = self.client_for(sender)
        if name is None:
            self.send(chat, "This Telegram account has no access yet. Ask the administrator to add your username"
                      + (f" @{sender['username']}." if sender.get("username")
                         else ". First set a username in Telegram: Settings → My profile → Username."))
            return
        info = self.info(name)
        menu = [["OpenVPN"] + (["Apple relay"] if info["relay"] else []), ["Portal password", "Status"]]
        command = text.split("@", 1)[0].lower()
        if not info["valid"] and command not in ("/start", "status", "/status"):
            self.send(chat, "Your access has expired or was revoked. Ask the administrator.", menu)
            return
        if command in ("openvpn", "/openvpn"):
            self.send_link(chat, sender["id"], name, "openvpn", menu)
        elif command in ("apple relay", "/relay") and info["relay"]:
            self.send_link(chat, sender["id"], name, "relay", menu)
        elif command in ("portal password", "/password"):
            if not self.allowed(sender["id"]):
                self.send(chat, "Too many requests. Try again in an hour.", menu)
                return
            username, password = self.password(name)
            self.db.add_event("portal_password_issued", name, "telegram")
            self.send(chat, f"Portal sign-in\nUsername: {username}\nPassword: {password}\n\n"
                      f"Open {info['portal_url']} while connected to the VPN. Your previous password and "
                      "sign-ins no longer work. Delete this message once you have saved the password.", menu)
        elif command in ("status", "/status"):
            expires = time.strftime("%Y-%m-%d", time.gmtime(info["expires_at"])) if info["expires_at"] else "unknown"
            self.send(chat, f"Account: {name}\nAccess: {'guest (internet only)' if info['guest'] else 'full'}\n"
                      f"State: {'valid' if info['valid'] else 'expired or revoked'}\nValid until: {expires}", menu)
        else:
            self.send(chat, f"Hello! This bot gives you access for the account {name}.\n\n"
                      "OpenVPN: a link to your OpenVPN profile (Android, iPhone, Windows, macOS, Linux).\n"
                      + ("Apple relay: a profile for iPhone, iPad and Mac, no app needed.\n" if info["relay"] else "")
                      + "Portal password: a new password for the website.\nStatus: your access.", menu)

    def send_link(self, chat: int, telegram_id: int, name: str, kind: str, menu) -> None:
        if not self.allowed(telegram_id):
            self.send(chat, "Too many requests. Try again in an hour.", menu)
            return
        link = self.link(name, kind)
        if not link["public"]:
            self.send(chat, "Links are not available yet: the administrator has to set the website hostname.", menu)
            return
        how = ("Open it on the device that will use the VPN and tap “Open in OpenVPN Connect” "
               "(install OpenVPN Connect first)." if kind == "openvpn" else
               "Open it in Safari on the iPhone, iPad or Mac, tap “Install the profile”, "
               "then Settings → Profile Downloaded → Install.")
        self.send(chat, f"{link['url']}\n\n{how} The link works once and for one hour.", menu)
