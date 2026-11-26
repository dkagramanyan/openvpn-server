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

    def call(self, method: str, http_timeout: float = 15, **params):
        # http_timeout, not timeout: "timeout" is a parameter of getUpdates itself (the long poll).
        request = urllib.request.Request(self._url + method, data=json.dumps(params).encode(),
                                         headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(request, timeout=http_timeout) as response:
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

    def __init__(self, api: Api | None, db, link: Callable, password: Callable, info: Callable, admin_chat: int | None = None):
        self.api, self.db, self.admin_chat = api, db, admin_chat
        self.link, self.password, self.info = link, password, info
        self.username: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._recent: dict[int, collections.deque] = {}
        self._asked: dict[int, float] = {}          # when an unknown account was last reported to the admin

    @property
    def configured(self) -> bool:
        return self.api is not None

    def configure(self, api: Api | None, admin_chat: int | None, username: str | None = None) -> None:
        """A new token or admin chat, from Settings → Telegram. The poller switches after its current poll."""
        self.api, self.admin_chat, self.username = api, admin_chat, username

    # -- lifecycle --------------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(target=self.run, name="telegram-bot", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()

    def run(self) -> None:
        offset, wait, polling = None, 5, None
        while not self._stop.is_set():
            api = self.api
            if api is None:                 # no token yet
                self._stop.wait(5)
                continue
            if api is not polling:          # a new token: its own updates
                offset, polling = None, api
            try:
                if self.username is None:
                    self.username = api.call("getMe")["username"]
                    log.info("Telegram bot @%s is polling", self.username)
                params = {"timeout": 50, "allowed_updates": ["message"]}
                if offset is not None:
                    params["offset"] = offset
                updates = api.call("getUpdates", http_timeout=60, **params)
                wait = 5
                if self.api is not api:     # replaced during the poll: these belong to the old bot
                    continue
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

    def notify_admin(self, text: str) -> None:
        if self.admin_chat is None:
            return
        try:
            self.send(self.admin_chat, text)
        except ApiError as exc:
            log.warning("Telegram: the admin chat cannot be reached: %s", exc)

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
        if bound:
            self.notify_admin(f"@{username} ({display or 'no name'}) is now linked to the client {bound['name']}.")
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
                         else ". First set a username in Telegram: Settings → My profile → Username.")
                      + f"\nYour Telegram ID: {sender['id']}")
            if sender["id"] != self.admin_chat and time.monotonic() - self._asked.get(sender["id"], -3600) >= 3600:
                self._asked[sender["id"]] = time.monotonic()
                who = " ".join(filter(None, (sender.get("first_name"), sender.get("last_name")))) or "no name"
                self.notify_admin(f"Access request from {'@' + sender['username'] if sender.get('username') else 'an account without a username'} "
                                  f"({who}, ID {sender['id']}). To let them in, enter the username on the client page under Telegram & portal.")
            return
        info = self.info(name)
        menu = [["OpenVPN"] + (["Apple relay"] if info["relay"] else []) + (["Xray"] if info["xray"] else []),
                ["Portal password", "Status"]]
        command = text.split("@", 1)[0].lower()
        if not info["valid"] and command not in ("/start", "status", "/status"):
            self.send(chat, "Your access has expired or was revoked. Ask the administrator.", menu)
            return
        if command in ("openvpn", "/openvpn"):
            self.send_link(chat, sender["id"], name, "openvpn", menu)
        elif command in ("apple relay", "/relay") and info["relay"]:
            self.send_link(chat, sender["id"], name, "relay", menu)
        elif command in ("xray", "/xray") and info["xray"]:
            self.send_link(chat, sender["id"], name, "xray", menu)
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
                      + ("Xray: a key for an Xray app, for networks where OpenVPN is blocked.\n" if info["xray"] else "")
                      + "Portal password: a new password for the website.\nStatus: your access.", menu)

    def send_link(self, chat: int, telegram_id: int, name: str, kind: str, menu) -> None:
        if not self.allowed(telegram_id):
            self.send(chat, "Too many requests. Try again in an hour.", menu)
            return
        link = self.link(name, kind)
        if not link["public"]:
            self.send(chat, "Links are not available yet: the administrator has to set the website hostname.", menu)
            return
        how = {"openvpn": "Open it on the device that will use the VPN and tap “Open in OpenVPN Connect” "
                          "(install OpenVPN Connect first).",
               "relay": "Open it in Safari on the iPhone, iPad or Mac, tap “Install the profile”, "
                        "then Settings → Profile Downloaded → Install.",
               "xray": "Open it on the device that will use it: the page shows your key and how to import it."}[kind]
        self.send(chat, f"{link['url']}\n\n{how} The link works once and for one hour.", menu)
