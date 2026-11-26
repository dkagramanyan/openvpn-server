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

# Menu buttons. Older keyboards (English labels) and slash commands still work.
BUTTONS = {"openvpn": "🔐 OpenVPN", "relay": "🍏 Apple Relay", "xray": "🚀 Xray",
           "password": "🔑 Пароль от портала", "status": "ℹ️ Мой доступ", "help": "❓ Помощь"}
ALIASES = {**{label.lower(): action for action, label in BUTTONS.items()},
           "openvpn": "openvpn", "/openvpn": "openvpn", "apple relay": "relay", "/relay": "relay",
           "xray": "xray", "/xray": "xray", "portal password": "password", "/password": "password",
           "status": "status", "/status": "status", "/start": "help", "/help": "help"}
COMMANDS = [{"command": "start", "description": "Главное меню"},
            {"command": "openvpn", "description": "Ссылка на профиль OpenVPN"},
            {"command": "relay", "description": "Профиль Apple Relay (iPhone, iPad, Mac)"},
            {"command": "xray", "description": "Ключ Xray"},
            {"command": "password", "description": "Новый пароль от личного кабинета"},
            {"command": "status", "description": "Мой доступ"}]

LINK_STEPS = {
    "openvpn": ("🔐 Ваша ссылка на профиль OpenVPN:\n{url}\n\n"
                "Как подключиться:\n"
                "1. Установите приложение OpenVPN Connect: App Store (iPhone, Mac), Google Play (Android) "
                "или openvpn.net/client (Windows, Linux).\n"
                "2. Откройте ссылку выше на том же устройстве.\n"
                "3. Нажмите «Открыть в OpenVPN Connect» — приложение добавит профиль. Если не сработало, "
                "нажмите «Скачать файл .ovpn» и откройте файл в OpenVPN Connect.\n"
                "4. В приложении включите переключатель рядом с профилем."),
    "relay": ("🍏 Ваша ссылка на профиль Apple Relay:\n{url}\n\n"
              "Как подключиться (iPhone, iPad, Mac), приложение не нужно:\n"
              "1. Откройте ссылку в Safari, а не внутри Telegram: нажмите на ссылку и выберите «Открыть в Safari» "
              "(значок компаса или «…» вверху).\n"
              "2. Нажмите «Установить профиль» и разрешите загрузку.\n"
              "3. Откройте Настройки → «Профиль загружен» (вверху списка) → «Установить». "
              "На Mac: Системные настройки → Профили.\n"
              "4. Готово: защита включается сама."),
    "xray": ("🚀 Ваша ссылка на ключ Xray:\n{url}\n\n"
             "Как подключиться:\n"
             "1. Установите приложение: v2RayTun или Streisand (iPhone, Mac), v2RayTun или v2rayNG (Android), "
             "Hiddify (Windows, macOS, Linux).\n"
             "2. Откройте ссылку и нажмите «Показать мой ключ».\n"
             "3. Скопируйте ключ целиком (он начинается с vless://).\n"
             "4. В приложении нажмите «+» → «Импорт из буфера обмена» и подключитесь.\n\n"
             "Ключ показывается один раз — не закрывайте страницу, пока не добавите его в приложение."),
}
ONCE = "\n\nСсылка одноразовая и действует 1 час. Не получилось — просто запросите новую."


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
                    try:
                        api.call("setMyCommands", commands=COMMANDS)
                    except ApiError as exc:
                        log.warning("Telegram: the command menu was not set: %s", exc)
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
                            self.send(chat, "Что-то пошло не так. Попробуйте ещё раз позже или напишите администратору.")
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
            self.notify_admin(f"✅ @{username} ({display or 'без имени'}) привязан к клиенту {bound['name']}.")
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
            self.unknown(chat, sender)
            return
        info = self.info(name)
        menu = [[BUTTONS["openvpn"]] + ([BUTTONS["relay"]] if info["relay"] else []) + ([BUTTONS["xray"]] if info["xray"] else []),
                [BUTTONS["password"], BUTTONS["status"]], [BUTTONS["help"]]]
        action = ALIASES.get(text.split("@", 1)[0].lower(), "help")
        if (action == "relay" and not info["relay"]) or (action == "xray" and not info["xray"]):
            action = "help"
        if not info["valid"] and action not in ("help", "status"):
            self.send(chat, "⛔️ Ваш доступ закончился или отозван. Чтобы продлить его, напишите администратору.", menu)
            return
        if action in ("openvpn", "relay", "xray"):
            self.send_link(chat, sender["id"], name, action, menu)
        elif action == "password":
            if not self.allowed(sender["id"]):
                self.send(chat, "Слишком много запросов. Попробуйте снова через час.", menu)
                return
            username, password = self.password(name)
            self.db.add_event("portal_password_issued", name, "telegram")
            self.send(chat, f"🔑 Вход в личный кабинет\n\nЛогин: {username}\nПароль: {password}\n\n"
                      f"Сайт: {info['portal_url']}\nОн открывается только при включённом VPN.\n\n"
                      "Старый пароль больше не действует. Сохраните новый (например, в менеджере паролей) "
                      "и удалите это сообщение.", menu)
        elif action == "status":
            expires = time.strftime("%d.%m.%Y", time.gmtime(info["expires_at"])) if info["expires_at"] else "неизвестно"
            self.send(chat, f"ℹ️ Ваш доступ\n\nУчётная запись: {name}\n"
                      f"Тип: {'гостевой — только интернет' if info['guest'] else 'полный — интернет и домашняя сеть'}\n"
                      f"Состояние: {'действует' if info['valid'] else 'закончился или отозван'}\n"
                      f"Действует до: {expires}", menu)
        else:
            self.send(chat, f"👋 Здравствуйте! Это бот для подключения к VPN. Ваша учётная запись: {name}.\n\n"
                      "Выберите способ подключения кнопкой внизу:\n\n"
                      "🔐 OpenVPN — для любых устройств: iPhone, Android, Windows, macOS, Linux. "
                      "Нужно приложение OpenVPN Connect.\n"
                      + ("🍏 Apple Relay — для iPhone, iPad и Mac, без приложений: ставится профилем в настройках.\n"
                         if info["relay"] else "")
                      + ("🚀 Xray — если OpenVPN не подключается (например, в мобильной сети). "
                         "Нужно приложение v2RayTun, Streisand, v2rayNG или Hiddify.\n" if info["xray"] else "")
                      + "\n🔑 Пароль от портала — новый пароль для личного кабинета на сайте.\n"
                      "ℹ️ Мой доступ — какой у вас доступ и до какого числа.\n\n"
                      "Каждая ссылка одноразовая и действует 1 час.", menu)

    def unknown(self, chat: int, sender: dict) -> None:
        """An account the bot does not know: what to tell the administrator, and a note to the admin chat."""
        if sender.get("username"):
            how = f"Сообщите администратору ваше имя пользователя: @{sender['username']}\nПосле этого снова нажмите /start."
        else:
            how = ("Сначала задайте имя пользователя в Telegram: Настройки → Мой профиль → Имя пользователя. "
                   "Затем сообщите его администратору и снова нажмите /start.")
        self.send(chat, f"У этого аккаунта Telegram пока нет доступа.\n\n{how}\n\nВаш Telegram ID: {sender['id']}")
        if sender["id"] != self.admin_chat and time.monotonic() - self._asked.get(sender["id"], -3600) >= 3600:
            self._asked[sender["id"]] = time.monotonic()
            who = " ".join(filter(None, (sender.get("first_name"), sender.get("last_name")))) or "без имени"
            account = "@" + sender["username"] if sender.get("username") else "аккаунт без имени пользователя"
            self.notify_admin(f"🙋 Запрос доступа: {account} ({who}, ID {sender['id']}).\n"
                              "Чтобы дать доступ, впишите имя пользователя на странице клиента в разделе «Telegram & portal».")

    def send_link(self, chat: int, telegram_id: int, name: str, kind: str, menu) -> None:
        if not self.allowed(telegram_id):
            self.send(chat, "Слишком много запросов. Попробуйте снова через час.", menu)
            return
        link = self.link(name, kind)
        if not link["public"]:
            self.send(chat, "Ссылки пока недоступны: администратор ещё не настроил адрес сайта. Попробуйте позже.", menu)
            return
        self.send(chat, LINK_STEPS[kind].format(url=link["url"]) + ONCE, menu)
