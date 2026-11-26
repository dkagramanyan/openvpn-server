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

# Menu buttons. Earlier keyboards (English labels, labels with emoji) and slash commands still work.
BUTTONS = {"openvpn": "OpenVPN", "relay": "Apple Relay", "xray": "Xray",
           "password": "Пароль от сайта", "status": "Мой доступ", "help": "Помощь"}
ALIASES = {**{label.lower(): action for action, label in BUTTONS.items()},
           "🔐 openvpn": "openvpn", "/openvpn": "openvpn", "🍏 apple relay": "relay", "/relay": "relay",
           "🚀 xray": "xray", "/xray": "xray", "portal password": "password", "🔑 пароль от портала": "password",
           "/password": "password", "status": "status", "ℹ️ мой доступ": "status", "/status": "status",
           "❓ помощь": "help", "/start": "help", "/help": "help"}
COMMANDS = [{"command": "start", "description": "Меню"},
            {"command": "openvpn", "description": "Подключить OpenVPN"},
            {"command": "relay", "description": "Подключить Apple Relay (iPhone, iPad, Mac)"},
            {"command": "xray", "description": "Подключить Xray"},
            {"command": "password", "description": "Новый пароль от сайта"},
            {"command": "status", "description": "Мой доступ"}]

LINK_STEPS = {
    "openvpn": ("Профиль OpenVPN:\n{url}\n\n"
                "1. Установите приложение OpenVPN Connect из App Store или Google Play. "
                "Для компьютера оно лежит на openvpn.net/client.\n"
                "2. Откройте ссылку на том устройстве, где нужен VPN.\n"
                "3. Нажмите «Открыть в OpenVPN Connect». Приложение спросит, добавить ли профиль. Согласитесь.\n"
                "4. Включите переключатель рядом с профилем. Когда он позеленеет, VPN работает.\n\n"
                "Если на шаге 3 ничего не произошло, нажмите на той же странице «Скачать файл .ovpn» "
                "и откройте скачанный файл в OpenVPN Connect."),
    "relay": ("Профиль Apple Relay:\n{url}\n\n"
              "1. Откройте ссылку в Safari. Если она открылась внутри Telegram, нажмите значок Safari (компас) "
              "в углу экрана: в окне Telegram профиль не установится.\n"
              "2. На странице нажмите «Установить профиль», затем «Разрешить».\n"
              "3. Откройте «Настройки». Вверху появится строка «Профиль загружен». Нажмите на неё, "
              "затем «Установить», и введите код-пароль телефона.\n"
              "4. Больше ничего включать не нужно: интернет на этом устройстве идёт через сервер.\n\n"
              "На Mac после шага 2 откройте «Системные настройки», наберите в поиске «Профили» и установите профиль там."),
    "xray": ("Ключ Xray:\n{url}\n\n"
             "1. Установите приложение v2RayTun на телефон. Для компьютера подойдёт Hiddify.\n"
             "2. Откройте ссылку и нажмите «Показать мой ключ».\n"
             "3. Скопируйте ключ целиком. Он начинается с vless://\n"
             "4. В v2RayTun нажмите «+» в углу экрана и выберите «Импорт из буфера обмена».\n"
             "5. Нажмите кнопку подключения.\n\n"
             "Страница с ключом открывается один раз. Не закрывайте её, пока не выполните шаг 4."),
}
ONCE = "\n\nСсылка работает один час и один раз. Если не успели, нажмите кнопку снова, бот пришлёт новую."


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
                            self.send(chat, "Не получилось выполнить запрос. Попробуйте ещё раз через минуту.")
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
            self.notify_admin(f"@{username} ({display or 'без имени'}) привязан к клиенту {bound['name']}.")
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
            self.send(chat, "Ваш доступ закончился или отозван. Напишите администратору.", menu)
            return
        if action in ("openvpn", "relay", "xray"):
            self.send_link(chat, sender["id"], name, action, menu)
        elif action == "password":
            if not self.allowed(sender["id"]):
                self.send(chat, "Слишком много запросов. Попробуйте через час.", menu)
                return
            username, password = self.password(name)
            self.db.add_event("portal_password_issued", name, "telegram")
            self.send(chat, f"Вход на сайт {info['portal_url']}\n\nЛогин: {username}\nПароль: {password}\n\n"
                      "Сайт открывается только при включённом VPN. Прежний пароль больше не работает. "
                      "Сохраните новый пароль и удалите это сообщение.", menu)
        elif action == "status":
            expires = time.strftime("%d.%m.%Y", time.gmtime(info["expires_at"])) if info["expires_at"] else "неизвестно"
            if info["valid"]:
                access = "гостевой, только интернет" if info["guest"] else "полный, интернет и домашняя сеть"
                self.send(chat, f"Учётная запись: {name}\nДоступ: {access}\nДействует до: {expires}", menu)
            else:
                self.send(chat, f"Учётная запись: {name}\nДоступ закончился или отозван. Напишите администратору.", menu)
        else:
            first = "Apple Relay" if info["relay"] else "OpenVPN"
            self.send(chat, f"Здравствуйте. Этот бот выдаёт доступ к VPN. Ваша учётная запись: {name}.\n\n"
                      "Нажмите кнопку внизу, и бот пришлёт ссылку и порядок действий.\n\n"
                      "OpenVPN работает на любом устройстве. Нужно бесплатное приложение OpenVPN Connect.\n"
                      + ("Apple Relay работает на iPhone, iPad и Mac. Приложение не нужно.\n" if info["relay"] else "")
                      + ("Xray пригодится, если OpenVPN не подключается. Нужно приложение v2RayTun.\n" if info["xray"] else "")
                      + (f"\nНа iPhone начните с {first}, на других устройствах с OpenVPN.\n" if info["relay"] else "")
                      + "\n«Пароль от сайта» выдаёт новый пароль для личного кабинета.\n"
                      "«Мой доступ» показывает, до какого числа действует доступ.", menu)

    def unknown(self, chat: int, sender: dict) -> None:
        """An account the bot does not know: what to tell the administrator, and a note to the admin chat."""
        if sender.get("username"):
            how = f"Напишите администратору своё имя в Telegram: @{sender['username']}\nКогда он добавит вас, нажмите /start."
        else:
            how = ("У вашего аккаунта нет имени пользователя. Задайте его: Настройки Telegram, «Мой профиль», "
                   "«Имя пользователя». Потом напишите это имя администратору и нажмите /start.")
        self.send(chat, f"У этого аккаунта пока нет доступа.\n\n{how}\n\nВаш Telegram ID: {sender['id']}")
        if sender["id"] != self.admin_chat and time.monotonic() - self._asked.get(sender["id"], -3600) >= 3600:
            self._asked[sender["id"]] = time.monotonic()
            who = " ".join(filter(None, (sender.get("first_name"), sender.get("last_name")))) or "без имени"
            account = "@" + sender["username"] if sender.get("username") else "аккаунт без имени пользователя"
            self.notify_admin(f"Запрос доступа: {account} ({who}, ID {sender['id']}).\n"
                              "Чтобы дать доступ, впишите имя пользователя на странице клиента, раздел «Telegram & portal».")

    def send_link(self, chat: int, telegram_id: int, name: str, kind: str, menu) -> None:
        if not self.allowed(telegram_id):
            self.send(chat, "Слишком много запросов. Попробуйте через час.", menu)
            return
        link = self.link(name, kind)
        if not link["public"]:
            self.send(chat, "Ссылки пока не работают: администратор не указал адрес сайта.", menu)
            return
        self.send(chat, LINK_STEPS[kind].format(url=link["url"]) + ONCE, menu)
