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
from .configs import ConfigLimit

log = logging.getLogger("telegram")

USERNAME = re.compile(r"^[a-z0-9_]{5,32}$")
ACTIONS_PER_HOUR = 20       # links and passwords one Telegram account may ask for

# Menu buttons. Earlier keyboards (English labels, labels with emoji) and slash commands still work.
BUTTONS = {"openvpn": "OpenVPN", "relay": "Apple Relay", "xray": "Xray",
           "password": "Пароль от сайта", "status": "Мой доступ", "configs": "Мои подключения", "help": "Помощь"}
ALIASES = {**{label.lower(): action for action, label in BUTTONS.items()},
           "🔐 openvpn": "openvpn", "/openvpn": "openvpn", "🍏 apple relay": "relay", "/relay": "relay",
           "🚀 xray": "xray", "/xray": "xray", "portal password": "password", "🔑 пароль от портала": "password",
           "/password": "password", "status": "status", "ℹ️ мой доступ": "status", "/status": "status",
           "❓ помощь": "help", "/start": "help", "/help": "help", "/configs": "configs"}
COMMANDS = [{"command": "start", "description": "Меню"},
            {"command": "openvpn", "description": "Подключить OpenVPN"},
            {"command": "relay", "description": "Подключить Apple Relay (iPhone, iPad, Mac)"},
            {"command": "xray", "description": "Подключить Xray"},
            {"command": "password", "description": "Новый пароль от сайта"},
            {"command": "status", "description": "Мой доступ"},
            {"command": "configs", "description": "Мои подключения: посмотреть и удалить"}]
KINDS = {"relay": "Apple Relay", "xray": "Xray"}

LINK_STEPS = {
    "openvpn": ("Вот ссылка на OpenVPN:\n{url}\n\n"
                "Поставьте приложение OpenVPN Connect, откройте ссылку на этом же устройстве и нажмите "
                "«Открыть в OpenVPN Connect». Потом включите профиль в приложении.\n\n"
                "Если приложение не открылось, скачайте на той же странице файл .ovpn и откройте его в OpenVPN Connect."),
    "relay": ("Вот ссылка на Apple Relay:\n{url}\n\n"
              "Откройте её в Safari (если она открылась в Telegram, нажмите значок компаса) "
              "и нажмите «Установить профиль». Потом зайдите в Настройки, нажмите вверху «Профиль загружен» "
              "и установите его. Больше ничего делать не нужно."),
    "xray": ("Вот ссылка на ключ Xray:\n{url}\n\n"
             "Поставьте приложение v2RayTun (на компьютер — Hiddify). Откройте ссылку, нажмите «Показать мой ключ» "
             "и скопируйте ключ. В v2RayTun нажмите «+», выберите «Импорт из буфера обмена» и подключитесь.\n\n"
             "Ключ можно открыть по ссылке только в течение 10 минут после первого открытия, так что добавьте его сразу."),
}
ONCE = "\n\nСсылка одноразовая и работает час."


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
    info(name) -> {"valid", "guest", "expires_at", "relay", "xray", "configs", "portal_url"};
    configs(name) -> {"used", "limit", "items": [{"kind", "id", "key", "state", "since", "last_seen"}]};
    remove(name, kind, key) -> bool: the client's relay device or Xray key ends."""

    def __init__(self, api: Api | None, db, link: Callable, password: Callable, info: Callable, admin_chat: int | None = None,
                 configs: Callable | None = None, remove: Callable | None = None):
        self.api, self.db, self.admin_chat = api, db, admin_chat
        self.link, self.password, self.info = link, password, info
        self.configs, self.remove = configs, remove
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
                params = {"timeout": 50, "allowed_updates": ["message", "callback_query"]}
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
                    if update.get("callback_query"):
                        self.handle_button(update["callback_query"])
                    else:
                        self.handle(update.get("message"))
                except Exception:       # one bad message must not stop the bot
                    log.exception("Telegram: update %s failed", update["update_id"])
                    chat = ((update.get("message") or (update.get("callback_query") or {}).get("message") or {})
                            .get("chat") or {}).get("id")
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

    def send_buttons(self, chat_id: int, text: str, buttons: list[list[tuple[str, str]]]) -> None:
        """A message with buttons under it (inline keyboard): (label, callback data) per button."""
        params = {"chat_id": chat_id, "text": text, "link_preview_options": {"is_disabled": True}}
        if buttons:
            params["reply_markup"] = {"inline_keyboard": [[{"text": t, "callback_data": d} for t, d in row] for row in buttons]}
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
        menu = self.menu(info)
        action = ALIASES.get(text.split("@", 1)[0].lower(), "help")
        if (action == "relay" and not info["relay"]) or (action == "xray" and not info["xray"]) or \
                (action == "configs" and not self.has_configs(info)):
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
            self.send(chat, f"Логин: {username}\nПароль: {password}\n\n"
                      f"Сайт: {info['portal_url']} (открывается только с включённым VPN). "
                      "Старый пароль больше не работает. Сохраните новый и удалите это сообщение.", menu)
        elif action == "configs":
            self.list_configs(chat, name)
        elif action == "status":
            expires = time.strftime("%d.%m.%Y", time.gmtime(info["expires_at"])) if info["expires_at"] else "неизвестно"
            if info["valid"]:
                access = "гостевой, только интернет" if info["guest"] else "полный, интернет и домашняя сеть"
                self.send(chat, f"Учётная запись: {name}\nДоступ: {access}\nДействует до: {expires}", menu)
            else:
                self.send(chat, f"Учётная запись: {name}\nДоступ закончился или отозван. Напишите администратору.", menu)
        else:
            self.send(chat, "Привет! Здесь можно получить доступ к VPN.\n\n"
                      "Выберите способ кнопкой внизу:\n"
                      "OpenVPN — для любого телефона и компьютера.\n"
                      + ("Apple Relay — для iPhone, iPad и Mac, без приложений.\n" if info["relay"] else "")
                      + ("Xray — если OpenVPN не подключается.\n" if info["xray"] else "")
                      + "\n«Пароль от сайта» пришлёт новый пароль для личного кабинета, "
                      "«Мой доступ» покажет, до какого числа он действует."
                      + ("\n«Мои подключения» покажет ваши подключения Apple Relay и Xray: там можно удалить "
                         "ненужное, чтобы получить новое." if self.has_configs(info) else ""), menu)

    def has_configs(self, info: dict) -> bool:
        return self.configs is not None and bool(info.get("configs"))

    def menu(self, info: dict) -> list[list[str]]:
        return [[BUTTONS["openvpn"]] + ([BUTTONS["relay"]] if info["relay"] else []) + ([BUTTONS["xray"]] if info["xray"] else []),
                [BUTTONS["password"], BUTTONS["status"]],
                ([BUTTONS["configs"]] if self.has_configs(info) else []) + [BUTTONS["help"]]]

    # -- my configs: see them, remove one to make room --------------------------------
    def list_configs(self, chat: int, name: str) -> None:
        data = self.configs(name)
        items = data["items"]
        lines = [f"Ваши подключения: {data['used']} из {data['limit']}."]
        if not items:
            lines.append("\nПока ни одного. Получите Apple Relay или Xray кнопкой внизу.")
            self.send(chat, "\n".join(lines))
            return
        for i, item in enumerate(items, 1):
            day = time.strftime("%d.%m.%Y", time.localtime(item["since"]))
            if item["state"] == "waiting":
                state = f"скачан {day}, ещё не установлен"
            elif item["kind"] == "relay":
                state = f"установлен {day}"
            else:
                state = f"выдан {day}"
            if item.get("last_seen"):
                state += ", был в сети " + time.strftime("%d.%m.%Y", time.localtime(item["last_seen"]))
            lines.append(f"\n{i}. {KINDS[item['kind']]} — {state}")
        lines.append("\n\nКаждое подключение работает на одном устройстве. Чтобы получить новое, когда места нет, "
                     "удалите ненужное: на том устройстве оно перестанет работать.")
        buttons = [(f"Удалить {i}", f"ask:{item['kind']}:{item['key']}") for i, item in enumerate(items, 1)]
        self.send_buttons(chat, "".join(lines), [buttons[i:i + 3] for i in range(0, len(buttons), 3)])

    def handle_button(self, query: dict) -> None:
        """A press on a button under a message: data "ask:<kind>:<key>", "rm:<kind>:<key>" or "keep"."""
        try:
            self.api.call("answerCallbackQuery", callback_query_id=query["id"])
        except ApiError:
            pass
        message, sender = query.get("message") or {}, query.get("from") or {}
        chat = (message.get("chat") or {}).get("id")
        if not chat or (message.get("chat") or {}).get("type") != "private" or "id" not in sender:
            return
        name = self.client_for(sender)
        if name is None:
            self.unknown(chat, sender)
            return
        if self.configs is None:
            return
        verb, _, rest = str(query.get("data") or "").partition(":")
        kind, _, key = rest.partition(":")
        if verb == "keep":
            self.send(chat, "Хорошо, ничего не удалено.", self.menu(self.info(name)))
            return
        item = next((i for i in self.configs(name)["items"] if i["kind"] == kind and i["key"] == key), None)
        if item is None:
            self.send(chat, "Этого подключения уже нет.", self.menu(self.info(name)))
            self.list_configs(chat, name)
            return
        if verb == "ask":
            self.send_buttons(chat, f"Удалить {KINDS[kind]} от {time.strftime('%d.%m.%Y', time.localtime(item['since']))}? "
                              "На устройстве с ним доступ пропадёт.",
                              [[("Да, удалить", f"rm:{kind}:{key}"), ("Нет", "keep")]])
        elif verb == "rm":
            if not self.allowed(sender["id"]):
                self.send(chat, "Слишком много запросов. Попробуйте через час.", self.menu(self.info(name)))
                return
            self.remove(name, kind, key)
            self.db.add_event("config_removed_by_client", name, "telegram", f"{kind} {item['id']}")
            self.send(chat, "Удалено. Теперь можно получить новое подключение кнопкой внизу.", self.menu(self.info(name)))
            self.list_configs(chat, name)

    def unknown(self, chat: int, sender: dict) -> None:
        """An account the bot does not know: what to tell the administrator, and a note to the admin chat."""
        if sender.get("username"):
            how = f"Напишите администратору ваше имя в Telegram: @{sender['username']}. Когда он вас добавит, нажмите /start."
        else:
            how = ("Сначала задайте имя пользователя в настройках Telegram (Мой профиль → Имя пользователя), "
                   "отправьте его администратору и нажмите /start.")
        self.send(chat, f"У вас пока нет доступа. {how}\n\nВаш Telegram ID: {sender['id']}")
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
        try:
            link = self.link(name, kind)
        except ConfigLimit:
            self.send(chat, "У вас уже столько подключений (Apple Relay и Xray), сколько разрешено: каждый профиль "
                      "и ключ работает на одном устройстве. Напишите администратору, чтобы он удалил старое.", menu)
            return
        if not link["public"]:
            self.send(chat, "Ссылки пока не работают: администратор не указал адрес сайта.", menu)
            return
        self.send(chat, LINK_STEPS[kind].format(url=link["url"]) + ONCE, menu)
