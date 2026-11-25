"""Xray through 3x-ui (the xui service): one 3x-ui client per OpenVPN client on the inbound chosen
in Settings → Xray. Its email is the client name and its comment MARK, so clients made in the
3x-ui panel by hand are never touched. Xray gives internet access only: a routing rule of ours
sends private ranges and the networks of this host to "blocked", for guests and everyone else.

bin/xui-start.sh writes the panel's base path and an API token to xui/openvpn-ui.json.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import socket
import struct
import urllib.error
import urllib.parse
import urllib.request

from . import network, pki, relay
from .pki import PkiError
from .settings import settings

log = logging.getLogger("openvpn-ui.xray")

MARK = "openvpn-ui"                 # comment of the 3x-ui clients this UI manages
RULE_TAG = "openvpn-ui-no-lan"      # ruleTag of our routing rule in the Xray template
# Settings of a 3x-ui client an update sends back unchanged (someone may have set them in the panel).
KEPT = ("subId", "limitIp", "limitHwid", "totalGB", "tgId", "group", "reset", "resetDay", "resetWeekday",
        "resetMax", "trafficReset", "trafficResetDay")
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))   # the panel is local: never a proxy


def get_settings(db) -> dict:
    saved = json.loads(db.get_setting("xray", "{}"))
    return {"enabled": bool(saved.get("enabled")), "inbound_id": saved.get("inbound_id")}


def save_settings(db, enabled: bool, inbound_id: int | None) -> dict:
    if enabled:
        if inbound_id is None:
            raise PkiError("Choose the inbound clients get")
        inbound(inbound_id)         # it exists, and the panel answers
    db.set_setting("xray", json.dumps({"enabled": enabled, "inbound_id": inbound_id}))
    return get_settings(db)


def enabled(db) -> bool:
    return get_settings(db)["enabled"]


# -- the 3x-ui API ------------------------------------------------------------------
def _state() -> dict:
    try:
        state = json.loads((settings.openvpn_dir / "xui" / "openvpn-ui.json").read_text())
    except (OSError, ValueError):
        raise PkiError("3x-ui has not started yet (no xui/openvpn-ui.json): docker compose up -d xui")
    return state


def panel(gateway: dict) -> dict | None:
    """{"path", "backend", "url"} of the 3x-ui panel for the gateway, which routes its base path on
    the OpenVPN hostname to this server (trusted networks only), or None before 3x-ui has started."""
    try:
        base = _state()["base_path"]
    except PkiError:
        return None
    host = urllib.parse.urlsplit(gateway.get("openvpn_backend") or "").hostname
    if not host:
        return None
    return {"path": base, "backend": f"http://{host}:{settings.xui_port}",
            "url": f"https://{gateway['openvpn_host']}{base}" if gateway.get("openvpn_host") else None}


def call(method: str, path: str, body: dict | None = None, form: dict | None = None, host: str | None = None):
    """The "obj" of a 3x-ui API answer. host: the Host header, which 3x-ui writes into share links."""
    state = _state()
    url = f"http://127.0.0.1:{settings.xui_port}{state['base_path'].rstrip('/')}/{path.lstrip('/')}"
    headers = {"Authorization": "Bearer " + state["token"], "Accept": "application/json"}
    data = None
    if body is not None:
        data, headers["Content-Type"] = json.dumps(body).encode(), "application/json"
    elif form is not None:
        data, headers["Content-Type"] = urllib.parse.urlencode(form).encode(), "application/x-www-form-urlencoded"
    if host:
        headers["Host"] = host
    request = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with _opener.open(request, timeout=15) as response:
            answer = json.load(response)
    except urllib.error.HTTPError as exc:
        raise PkiError(f"3x-ui answered HTTP {exc.code} for {path}") from None
    except (urllib.error.URLError, OSError, ValueError) as exc:
        raise PkiError(f"3x-ui is not reachable: {getattr(exc, 'reason', exc)}") from None
    if not answer.get("success"):
        raise PkiError(f"3x-ui: {answer.get('msg') or 'request refused'}")
    return answer.get("obj")


def inbounds() -> list[dict]:
    return [{key: row.get(key) for key in ("id", "remark", "port", "protocol", "tag", "security", "network", "enable", "tlsFlowCapable")}
            for row in call("GET", "panel/api/inbounds/options") or []]


def inbound(inbound_id: int) -> dict:
    for row in inbounds():
        if row["id"] == inbound_id:
            return row
    raise PkiError(f"3x-ui has no inbound {inbound_id}")


def managed_clients() -> dict[str, dict]:
    """{email: client} of the 3x-ui clients this UI made."""
    rows = call("GET", "panel/api/clients/list") or []
    out = {}
    for row in rows:
        client = row.get("client", row)
        if client.get("comment") == MARK:
            out[client["email"]] = {**client, "inboundIds": row.get("inboundIds", client.get("inboundIds", []))}
    return out


# -- clients ------------------------------------------------------------------------
def _fields(name: str, expiry_ms: int, target: dict) -> dict:
    """What this UI decides about a client. Everything else stays as 3x-ui has it."""
    return {"email": name, "enable": True, "expiryTime": expiry_ms, "comment": MARK,
            "flow": "xtls-rprx-vision" if target.get("tlsFlowCapable") else ""}


def _update(name: str, expiry_ms: int, target: dict) -> None:
    # 3x-ui 3.11 clears omitted fields on update (comment, flow), so the stored settings go back
    # with it. Not the ids: the stored "id" is a row number, while "id" on writes is the credential,
    # which is kept when omitted. Not the protocol-specific fields, stored in other shapes than
    # they are written (allowedIPs).
    stored = call("GET", f"panel/api/clients/get/{urllib.parse.quote(name)}")["client"]
    body = {k: stored[k] for k in KEPT if k in stored}
    call("POST", f"panel/api/clients/update/{urllib.parse.quote(name)}", body={**body, **_fields(name, expiry_ms, target)})


def ensure_client(db, name: str) -> None:
    """The client's 3x-ui client exists, is on our inbound and ends with its certificate."""
    config = get_settings(db)
    if not config["enabled"]:
        raise PkiError("Xray is off (Settings → Xray)")
    cert = relay.eligible(name)
    if not cert:
        raise PkiError("Xray access requires a valid client certificate")
    expiry = int(cert["not_after"]) * 1000
    target = inbound(config["inbound_id"])
    existing = managed_clients().get(name)
    if existing is None:
        client = {**_fields(name, expiry, target), "limitIp": 0, "totalGB": 0}
        call("POST", "panel/api/clients/add", body={"client": client, "inboundIds": [config["inbound_id"]]})
        return
    if config["inbound_id"] not in existing["inboundIds"]:
        call("POST", f"panel/api/clients/{urllib.parse.quote(name)}/attach", body={"inboundIds": [config["inbound_id"]]})
    if existing.get("expiryTime") != expiry or not existing.get("enable"):
        _update(name, expiry, target)


def link(db, name: str) -> str:
    """The client's share link (vless://… etc.) for our inbound, with the public host in it."""
    ensure_client(db, name)
    host = pki.get_remote()["host"] or settings.public_host
    if not host:
        raise PkiError("Set the public host of profiles in Settings first")
    target = inbound(get_settings(db)["inbound_id"])
    links = call("GET", f"panel/api/clients/links/{urllib.parse.quote(name)}", host=host) or []
    port = f":{target['port']}"
    mine = [l for l in links if l.startswith(f"{target['protocol']}://") and port in l] or links
    if not mine:
        raise PkiError("3x-ui gave no link for this client (does the inbound have a protocol with links?)")
    return mine[0]


def forget(db, name: str) -> None:
    """Remove the client's 3x-ui client (revocation, deletion, a reused name). Best effort: the
    hourly check removes what is left."""
    if not enabled(db):
        return
    try:
        if name in managed_clients():
            call("POST", f"panel/api/clients/del/{urllib.parse.quote(name)}")
    except PkiError as exc:
        log.warning("xray: could not remove %s now (%s); the next check removes it", name, exc)


# -- the routing rule and the periodic check ------------------------------------------
def host_networks() -> list[str]:
    """The networks this host reaches directly (LAN, Docker bridges, the VPN subnet), from /proc/net/route."""
    nets = set()
    try:
        lines = open("/proc/net/route").read().splitlines()[1:]
    except OSError:
        return []
    for line in lines:
        fields = line.split()
        if len(fields) < 8 or fields[2] != "00000000" or fields[1] == "00000000":
            continue
        dest = socket.inet_ntoa(struct.pack("<L", int(fields[1], 16)))
        mask = socket.inet_ntoa(struct.pack("<L", int(fields[7], 16)))
        nets.add(str(ipaddress.ip_network(f"{dest}/{mask}", strict=False)))
    return sorted(nets)


def blocked_networks() -> list[str]:
    return ["geoip:private"] + sorted(set(host_networks()) | set(network.pushed_routes()))


def ensure_rule(inbound_tag: str) -> bool:
    """Our rule ahead of every other rule of the Xray template: True when it had to be changed
    (Xray restarted)."""
    answer = call("POST", "panel/api/xray/")
    answer = json.loads(answer) if isinstance(answer, str) else answer      # 3x-ui 3.11 sends it JSON-encoded
    template = answer["xraySetting"]
    template = json.loads(template) if isinstance(template, str) else template
    rule = {"type": "field", "ruleTag": RULE_TAG, "inboundTag": [inbound_tag], "ip": blocked_networks(), "outboundTag": "blocked"}
    routing = template.setdefault("routing", {})
    rules = routing.setdefault("rules", [])
    outbounds = template.setdefault("outbounds", [])
    has_blocked = any(o.get("tag") == "blocked" for o in outbounds)
    # 3x-ui keeps its own "api" rule (its internal API inbound) first; ours comes right after it.
    others = [r for r in rules if r.get("ruleTag") != RULE_TAG]
    api = [r for r in others if r.get("inboundTag") == ["api"]]
    wanted = api + [rule] + [r for r in others if r not in api]
    if rules == wanted and has_blocked:
        return False
    routing["rules"] = wanted
    if not has_blocked:
        outbounds.append({"protocol": "blackhole", "tag": "blocked"})
    call("POST", "panel/api/xray/update", form={"xraySetting": json.dumps(template, indent=2)})
    call("POST", "panel/api/server/restartXrayService")
    log.info("xray: routing rule %s updated (%d networks)", RULE_TAG, len(rule["ip"]))
    return True


def reconcile(db) -> None:
    """Every hour and after settings change: the rule is in place, and clients whose certificate
    ended lose their Xray access; renewed ones get the new end date."""
    config = get_settings(db)
    if not config["enabled"]:
        return
    try:
        target = inbound(config["inbound_id"])
        ensure_rule(target["tag"])
        for name, client in managed_clients().items():
            cert = relay.eligible(name) if pki.NAME_RE.match(name) else None
            if not cert:
                call("POST", f"panel/api/clients/del/{urllib.parse.quote(name)}")
                log.info("xray: removed %s (certificate no longer valid)", name)
            elif client.get("expiryTime") != int(cert["not_after"]) * 1000:
                _update(name, int(cert["not_after"]) * 1000, target)
    except PkiError as exc:
        log.warning("xray: check skipped: %s", exc)
