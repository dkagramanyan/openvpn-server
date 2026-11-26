"""How many configs a client may have: device-bound Apple relay profiles and Xray keys together.

One number per client: the default of Settings → Apple relay ("Configs per client"), or the
client's own (client page). OpenVPN is not counted (OVPN_MAX_DEVICES caps its connections).
A relay profile holds its slot from the download on (until it is installed, expires or is
removed), an Xray key from the moment it is issued.
"""
from __future__ import annotations

import json
import time

from .pki import PkiError

DEFAULT = 2


class ConfigLimit(PkiError):
    """The client has as many configs as allowed."""


def default_limit(db) -> int:
    saved = json.loads(db.get_setting("apple_relay", "{}"))
    value = saved.get("device_limit", DEFAULT)
    return value if isinstance(value, int) and 1 <= value <= 100 else DEFAULT


def override(db, client: str) -> int | None:
    row = db.one("SELECT config_limit FROM clients WHERE name = ?", (client,))
    return row["config_limit"] if row else None


def limit(db, client: str) -> int:
    own = override(db, client)
    return own if own is not None else default_limit(db)


def set_override(db, client: str, value: int | None) -> None:
    db.execute("INSERT INTO clients (name, note, created_at, config_limit) VALUES (?, '', ?, ?) "
               "ON CONFLICT (name) DO UPDATE SET config_limit = excluded.config_limit", (client, int(time.time()), value))


def used(db, client: str, *, installed_only: bool = False, conn=None) -> int:
    """Slots in use. installed_only: without relay profiles that are downloaded but not installed."""
    run = (conn or db._conn()).execute
    waiting = "" if installed_only else " OR (enrolled_at IS NULL AND expires_at >= ?)"
    args = (client,) if installed_only else (client, int(time.time()))
    relay = run("SELECT COUNT(*) AS n FROM relay_devices WHERE client_name = ? AND revoked_at IS NULL AND "
                "(enrolled_at IS NOT NULL" + waiting + ")", args).fetchone()["n"]
    xray = run("SELECT COUNT(*) AS n FROM xray_keys WHERE client_name = ?", (client,)).fetchone()["n"]
    return relay + xray


def check(db, client: str, conn=None) -> None:
    """Raise ConfigLimit when the client has no free slot."""
    allowed = limit(db, client)
    if used(db, client, conn=conn) >= allowed:
        raise ConfigLimit(f"{client} already has {allowed} configs (Apple relay devices and Xray keys): remove one first")
