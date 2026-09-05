"""Password hashing (scrypt), cookie sessions and login rate limiting."""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time

from .db import Database

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 1
SCRYPT_MAXMEM = 64 * 1024 * 1024


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=32,
                           maxmem=SCRYPT_MAXMEM)
    return "scrypt${}${}${}${}${}".format(
        SCRYPT_N, SCRYPT_R, SCRYPT_P,
        base64.b64encode(salt).decode(), base64.b64encode(digest).decode(),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if algo != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        digest = hashlib.scrypt(password.encode(), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected),
                                maxmem=SCRYPT_MAXMEM)
        return hmac.compare_digest(digest, expected)
    except (ValueError, TypeError):
        return False


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# -- sessions -----------------------------------------------------------------
def create_session(db: Database, user_id: int, ttl: int, ip: str | None, user_agent: str | None) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    db.execute(
        "INSERT INTO web_sessions (token_hash, user_id, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
        (_token_hash(token), user_id, now, now + ttl, ip, (user_agent or "")[:200]),
    )
    return token


def get_session_user(db: Database, token: str | None, ttl: int) -> dict | None:
    if not token:
        return None
    now = int(time.time())
    row = db.one(
        """SELECT s.token_hash, s.expires_at, u.id, u.username FROM web_sessions s
           JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?""",
        (_token_hash(token),),
    )
    if row is None or row["expires_at"] < now:
        return None
    # Sliding expiry: extend once less than half of the lifetime is left.
    if row["expires_at"] - now < ttl // 2:
        db.execute("UPDATE web_sessions SET expires_at = ? WHERE token_hash = ?", (now + ttl, row["token_hash"]))
    return {"id": row["id"], "username": row["username"]}


def delete_session(db: Database, token: str | None) -> None:
    if token:
        db.execute("DELETE FROM web_sessions WHERE token_hash = ?", (_token_hash(token),))


def delete_user_sessions(db: Database, user_id: int, keep_token: str | None = None) -> None:
    if keep_token:
        db.execute("DELETE FROM web_sessions WHERE user_id = ? AND token_hash != ?", (user_id, _token_hash(keep_token)))
    else:
        db.execute("DELETE FROM web_sessions WHERE user_id = ?", (user_id,))


# -- login throttling ---------------------------------------------------------
class LoginLimiter:
    """Exponential back-off per (client IP, username) after repeated failures."""

    def __init__(self, threshold: int = 5, max_delay: int = 300) -> None:
        self.threshold = threshold
        self.max_delay = max_delay
        self._lock = threading.Lock()
        self._state: dict[str, tuple[int, float]] = {}   # key -> (failures, blocked_until)

    def retry_after(self, key: str) -> int:
        with self._lock:
            failures, until = self._state.get(key, (0, 0.0))
            remaining = until - time.monotonic()
            return int(remaining) + 1 if remaining > 0 else 0

    def record_failure(self, key: str) -> None:
        with self._lock:
            failures, _ = self._state.get(key, (0, 0.0))
            failures += 1
            delay = 0
            if failures >= self.threshold:
                delay = min(self.max_delay, 2 ** (failures - self.threshold + 1))
            self._state[key] = (failures, time.monotonic() + delay)
            if len(self._state) > 5000:   # bounded memory
                self._state.clear()

    def record_success(self, key: str) -> None:
        with self._lock:
            self._state.pop(key, None)
