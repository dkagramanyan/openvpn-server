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

SCRYPT_N, SCRYPT_R, SCRYPT_P = 2**15, 8, 3      # one of the parameter sets OWASP recommends
SCRYPT_MAXMEM = 64 * 1024 * 1024
# A hash takes 32 MB. Anyone can ask for one by posting to the login form, so only two run at a time.
_hashing = threading.BoundedSemaphore(2)


def _scrypt(password: str, salt: bytes, n: int, r: int, p: int, dklen: int) -> bytes:
    with _hashing:
        return hashlib.scrypt(password.encode(), salt=salt, n=n, r=r, p=p, dklen=dklen, maxmem=SCRYPT_MAXMEM)


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = _scrypt(password, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P, 32)
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
        return hmac.compare_digest(_scrypt(password, salt, int(n), int(r), int(p), len(expected)), expected)
    except (ValueError, TypeError):
        return False


def needs_rehash(stored: str) -> bool:
    """True for a hash made with other parameters than today's (replaced at the next login)."""
    return stored.split("$")[1:4] != [str(SCRYPT_N), str(SCRYPT_R), str(SCRYPT_P)]


_DUMMY_HASH = hash_password(secrets.token_urlsafe(16))


def verify_unknown_user(password: str) -> None:
    """Spend the time of a real check, so that a response does not tell whether the user exists."""
    verify_password(password, _DUMMY_HASH)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


# -- sessions -----------------------------------------------------------------
def create_session(db: Database, user_id: int, ttl: int, ip: str | None, user_agent: str | None) -> str:
    token = secrets.token_urlsafe(32)
    now = int(time.time())
    db.execute(
        "INSERT INTO web_sessions (token_hash, user_id, created_at, expires_at, ip, user_agent) VALUES (?, ?, ?, ?, ?, ?)",
        (token_hash(token), user_id, now, now + ttl, ip, (user_agent or "")[:200]),
    )
    return token


def get_session_user(db: Database, token: str | None, ttl: int, extend: bool = True) -> dict | None:
    if not token:
        return None
    now = int(time.time())
    row = db.one(
        """SELECT s.token_hash, s.expires_at, u.id, u.username FROM web_sessions s
           JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?""",
        (token_hash(token),),
    )
    if row is None or row["expires_at"] < now:
        return None
    # Sliding expiry: extend once less than half of the lifetime is left.
    if extend and row["expires_at"] - now < ttl // 2:
        db.execute("UPDATE web_sessions SET expires_at = ? WHERE token_hash = ?", (now + ttl, row["token_hash"]))
    return {"id": row["id"], "username": row["username"]}


def delete_session(db: Database, token: str | None) -> None:
    if token:
        db.execute("DELETE FROM web_sessions WHERE token_hash = ?", (token_hash(token),))


def delete_user_sessions(db: Database, user_id: int, keep_token: str | None = None) -> None:
    if keep_token:
        db.execute("DELETE FROM web_sessions WHERE user_id = ? AND token_hash != ?", (user_id, token_hash(keep_token)))
    else:
        db.execute("DELETE FROM web_sessions WHERE user_id = ?", (user_id,))


# -- login throttling ---------------------------------------------------------
class LoginLimiter:
    """Exponential back-off per key after repeated failed attempts.

    attempt() counts the attempt as failed before it is checked, and success() takes that back:
    requests sent in parallel cannot all pass before the first failure is recorded."""

    def __init__(self, threshold: int = 5, max_delay: int = 300, max_keys: int = 5000, forget: int = 900) -> None:
        self.threshold, self.max_delay, self.max_keys, self.forget = threshold, max_delay, max_keys, forget
        self._lock = threading.Lock()
        self._state: dict[str, tuple[int, float]] = {}   # key -> (failures, blocked until), oldest attempt first

    def attempt(self, limits: str | dict[str, int]) -> int:
        """0 when an attempt may go ahead, else the seconds to wait. <limits> is a key, or several
        keys with a threshold each: an attempt that one of them holds back counts for none."""
        if isinstance(limits, str):
            limits = {limits: self.threshold}
        with self._lock:
            now = time.monotonic()
            wait = max(self._state.get(k, (0, 0.0))[1] - now for k in limits)
            if wait > 0:
                return int(wait) + 1
            for k, limit in limits.items():
                failures, until = self._state.pop(k, (0, 0.0))
                if now - until > self.forget:
                    failures = 0
                failures += 1
                delay = min(self.max_delay, 2 ** (failures - limit + 1)) if failures >= limit else 0
                self._state[k] = (failures, now + delay)
            while len(self._state) > self.max_keys:     # bounded memory: forget the oldest attempts
                del self._state[next(iter(self._state))]
            return 0

    def success(self, key: str) -> None:
        with self._lock:
            self._state.pop(key, None)
