"""Backup archives: everything needed to rebuild the server on another machine."""
from __future__ import annotations

import os
import re
import shutil
import sqlite3
import subprocess
import tarfile
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from . import pki
from .settings import settings

# Relative to the OpenVPN directory. The database goes in as a snapshot, see create().
ITEMS = ("server.conf", "config", "pki", "clients", "staticclients", "guests", "fw-rules.sh",
         "docker-compose.yml", ".env")
PREFIX, SUFFIX = "openvpn-backup-", ".tar.gz"
MAX_AGE = 86400
RECIPIENT_RE = re.compile(r"age1[a-z0-9]{58}")


def archives() -> list[Path]:
    return sorted(settings.backup_dir.glob(f"{PREFIX}*{SUFFIX}*"))     # also the encrypted .tar.gz.age


def status() -> dict[str, Any]:
    found = archives()
    last = found[-1].stat() if found else None
    return {"enabled": settings.backup_keep > 0, "dir": str(settings.backup_dir), "count": len(found),
            "keep": settings.backup_keep, "last": int(last.st_mtime) if last else None,
            "size": last.st_size if last else None, "encrypted": bool(settings.backup_recipient)}


def _write_archive(fh, snapshot: Path) -> None:
    with tarfile.open(fileobj=fh, mode="w|gz") as tar:
        for item in ITEMS:
            path = settings.openvpn_dir / item
            if path.exists():
                tar.add(path, arcname=item)
        if snapshot.exists():
            tar.add(snapshot, arcname="db/openvpn-ui.db")


def create() -> Path:
    """Write a new archive and drop the oldest ones beyond the number to keep. The archive holds
    the CA key: it is readable by its owner only and, with OVPN_BACKUP_RECIPIENT set, encrypted."""
    recipient = settings.backup_recipient
    if recipient and not RECIPIENT_RE.fullmatch(recipient):
        # Never fall back to an unencrypted archive when encryption was asked for.
        raise ValueError("OVPN_BACKUP_RECIPIENT is not an age public key (age1...)")
    dest = settings.backup_dir
    dest.mkdir(parents=True, exist_ok=True)
    try:
        dest.chmod(0o700)
    except OSError:         # a network share that does not take permissions
        pass
    target = dest / f"{PREFIX}{time.strftime('%Y%m%d-%H%M%S')}{SUFFIX}{'.age' if recipient else ''}"
    partial = dest / f".partial-{os.getpid()}-{threading.get_ident()}"
    with tempfile.TemporaryDirectory() as tmp:
        snapshot, built = Path(tmp) / "db", Path(tmp) / "archive"
        # The lock keeps the PKI still while it is read. The archive is built in the temporary
        # directory (memory, in the container), so a slow or hanging backup directory - it may be
        # a network share - is written without the lock and cannot hold up a revocation.
        with pki.lock:
            if settings.db_path.exists():
                # The backup API copies a consistent database while the collector keeps writing;
                # a plain file copy of a database in WAL mode can come out torn or stale.
                src, dst = sqlite3.connect(str(settings.db_path), timeout=30), sqlite3.connect(str(snapshot))
                try:
                    src.backup(dst)
                finally:
                    src.close()
                    dst.close()
            with open(built, "wb") as fh:
                if recipient:
                    age = subprocess.Popen(["age", "-r", recipient], stdin=subprocess.PIPE, stdout=fh,
                                           stderr=subprocess.PIPE)
                    try:
                        _write_archive(age.stdin, snapshot)
                    except BrokenPipeError:     # age gave up; its message follows
                        pass
                    except BaseException:
                        age.kill()
                        age.communicate()
                        raise
                    _, err = age.communicate()
                    if age.returncode:
                        raise OSError(f"age failed: {err.decode(errors='replace').strip()}")
                else:
                    _write_archive(fh, snapshot)
        try:
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "wb") as out, open(built, "rb") as src:
                shutil.copyfileobj(src, out)
                out.flush()
                os.fsync(out.fileno())      # complete on disk before it gets its final name
            partial.replace(target)
        finally:
            partial.unlink(missing_ok=True)
    if settings.backup_keep > 0:
        for old in archives()[:-settings.backup_keep]:
            old.unlink()
    return target


def ensure_recent() -> Path | None:
    """The maintenance task: one archive a day."""
    st = status()
    if st["enabled"] and (st["last"] is None or time.time() - st["last"] >= MAX_AGE):
        return create()
    return None


if __name__ == "__main__":      # docker exec openvpn-ui python -m app.backup
    print(create())
