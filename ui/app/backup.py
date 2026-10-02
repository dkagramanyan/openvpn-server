"""Backup archives: everything needed to rebuild the server on another machine."""
from __future__ import annotations

import os
import sqlite3
import tarfile
import time
from pathlib import Path
from typing import Any

from .settings import settings

# Relative to the OpenVPN directory. The database goes in as a snapshot, see create().
ITEMS = ("server.conf", "config", "pki", "clients", "staticclients", "guests", "fw-rules.sh",
         "docker-compose.yml", ".env")
PREFIX, SUFFIX = "openvpn-backup-", ".tar.gz"
MAX_AGE = 86400


def archives() -> list[Path]:
    return sorted(settings.backup_dir.glob(f"{PREFIX}*{SUFFIX}"))


def status() -> dict[str, Any]:
    found = archives()
    last = found[-1].stat() if found else None
    return {"enabled": settings.backup_keep > 0, "dir": str(settings.backup_dir), "count": len(found),
            "keep": settings.backup_keep, "last": int(last.st_mtime) if last else None,
            "size": last.st_size if last else None}


def create() -> Path:
    """Write a new archive and drop the oldest ones beyond the number to keep. The archive holds
    the CA key, so it is readable by its owner only."""
    dest = settings.backup_dir
    dest.mkdir(parents=True, exist_ok=True)
    dest.chmod(0o700)
    target = dest / f"{PREFIX}{time.strftime('%Y%m%d-%H%M%S')}{SUFFIX}"
    snapshot, partial = dest / ".db-snapshot", dest / ".partial"
    try:
        if settings.db_path.exists():
            # The backup API copies a consistent database while the collector keeps writing;
            # a plain file copy of a database in WAL mode can come out torn or stale.
            snapshot.unlink(missing_ok=True)
            src, dst = sqlite3.connect(str(settings.db_path), timeout=30), sqlite3.connect(str(snapshot))
            try:
                src.backup(dst)
            finally:
                src.close()
                dst.close()
        fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh, tarfile.open(fileobj=fh, mode="w:gz") as tar:
            for item in ITEMS:
                path = settings.openvpn_dir / item
                if path.exists():
                    tar.add(path, arcname=item)
            if snapshot.exists():
                tar.add(snapshot, arcname="db/openvpn-ui.db")
        partial.replace(target)
    finally:
        snapshot.unlink(missing_ok=True)
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
