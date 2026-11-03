"""Isolated PostgreSQL schemas for tests; never use the operator's runtime database."""
import hashlib
import os
from pathlib import Path
import uuid

from app.db import Database as PostgresDatabase


def Database(path=None):
    dsn = os.environ["OVPN_TEST_DATABASE_URL"]
    schema = "test_" + (hashlib.sha256(str(path).encode()).hexdigest()[:24] if path else uuid.uuid4().hex)
    db = PostgresDatabase(dsn, schema=schema)
    if path and Path(path).is_file():
        from app.migrate_db import import_sqlite
        import_sqlite(Path(path), db)
    return db
