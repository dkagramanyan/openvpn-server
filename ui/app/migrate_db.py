"""One-time legacy SQLite import and PostgreSQL dump restoration."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import sqlite3  # Legacy import only; never used for runtime storage.

import psycopg
from psycopg import sql

from .db import Database, SCHEMA, connection_parameters
from .settings import settings

TABLES = tuple(re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", SCHEMA))
MARKER = "migration:legacy_sqlite"


def client_environment(dsn=""):
    env = os.environ.copy()
    params = connection_parameters(dsn)
    for name in ("host", "hostaddr", "port", "dbname", "user", "password", "sslmode", "sslcert", "sslkey", "sslrootcert", "sslcrl", "connect_timeout", "passfile"):
        if name in params:
            env["PG" + ("DATABASE" if name == "dbname" else name.upper())] = str(params[name])
    return env


def dump_postgres(path: Path | None, dsn=None, schema=None):
    args = ["pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--schema", schema or settings.database_schema]
    if path: args += ["--file", str(path)]
    subprocess.run(args, env=client_environment(settings.database_url if dsn is None else dsn),
                   check=True, stderr=subprocess.PIPE)
    if path: path.chmod(0o600)



def empty_database(db):
    return not any(db.one(f"SELECT 1 FROM {table} LIMIT 1") for table in TABLES)


def import_sqlite(path: Path, db: Database):
    """Legacy file is opened read-only, in a consistent source transaction."""
    from urllib.parse import quote
    if db.get_setting(MARKER) is not None:
        return {"already_imported": True}
    if not empty_database(db):
        raise ValueError("PostgreSQL already contains application data; refusing to merge or overwrite it")
    source = sqlite3.connect("file:" + quote(str(path.resolve()), safe="/") + "?mode=ro", uri=True, timeout=30)
    counts = {}
    try:
        source.execute("BEGIN")
        if source.execute("PRAGMA quick_check").fetchone()[0] != "ok":
            raise ValueError("Legacy database integrity check failed")
        have = {row[0] for row in source.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "vpn_sessions" not in have:
            raise ValueError("Source is not a recognized OpenVPN UI database")
        with db.tx() as conn:
            conn.raw.execute("SELECT pg_advisory_xact_lock(hashtext('openvpn-legacy-import'))")
            if db.get_setting(MARKER) is not None:
                return {"already_imported": True}
            if not empty_database(db):
                raise ValueError("PostgreSQL was populated during import; refusing to merge")
            for table in TABLES:
                if table not in have: continue
                available = {row["column_name"] for row in conn.raw.execute(
                    "SELECT column_name FROM information_schema.columns WHERE table_schema=%s AND table_name=%s",
                    (db.schema, table))}
                columns = [row[1] for row in source.execute(f'PRAGMA table_info("{table}")') if row[1] in available]
                selected = ",".join('"' + c.replace('"', '""') + '"' for c in columns)
                query = sql.SQL("COPY {} ({}) FROM STDIN").format(sql.Identifier(table), sql.SQL(",").join(map(sql.Identifier, columns)))
                count = 0
                with conn.raw.cursor().copy(query) as writer:
                    for row in source.execute(f'SELECT {selected} FROM "{table}"'):
                        writer.write_row(row)
                        count += 1
                actual = conn.execute(f"SELECT COUNT(*) AS n FROM {table}").fetchone()["n"]
                if actual != count: raise ValueError("Imported row count does not match the source")
                counts[table] = count
            for table in ("users", "vpn_sessions", "events"):
                qualified = '"' + db.schema.replace('"', '""') + '"."' + table + '"'
                conn.raw.execute(sql.SQL("SELECT setval(pg_get_serial_sequence(%s,'id'),COALESCE(MAX(id),1),MAX(id) IS NOT NULL) FROM {}").format(sql.Identifier(table)), (qualified,))
            conn.execute("INSERT INTO settings(key,value) VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                         (MARKER, json.dumps({"tables": counts, "verified": True})))
    finally:
        source.close()
    return {"imported": counts, "verified": True}


def restore_dump(path: Path, db: Database):
    if not empty_database(db):
        if db.get_setting("migration:postgres_dump") is not None:
            return {"already_imported": True}
        raise ValueError("PostgreSQL contains application data; restore requires an empty target")
    # Schema is initialized by Database. Restore data and sequence values only.
    subprocess.run(["pg_restore", "--data-only", "--no-owner", "--no-privileges", "--exit-on-error", "--single-transaction",
                    "--dbname", connection_parameters(db.dsn).get("dbname", "openvpn"), str(path)],
                   env=client_environment(db.dsn), check=True, capture_output=True)
    db.set_setting("migration:postgres_dump", "1")
    return {"restored": True}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("import", "dump"), default="import", nargs="?")
    parser.add_argument("--source", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--stdout", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "dump":
            if not args.output and not args.stdout: parser.error("dump requires --output or --stdout")
            dump_postgres(args.output)
            if not args.stdout: print("PostgreSQL snapshot created")
            return
        db = Database(settings.database_url, schema=settings.database_schema)
        source = args.source or settings.db_path
        dump = settings.openvpn_dir / "db/openvpn-ui.pgdump"
        if args.source:
            result = import_sqlite(source, db)
        elif dump.exists():
            result = restore_dump(dump, db)
        elif source.exists():
            result = import_sqlite(source, db)
        else:
            result = {"fresh_install": True}
        print(json.dumps(result))  # Counts only, never account data or credentials.
    except (OSError, ValueError, sqlite3.Error, psycopg.Error, subprocess.SubprocessError):
        parser.exit(1, "Database migration failed; original state was retained. Check target readiness and use an empty application database.\n")


if __name__ == "__main__":
    main()
