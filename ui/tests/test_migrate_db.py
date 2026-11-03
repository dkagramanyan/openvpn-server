"""Real legacy file -> PostgreSQL import, rollback and pg_dump recovery."""
import hashlib
import json
from pathlib import Path
import sqlite3
import uuid

import psycopg
from psycopg import sql
import pytest

from app import auth
from app.db import Database as PostgresDatabase, connection_parameters
from app.migrate_db import MARKER, TABLES, dump_postgres, empty_database, import_sqlite, restore_dump
from pg_fixture import Database

LEGACY = (Path(__file__).parent / 'fixtures/legacy.sql').read_text()


def legacy(path):
    with sqlite3.connect(path) as source:
        source.executescript(LEGACY)
        source.execute("INSERT INTO users VALUES(41,?,?,?,?,?,?)", ("operator", auth.hash_password("existing-password"), 100, None, "alice", "ABCD"))
        source.execute("INSERT INTO users VALUES(42,?,?,?,?,?,?)", ("portal", auth.hash_password("portal-password"), 101, 102, "bob", "BCDE"))
        source.execute("INSERT INTO settings VALUES(?,?)", ("relay_client:alice", json.dumps({"serial": "ABCD", "secret": "existing-relay-secret"})))
        source.execute("INSERT INTO settings VALUES(?,?)", ("apple_relay", '{"enabled":true,"url":"https://relay.example.com:8443"}'))
        source.execute("INSERT INTO web_sessions VALUES('web-session',41,100,9000000000,'203.0.113.1','iOS')")
        source.execute("INSERT INTO clients VALUES('alice',?,100)", ("Дом '50%' ?",))
        source.execute("INSERT INTO hidden_certs VALUES('AAAA','old',110)")
        source.execute("INSERT INTO vpn_sessions VALUES(95,'alice',3,'203.0.113.1:1234','10.0.70.2',NULL,'AES-256-GCM',100,120,130,4294967297,8589934593,'udp','ios','3.7','left',95)")
        for table in ('traffic_minute', 'traffic_hour', 'traffic_day'):
            source.execute(f"INSERT INTO {table} VALUES(100,'alice',4294967297,8589934593)")
        source.execute("INSERT INTO events VALUES(74,100,'test','alice','admin','preserved')")
        source.execute("INSERT INTO archived_clients VALUES('old#10','old',10)")
        source.execute("INSERT INTO rejections VALUES(0,'old','revoked','203.0.113.1',3,100)")
        source.execute("INSERT INTO share_tokens VALUES('share-session','alice',100,9000000000,NULL,'admin')")
    return path


def test_import_preserves_every_table_accounts_credentials_history_and_source(tmp_path):
    path = legacy(tmp_path / 'openvpn-ui.db')
    before = hashlib.sha256(path.read_bytes()).digest()
    db = Database()
    result = import_sqlite(path, db)
    assert result['verified'] and set(result['imported']) == set(TABLES)
    with sqlite3.connect(path) as source:
        source.row_factory = sqlite3.Row
        for table in TABLES:
            rows = [dict(row) for row in source.execute(f'SELECT * FROM {table}')]
            assert result['imported'][table] == len(rows)
            actual = db.query(f'SELECT * FROM {table}' + (" WHERE key NOT LIKE 'migration:%'" if table == 'settings' else ''))
            assert sorted(actual, key=str) == sorted(rows, key=str)
    assert auth.verify_password('existing-password', db.one("SELECT password_hash FROM users WHERE id=41")['password_hash'])
    assert auth.verify_password('portal-password', db.one("SELECT password_hash FROM users WHERE id=42")['password_hash'])
    assert json.loads(db.get_setting('relay_client:alice'))['secret'] == 'existing-relay-secret'
    assert import_sqlite(path, db) == {'already_imported': True}
    for table, fields, values in (
        ('users', 'username,password_hash,created_at', ('next', 'hash', 1)),
        ('vpn_sessions', 'client_name,connected_at,last_seen', ('alice', 1, 1)),
        ('events', 'ts,kind', (1, 'next')),
    ):
        row = db.execute(f"INSERT INTO {table}({fields}) VALUES ({','.join('?' for _ in values)}) RETURNING id", values).fetchone()
        assert row['id'] == {'users':43, 'vpn_sessions':96, 'events':75}[table]
    assert hashlib.sha256(path.read_bytes()).digest() == before


def test_refuses_nonempty_target_and_missing_or_corrupt_source(tmp_path):
    path = legacy(tmp_path / 'legacy.db')
    db = Database()
    db.set_setting('existing', 'retain')
    with pytest.raises(ValueError, match='refusing'):
        import_sqlite(path, db)
    assert db.get_setting('existing') == 'retain'
    assert db.one('SELECT 1 FROM users') is None
    missing = tmp_path / 'missing.db'
    with pytest.raises(sqlite3.Error): import_sqlite(missing, Database())
    assert not missing.exists()
    bad = tmp_path / 'bad.db'
    bad.write_bytes(b'not a database')
    with pytest.raises(sqlite3.Error): import_sqlite(bad, Database())


def test_failure_rolls_back_earlier_tables_and_can_retry(tmp_path):
    path = legacy(tmp_path / 'legacy.db')
    # A legacy TEXT column with an invalid integer forces COPY to fail after
    # accounts/settings have already been copied inside the same transaction.
    with sqlite3.connect(path) as source:
        source.execute("UPDATE events SET ts='broken'")
    db = Database()
    with pytest.raises(psycopg.Error): import_sqlite(path, db)
    assert empty_database(db)
    assert db.get_setting(MARKER) is None
    with sqlite3.connect(path) as source: source.execute('UPDATE events SET ts=100')
    assert import_sqlite(path, db)['verified']


def test_readonly_sqlite_wal_is_imported_consistently(tmp_path):
    path = legacy(tmp_path / 'wal.db')
    with sqlite3.connect(path) as source:
        source.execute('PRAGMA journal_mode=WAL')
        source.execute("INSERT INTO settings VALUES('wal-committed','yes')")
        source.commit()
        assert Path(str(path) + '-wal').stat().st_size > 0
        db = Database()
        assert import_sqlite(path, db)['verified']
        assert db.get_setting('wal-committed') == 'yes'


def test_postgres_dump_can_restore_to_empty_database_and_preserves_data(tmp_path):
    db = Database()
    import_sqlite(legacy(tmp_path / 'legacy.db'), db)
    dump = tmp_path / 'snapshot.pgdump'
    dump_postgres(dump, db.dsn, db.schema)
    assert dump.stat().st_mode & 0o777 == 0o600
    # pg_dump records the schema name: use another database with the same schema.
    params = connection_parameters(db.dsn)
    name = 'restore_' + uuid.uuid4().hex
    with psycopg.connect(**params, autocommit=True) as admin:
        admin.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(name)))
    target = None
    try:
        target = PostgresDatabase(psycopg.conninfo.make_conninfo(**{**params, 'dbname': name}), schema=db.schema)
        assert restore_dump(dump, target) == {'restored': True}
        for table in TABLES:
            clause = " WHERE key != 'migration:postgres_dump'" if table == 'settings' else ''
            assert sorted(target.query(f'SELECT * FROM {table}' + clause), key=str) == sorted(db.query(f'SELECT * FROM {table}'), key=str)
        assert restore_dump(dump, target) == {'already_imported': True}
    finally:
        if target: target._conn().close()
        with psycopg.connect(**params, autocommit=True) as admin:
            admin.execute(sql.SQL('DROP DATABASE {} WITH (FORCE)').format(sql.Identifier(name)))
