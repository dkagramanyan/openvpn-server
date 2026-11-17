"""Relay traffic, connection log and periods next to the OpenVPN statistics."""
import datetime

import pytest
from fastapi import HTTPException

from pg_fixture import Database
from app import relay_history, relay_services
from app.db import RELAY_FLOW_RETENTION, SCHEMA


def status(identifier='boot:1', last=1010, up=100, down=200, **changes):
    row = dict(id=identifier, client='alice', credential_id='one', transport='http2', started_at=1000,
               last_seen=last, active=1, accepted=3, denied=0, failed=0, bytes_up=up, bytes_down=down, uncounted_flows=0)
    row.update(changes)
    return dict(ready=True, instance=identifier.split(':')[0], sessions=[row])


def traffic(db, source='relay', client='alice'):
    return db.totals(0, 10**10, client, source)


def test_old_traffic_tables_get_a_source_and_keep_their_rows():
    db = Database()
    with db.tx() as conn:
        for table in ('traffic_minute', 'traffic_hour', 'traffic_day'):
            # The table as releases up to 2.2 created it.
            conn.execute(f'DROP TABLE {table}')
            conn.execute(f'''CREATE TABLE {table} (ts BIGINT NOT NULL, client_name TEXT NOT NULL,
                bytes_in BIGINT NOT NULL DEFAULT 0, bytes_out BIGINT NOT NULL DEFAULT 0, PRIMARY KEY (ts, client_name))''')
            conn.execute(f"INSERT INTO {table} (ts, client_name, bytes_in, bytes_out) VALUES (600, 'alice', 5, 7)")
    for _ in range(2):      # the second start changes nothing
        again = type(db)(db.dsn, schema=db.schema)
        for table in ('traffic_minute', 'traffic_hour', 'traffic_day'):
            assert again.query(f'SELECT ts, client_name, source, bytes_in, bytes_out FROM {table}') == [
                dict(ts=600, client_name='alice', source='vpn', bytes_in=5, bytes_out=7)]
    with again.tx() as conn:
        again.add_traffic(conn, 600, 'alice', 1, 2, source='relay')
        again.add_traffic(conn, 600, 'alice', 1, 2, source='relay')
        again.add_traffic(conn, 600, 'alice', 10, 20)
    assert traffic(again) == (2, 4) and traffic(again, 'vpn') == (5 + 5 + 5 + 10, 7 + 7 + 7 + 20)
    assert again.totals_by_client(0, 10**10)['alice'] == (27, 45)
    assert 'source' in SCHEMA


def test_relay_traffic_is_counted_once_across_polls_ui_and_relay_restarts():
    db = Database()
    relay_history.record(db, status(), now=1010)
    relay_history.record(db, status(), now=1011)                       # the same snapshot again
    assert traffic(db) == (100, 200)                                    # up = bytes_in, down = bytes_out
    relay_history.record(db, status(last=1020, up=140, down=280), now=1020)
    assert traffic(db) == (140, 280)
    # UI restart: the collector has forgotten what it saw and reads every row again.
    relay_history.record(db, status(last=1020, up=140, down=280), now=1080)
    assert traffic(db) == (140, 280)
    # Relay restart: a new process counts from zero under new ids.
    relay_history.record(db, status('reboot:1', last=1100, up=30, down=40), now=1100)
    relay_history.record(db, status('reboot:1', last=1130, up=50, down=60), now=1130)
    assert traffic(db) == (190, 340)
    assert traffic(db, 'vpn') == (0, 0)
    # The minutes it was booked in.
    rows = db.query("SELECT ts, bytes_in FROM traffic_minute WHERE source = 'relay' ORDER BY ts")
    assert [(r['ts'], r['bytes_in']) for r in rows] == [(960, 100), (1020, 40), (1080, 50)]
    # A counter that went back (never expected) is not booked as negative traffic.
    relay_history.record(db, status('reboot:1', last=1140, up=10, down=10), now=1140)
    assert traffic(db) == (190, 340)


def test_rollup_keeps_sources_apart_and_archive_moves_relay_history():
    db = Database()
    now = 10 * 86400
    with db.tx() as conn:
        db.add_traffic(conn, 60, 'alice', 1, 2)
        db.add_traffic(conn, 120, 'alice', 10, 20, source='relay')
    relay_history.record(db, status(active=0), now=1010)
    relay_history.record_flows(db, 'boot', [event(1)], now=now)
    db.rollup(now)
    assert db.query('SELECT * FROM traffic_minute WHERE ts < 3600') == []
    assert traffic(db, 'vpn') == (1, 2) and traffic(db) == (110, 220)
    key = db.archive_client_history('alice')
    assert traffic(db) == (0, 0) and traffic(db, client=key) == (110, 220)
    assert relay_history.flows(db, 'alice')[0] == 0 and relay_history.flows(db, key)[0] == 1
    db.purge_client(key)
    assert relay_history.flows(db, key)[0] == 0 and traffic(db, client=key) == (0, 0)


def event(identifier, kind='closed', client='alice', ts=None, **changes):
    row = dict(id=identifier, seq=identifier * 2, session_id='boot:1', ts=ts, kind=kind, client=client, guest=False,
               protocol='TCP', transport='http2', target=f'site{identifier}.example:443', reason='connection_closed',
               status=200, duration_ms=1500, bytes_up=10, bytes_down=20, bytes_counted=True)
    row.update(changes)
    return row


def test_relay_flows_are_saved_once_and_pruned_after_seven_days():
    db = Database()
    now = 30 * 86400
    events = [event(1, ts=now - 10), event(2, 'connected', ts=now - 9), event(3, 'denied', ts=now - 8, reason='destination_denied'),
              event(4, 'failed', client='', ts=now - 7), event(5, ts=now - RELAY_FLOW_RETENTION - 5)]
    assert relay_history.record_flows(db, 'boot', events, now=now) == 2      # open, anonymous and too old ones are not kept
    assert relay_history.record_flows(db, 'boot', events, now=now) == 0
    assert relay_history.record_flows(db, 'reboot', [event(1, ts=now - 5)], now=now) == 1    # ids restart with the process
    total, rows = relay_history.flows(db, 'alice')
    assert total == 3 and [r['id'] for r in rows] == [1, 3, 1]
    assert rows[1]['kind'] == 'denied' and rows[1]['target'] == 'site3.example:443'
    assert relay_history.flows(db, 'alice', q='SITE3')[0] == 1
    assert relay_history.flows(db, 'alice', q='%')[0] == 0                  # a filter is text, not a pattern
    assert relay_history.flows(db, 'alice', limit=1, offset=2)[1][0]['instance'] == 'boot'
    assert relay_history.flows(db, 'bob')[0] == 0
    assert RELAY_FLOW_RETENTION == 7 * 86400
    db.rollup(now + RELAY_FLOW_RETENTION - 6)
    assert relay_history.flows(db, 'alice')[0] == 1
    db.rollup(now + RELAY_FLOW_RETENTION)
    assert relay_history.flows(db, 'alice')[0] == 0


def test_collector_reads_events_by_sequence_and_starts_again_with_a_new_relay(monkeypatch):
    db = Database()
    calls, live = [], []
    answers = []

    def runtime_status(client=None, since=None):
        calls.append(since)
        return answers.pop(0)

    monkeypatch.setattr(relay_services, 'runtime_status', runtime_status)
    collector = relay_history.RelayCollector(db, lambda clients, ready: live.append((clients, ready)))
    import time
    now = int(time.time())
    base = dict(ready=True, transport='http2+http3', sessions=[], active=[])
    answers.append({**base, 'instance': 'boot', 'events': [event(1, ts=now), event(7, 'connected', ts=now)],
                    'clients': [dict(client='alice', guest=False, active=2, tcp=1, udp=1, destinations=2, bytes_up=100, bytes_down=1000)]})
    collector.poll(now=100.0)
    # Flow 2 was opened before flow 7 and ends after it: ids are not in the order of events.
    answers.append({**base, 'instance': 'boot', 'events': [event(2, ts=now, seq=15, transport='http3')],
                    'clients': [dict(client='alice', guest=False, active=1, tcp=1, udp=0, destinations=1, bytes_up=600, bytes_down=6000)]})
    collector.poll(now=105.0)
    assert calls == [0, 14]
    assert [(r['id'], r['transport']) for r in relay_history.flows(db, 'alice')[1]] == [(2, 'http3'), (1, 'http2')]
    assert live[0][0][0]['active'] == 2 and live[0][0][0]['rate_down'] == 0 and live[0][1] is True
    assert live[1][0][0]['rate_up'] == 100 and live[1][0][0]['rate_down'] == 1000
    # A new relay process: the answer to "since 15" is not trusted, its log is read from the start.
    answers.append({**base, 'instance': 'reboot', 'events': [], 'clients': []})
    answers.append({**base, 'instance': 'reboot', 'events': [event(1, ts=now, seq=1)], 'clients': []})
    collector.poll(now=110.0)
    assert calls == [0, 14, 15, 0] and relay_history.flows(db, 'alice')[0] == 3 and live[-1] == ([], True)
    answers.append(dict(ready=False))
    collector.poll(now=115.0)
    assert live[-1] == ([], False)
    # An older relay: no "seq", the last events come every time and are stored once.
    old = event(9, ts=now)
    del old['seq']
    answers.extend([{**base, 'instance': 'reboot', 'events': [old], 'clients': []}] * 2)
    collector.poll(now=120.0)
    collector.poll(now=125.0)
    assert calls[-2:] == [1, 1] and relay_history.flows(db, 'alice')[0] == 4


def test_upgrade_books_the_traffic_of_earlier_relay_sessions_once():
    db = Database()
    relay_history.record(db, status(active=0), now=1010)
    db.execute('DELETE FROM traffic_minute')              # as a 2.2 database: sessions without traffic rows
    assert relay_history.backfill_traffic(db) == 1 and relay_history.backfill_traffic(db) == 0
    assert traffic(db) == (100, 200)


UTC3 = 3 * 3600


def at(*parts, tz=0):
    return int(datetime.datetime(*parts, tzinfo=datetime.timezone.utc).timestamp()) - tz


@pytest.mark.parametrize('name, now, tz, start, end', [
    # 17 Nov 2026 is a Tuesday. 22:30 UTC is already the 18th in UTC+3.
    ('today', at(2026, 11, 17, 22, 30), 0, at(2026, 11, 17), None),
    ('today', at(2026, 11, 17, 22, 30), UTC3, at(2026, 11, 18, tz=UTC3), None),
    ('today', at(2026, 11, 17, 2, 0), -5 * 3600, at(2026, 11, 16, tz=-5 * 3600), None),
    ('yesterday', at(2026, 11, 17, 22, 30), UTC3, at(2026, 11, 17, tz=UTC3), at(2026, 11, 18, tz=UTC3)),
    ('week', at(2026, 11, 17, 12), UTC3, at(2026, 11, 16, tz=UTC3), None),
    ('week', at(2026, 11, 16, 0, 0), 0, at(2026, 11, 16), None),                # Monday 00:00 starts the week
    ('week', at(2026, 11, 15, 22, 0), UTC3, at(2026, 11, 16, tz=UTC3), None),   # Sunday evening UTC = Monday in UTC+3
    ('week', at(2027, 1, 1, 12), 0, at(2026, 12, 28), None),                    # a week across the new year
    ('month', at(2026, 11, 17, 12), UTC3, at(2026, 11, 1, tz=UTC3), None),
    ('month', at(2026, 11, 30, 22), UTC3, at(2026, 12, 1, tz=UTC3), None),
    ('last_month', at(2026, 11, 17, 12), UTC3, at(2026, 10, 1, tz=UTC3), at(2026, 11, 1, tz=UTC3)),
    ('last_month', at(2027, 1, 15), 0, at(2026, 12, 1), at(2027, 1, 1)),        # across the year
    ('last_month', at(2028, 3, 31, 23), 0, at(2028, 2, 1), at(2028, 3, 1)),     # February of a leap year
    ('24h', at(2026, 11, 17, 12), UTC3, at(2026, 11, 16, 12), None),            # the rolling names still work
])
def test_period_bounds(name, now, tz, start, end):
    from app.main import range_bounds
    assert range_bounds(name, tz, now=now) == (start, now + 1 if end is None else end)


def test_custom_period_and_chart_step():
    from app.main import bucket_for, range_bounds
    now = at(2026, 11, 17, 12)
    assert range_bounds('custom', UTC3, '2026-11-01', '2026-11-03', now) == (at(2026, 11, 1, tz=UTC3), at(2026, 11, 4, tz=UTC3))
    assert range_bounds('custom', 0, '2026-11-17', '2026-11-17', now) == (at(2026, 11, 17), now + 1)     # not into the future
    for dates in (('2026-11-03', '2026-11-01'), ('2026-11-20', '2026-11-21'), ('', ''), ('yesterday', '2026-11-01'), (None, None)):
        with pytest.raises(HTTPException):
            range_bounds('custom', 0, *dates, now)
    for bad in (('bogus', 0), ('today', 15 * 3600)):
        with pytest.raises(HTTPException):
            range_bounds(*bad, now=now)
    day = 86400
    assert bucket_for(now - day, now, now) == 600 and bucket_for(now - 2 * day, now, now) == 600
    assert bucket_for(now - 7 * day, now, now) == 3600 and bucket_for(now - 30 * day, now, now) == 86400
    # Old data is only kept per hour, then per day: a short period long ago is not drawn finer.
    assert bucket_for(now - 10 * day, now - 9 * day, now) == 3600
    assert bucket_for(now - 100 * day, now - 99 * day, now) == 86400
