"""Persist bounded relay snapshots as visits, traffic and a connection log, independently of VPN management."""
import logging
import threading
import time

from . import relay_services
from .db import RELAY_FLOW_RETENTION

IDLE_SECONDS = 300
POLL_SECONDS = 5
RETENTION = 365 * 86400
FINAL_KINDS = ('closed', 'denied', 'failed')
log = logging.getLogger(__name__)

_GROUPED = '''SELECT grp AS id, ARRAY_AGG(id) AS member_ids, client_name AS client, MIN(started_at) AS started_at,
    MAX(last_seen) AS last_seen, SUM(CASE WHEN sampled_at >= ? THEN active ELSE 0 END) AS active,
    SUM(accepted) AS accepted, SUM(denied) AS denied, SUM(failed) AS failed,
    SUM(bytes_up) AS bytes_up, SUM(bytes_down) AS bytes_down, SUM(uncounted) AS uncounted_flows,
    STRING_AGG(DISTINCT transport, '+' ORDER BY transport) AS transport
    FROM relay_sessions'''


def record(db, status, now=None):
    """Save the session rows of one relay status. A row's counters are cumulative, so the traffic
    added to the per-minute buckets is the growth against the stored row: reading the same status
    twice, a UI restart or a relay restart (new ids) never counts a byte twice."""
    if not status.get('ready'):
        return
    now = int(time.time()) if now is None else now
    minute = now - now % 60
    with db.tx() as conn:
        # A new relay process has no surviving flows from its predecessor.
        instance = status.get('instance')
        if instance:
            conn.execute("UPDATE relay_sessions SET active = 0 WHERE active > 0 AND id NOT LIKE ?", (instance + ':%',))
        for row in status.get('sessions', []):
            # Older relays have no credential identity. Do not associate their
            # historical data with a newly created profile with the same name.
            if not row.get('client') or not row.get('credential_id'):
                continue
            existing = conn.execute('SELECT grp, client_name, bytes_up, bytes_down FROM relay_sessions WHERE id = ?',
                                    (row['id'],)).fetchone()
            previous = None if existing else conn.execute(
                'SELECT grp FROM relay_sessions WHERE client_name = ? AND credential_id = ? '
                'AND last_seen >= ? AND started_at <= ? ORDER BY last_seen DESC LIMIT 1',
                (row['client'], row['credential_id'], row['started_at'] - IDLE_SECONDS, row['started_at'])).fetchone()
            group = (existing or previous or {}).get('grp', row['id'])
            conn.execute('''INSERT INTO relay_sessions
                (id, grp, client_name, credential_id, transport, started_at, last_seen, sampled_at,
                 active, accepted, denied, failed, bytes_up, bytes_down, uncounted)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO UPDATE SET last_seen = GREATEST(relay_sessions.last_seen, EXCLUDED.last_seen),
                sampled_at = EXCLUDED.sampled_at, active = EXCLUDED.active, transport = EXCLUDED.transport,
                accepted = GREATEST(relay_sessions.accepted, EXCLUDED.accepted),
                denied = GREATEST(relay_sessions.denied, EXCLUDED.denied),
                failed = GREATEST(relay_sessions.failed, EXCLUDED.failed),
                bytes_up = GREATEST(relay_sessions.bytes_up, EXCLUDED.bytes_up),
                bytes_down = GREATEST(relay_sessions.bytes_down, EXCLUDED.bytes_down),
                uncounted = GREATEST(relay_sessions.uncounted, EXCLUDED.uncounted)''',
                (row['id'], group, row['client'], row['credential_id'], row.get('transport') or '', row['started_at'],
                 row['last_seen'], now, row['active'], row['accepted'], row['denied'], row['failed'],
                 row['bytes_up'], row['bytes_down'], row.get('uncounted_flows', 0)))
            # Relay "up" is what the client sent: bytes_in, as for OpenVPN. A row archived under
            # an earlier certificate's name keeps collecting under that name.
            stored = existing or {'client_name': row['client'], 'bytes_up': 0, 'bytes_down': 0}
            db.add_traffic(conn, minute, stored['client_name'], row['bytes_up'] - stored['bytes_up'],
                           row['bytes_down'] - stored['bytes_down'], source='relay')
        conn.execute('DELETE FROM relay_sessions WHERE last_seen < ?', (now - RETENTION,))


def record_flows(db, instance, events, default_transport=None, now=None):
    """Save finished connections of known clients, once each: (instance, id) is the key."""
    now = int(time.time()) if now is None else now
    rows = [e for e in events if e.get('kind') in FINAL_KINDS and e.get('client') and e.get('id') is not None
            and (e.get('ts') or now) >= now - RELAY_FLOW_RETENTION]
    if not instance or not rows:
        return 0
    saved = 0
    with db.tx() as conn:
        for e in rows:
            # The session row knows the name the history is kept under (an archived earlier certificate).
            owner = conn.execute('SELECT client_name FROM relay_sessions WHERE id = ?', (e.get('session_id') or '',)).fetchone()
            saved += conn.execute('''INSERT INTO relay_flows (instance, id, session_id, client_name, ts, kind, protocol,
                transport, target, reason, upstream_error, status, duration_ms, bytes_up, bytes_down, address)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (instance, id) DO NOTHING''',
                (instance, int(e['id']), e.get('session_id') or None, owner['client_name'] if owner else e['client'],
                 int(e.get('ts') or now), e['kind'], e.get('protocol') or None,
                 e.get('transport') or default_transport, (e.get('target') or '')[:300] or None, e.get('reason') or None,
                 e.get('upstream_error') or None, e.get('status') or None, int(e.get('duration_ms') or 0),
                 int(e.get('bytes_up') or 0), int(e.get('bytes_down') or 0), (e.get('address') or '')[:64] or None)).rowcount
    return saved


def flows(db, client, *, credential=None, q='', limit=100, offset=0):
    """(total, one page) of a client's saved connections, newest first."""
    where, args = ['f.client_name = ?'], [client]
    if credential is not None:
        where.append('EXISTS (SELECT 1 FROM relay_sessions s WHERE s.id = f.session_id AND s.credential_id = ?)')
        args.append(credential)
    if q:
        where.append("f.target ILIKE ? ESCAPE '\\'")
        args.append('%' + q.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%')
    clause = ' WHERE ' + ' AND '.join(where)
    total = db.one('SELECT COUNT(*) AS n FROM relay_flows f' + clause, args)
    rows = db.query('SELECT f.id, f.instance, f.session_id, f.ts, f.kind, f.protocol, f.transport, f.target, f.reason, '
                    'f.upstream_error, f.status, f.duration_ms, f.bytes_up, f.bytes_down FROM relay_flows f' + clause +
                    ' ORDER BY f.ts DESC, f.id DESC LIMIT ? OFFSET ?', args + [limit, offset])
    return (int(total['n']) if total else 0), [dict(r) for r in rows]


def _finish(rows, now):
    for row in rows:
        row['state'] = 'active' if row['active'] else 'idle' if now - row['last_seen'] <= IDLE_SECONDS else 'ended'
        row['ended_at'] = row['last_seen'] if row['state'] == 'ended' else None
    return rows


def sessions(db, *, client=None, credential=None, now=None):
    now = int(time.time()) if now is None else now
    where, args = [], []
    if client is not None:
        where.append('client_name = ?'); args.append(client)
    if credential is not None:
        where.append('credential_id = ?'); args.append(credential)
    rows = db.query(_GROUPED + (' WHERE ' + ' AND '.join(where) if where else '') +
        ' GROUP BY grp, client_name ORDER BY MIN(started_at) DESC, grp DESC LIMIT 200', (now - 3 * POLL_SECONDS, *args))
    return _finish(rows, now)


def visits(db, *, client=None, active=False, limit=100, offset=0, now=None):
    """(number of relay sessions, one page of them), newest first."""
    now = int(time.time()) if now is None else now
    where, args = ('WHERE client_name = ?', [client]) if client is not None else ('', [])
    having = ' HAVING SUM(CASE WHEN sampled_at >= ? THEN active ELSE 0 END) > 0' if active else ''
    grouped = f'{_GROUPED} {where} GROUP BY grp, client_name{having}'
    params = [now - 3 * POLL_SECONDS, *args] + ([now - 3 * POLL_SECONDS] if active else [])
    total = db.one(f'SELECT COUNT(*) AS n FROM ({grouped})', params)
    rows = db.query(grouped + ' ORDER BY MIN(started_at) DESC, grp DESC LIMIT ? OFFSET ?', params + [limit, offset])
    return (int(total['n']) if total else 0), _finish(rows, now)


def stats_by_client(db):
    rows = db.query('''SELECT client_name, COUNT(DISTINCT grp) AS n, MAX(last_seen) AS last_seen, MIN(started_at) AS first_seen,
        SUM(bytes_up) AS bu, SUM(bytes_down) AS bd FROM relay_sessions GROUP BY client_name''')
    return {r['client_name']: {'sessions': int(r['n']), 'last_seen': int(r['last_seen']), 'first_seen': int(r['first_seen']),
                               'bytes_in': int(r['bu'] or 0), 'bytes_out': int(r['bd'] or 0)} for r in rows}


def count_between(db, start, end):
    row = db.one('SELECT COUNT(DISTINCT grp) AS n FROM relay_sessions WHERE last_seen >= ? AND started_at < ?', (start, end))
    return int(row['n']) if row else 0


def backfill_traffic(db):
    """Once, on the upgrade to 2.3: relay sessions recorded so far have no per-minute traffic.
    Each one's bytes are booked at its last activity, the only time known for them."""
    with db.tx() as conn:
        if conn.execute("SELECT 1 FROM settings WHERE key = 'migration:relay_traffic'").fetchone():
            return 0
        rows = conn.execute('SELECT client_name, last_seen, bytes_up, bytes_down FROM relay_sessions').fetchall()
        for r in rows:
            db.add_traffic(conn, r['last_seen'] - r['last_seen'] % 60, r['client_name'], r['bytes_up'], r['bytes_down'],
                           source='relay')
        conn.execute("INSERT INTO settings (key, value) VALUES ('migration:relay_traffic', '1')")
        return len(rows)


class RelayCollector(threading.Thread):
    def __init__(self, db, on_live=None):
        super().__init__(name='relay-history', daemon=True)
        self.db = db
        self.on_live = on_live          # called with the clients that have open relay connections
        self._stop_event = threading.Event()
        self._seen = {}
        self._instance = None
        self._cursor = 0                # highest event "seq" stored from this relay process
        self._rates = {}                # client -> (time, bytes_up, bytes_down)

    def poll(self, now=None):
        clock = time.monotonic() if now is None else now
        status = relay_services.runtime_status(since=self._cursor)
        if not status.get('ready'):
            self._live([], False)
            return
        instance = status.get('instance')
        if instance != self._instance:
            # Another relay process: its event log starts again, so read it from the beginning.
            stale = self._cursor
            self._instance, self._cursor, self._seen, self._rates = instance, 0, {}, {}
            if stale:
                status = relay_services.runtime_status(since=0)
                if not status.get('ready') or status.get('instance') != instance:
                    return
        snapshots = {row['id']: row for row in status.get('sessions', [])}
        changed = [row for key, row in snapshots.items() if self._seen.get(key) != row]
        record(self.db, {**status, 'sessions': changed})
        self._seen = snapshots
        events = status.get('events', [])
        transport = status.get('transport') if status.get('transport') in ('http2', 'http3') else None
        record_flows(self.db, instance, events, transport)
        # Events of an older relay have no "seq": every poll then reads the last 500 again and
        # the (instance, id) key drops what is already stored.
        self._cursor = max([self._cursor] + [int(e['seq']) for e in events if e.get('seq') is not None])
        live = []
        for c in status.get('clients', []):
            if not c.get('client') or not c.get('active'):
                continue
            up, down = int(c.get('bytes_up') or 0), int(c.get('bytes_down') or 0)
            at, last_up, last_down = self._rates.get(c['client'], (clock, up, down))
            dt = max(clock - at, 1e-6)
            live.append({'client': c['client'], 'guest': bool(c.get('guest')), 'active': int(c['active']),
                         'tcp': int(c.get('tcp') or 0), 'udp': int(c.get('udp') or 0),
                         'destinations': int(c.get('destinations') or 0), 'bytes_up': up, 'bytes_down': down,
                         'rate_up': max(up - last_up, 0) / dt if clock > at else 0.0,
                         'rate_down': max(down - last_down, 0) / dt if clock > at else 0.0})
            self._rates[c['client']] = (clock, up, down)
        self._rates = {name: self._rates[name] for name in (c['client'] for c in live)}
        self._live(live, True)

    def _live(self, clients, ready):
        if self.on_live:
            self.on_live(sorted(clients, key=lambda c: c['client']), ready)

    def run(self):
        while not self._stop_event.is_set():
            try:
                self.poll()
            except Exception:
                log.exception('Could not save relay activity')
            self._stop_event.wait(POLL_SECONDS)

    def stop(self):
        self._stop_event.set()
        self.join(timeout=10)
