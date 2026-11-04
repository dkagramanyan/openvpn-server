"""Persist bounded relay snapshots as visits, independently of VPN management."""
import logging
import threading
import time

from . import relay_services

IDLE_SECONDS = 300
POLL_SECONDS = 5
RETENTION = 365 * 86400
log = logging.getLogger(__name__)


def record(db, status, now=None):
    if not status.get('ready'):
        return
    now = int(time.time()) if now is None else now
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
            existing = conn.execute('SELECT grp FROM relay_sessions WHERE id = ?', (row['id'],)).fetchone()
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
                sampled_at = EXCLUDED.sampled_at, active = EXCLUDED.active,
                accepted = GREATEST(relay_sessions.accepted, EXCLUDED.accepted),
                denied = GREATEST(relay_sessions.denied, EXCLUDED.denied),
                failed = GREATEST(relay_sessions.failed, EXCLUDED.failed),
                bytes_up = GREATEST(relay_sessions.bytes_up, EXCLUDED.bytes_up),
                bytes_down = GREATEST(relay_sessions.bytes_down, EXCLUDED.bytes_down),
                uncounted = GREATEST(relay_sessions.uncounted, EXCLUDED.uncounted)''',
                (row['id'], group, row['client'], row['credential_id'], row['transport'], row['started_at'],
                 row['last_seen'], now, row['active'], row['accepted'], row['denied'], row['failed'],
                 row['bytes_up'], row['bytes_down'], row['uncounted_flows']))
        conn.execute('DELETE FROM relay_sessions WHERE last_seen < ?', (now - RETENTION,))


def sessions(db, *, client=None, credential=None, now=None):
    now = int(time.time()) if now is None else now
    where, args = [], []
    if client is not None:
        where.append('client_name = ?'); args.append(client)
    if credential is not None:
        where.append('credential_id = ?'); args.append(credential)
    rows = db.query('''SELECT grp AS id, ARRAY_AGG(id) AS member_ids, client_name AS client, MIN(started_at) AS started_at,
        MAX(last_seen) AS last_seen, SUM(CASE WHEN sampled_at >= ? THEN active ELSE 0 END) AS active,
        SUM(accepted) AS accepted, SUM(denied) AS denied, SUM(failed) AS failed,
        SUM(bytes_up) AS bytes_up, SUM(bytes_down) AS bytes_down, SUM(uncounted) AS uncounted_flows
        FROM relay_sessions ''' + ('WHERE ' + ' AND '.join(where) if where else '') +
        ' GROUP BY grp, client_name ORDER BY MIN(started_at) DESC, grp DESC LIMIT 200', (now - 3 * POLL_SECONDS, *args))
    for row in rows:
        row['state'] = 'active' if row['active'] else 'idle' if now - row['last_seen'] <= IDLE_SECONDS else 'ended'
        row['ended_at'] = row['last_seen'] if row['state'] == 'ended' else None
    return rows


class RelayCollector(threading.Thread):
    def __init__(self, db):
        super().__init__(name='relay-history', daemon=True)
        self.db = db
        self._stop_event = threading.Event()
        self._seen = {}

    def run(self):
        while not self._stop_event.is_set():
            try:
                status = relay_services.runtime_status()
                if status.get('ready'):
                    snapshots = {row['id']: row for row in status.get('sessions', [])}
                    changed = [row for key, row in snapshots.items() if self._seen.get(key) != row]
                    record(self.db, {**status, 'sessions': changed})
                    self._seen = snapshots
            except Exception:
                log.exception('Could not save relay activity')
            self._stop_event.wait(POLL_SECONDS)

    def stop(self):
        self._stop_event.set()
        self.join(timeout=10)
