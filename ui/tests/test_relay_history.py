import copy
from pg_fixture import Database
from app import relay_history


def sample(identifier='boot:1', start=1000, last=1010, **changes):
    row = dict(id=identifier, client='alice', credential_id='one', transport='http2', started_at=start,
        last_seen=last, active=1, accepted=3, denied=1, failed=0, bytes_up=100, bytes_down=200, uncounted_flows=0)
    row.update(changes)
    return dict(ready=True, instance=identifier.split(':')[0], sessions=[row])


def test_history_counts_snapshots_once_and_survives_database_reopen():
    db = Database()
    relay_history.record(db, sample(), now=1010)
    relay_history.record(db, sample(), now=1011)
    later = sample(last=1020, accepted=4, bytes_up=140, bytes_down=280, active=0)
    relay_history.record(db, later, now=1020)
    row = relay_history.sessions(db, now=1021)[0]
    assert (row['accepted'], row['bytes_up'], row['bytes_down'], row['state']) == (4, 140, 280, 'idle')
    db._conn().close()
    assert relay_history.sessions(db, now=1400)[0]['state'] == 'ended'
    assert relay_history.sessions(db, now=1400)[0]['ended_at'] == 1020


def test_restart_merges_close_visits_but_keeps_new_credentials_separate():
    db = Database()
    relay_history.record(db, sample(), now=1010)
    relay_history.record(db, sample('reboot:1', 1020, 1030), now=1030)
    rows = relay_history.sessions(db, now=1030)
    assert len(rows) == 1
    assert (rows[0]['active'], rows[0]['accepted'], rows[0]['bytes_up']) == (1, 6, 200)
    relay_history.record(db, sample('reboot:2', 1400, 1410, active=0), now=1410)
    assert len(relay_history.sessions(db, now=1410)) == 2
    relay_history.record(db, sample('reboot:3', 1411, 1412, credential_id='replacement'), now=1412)
    assert len(relay_history.sessions(db, client='alice', credential='replacement', now=1412)) == 1
    assert len(relay_history.sessions(db, client='alice', credential='one', now=1412)) == 2
    assert relay_history.sessions(db, client='bob', now=1412) == []
    assert relay_history.sessions(db, client='alice', credential='', now=1412) == []


def test_stale_live_status_expires_and_missing_backend_preserves_history():
    db = Database()
    relay_history.record(db, sample(), now=1010)
    relay_history.record(db, dict(ready=False), now=1400)
    assert relay_history.sessions(db, now=1400)[0]['active'] == 0
    assert relay_history.sessions(db, now=1400)[0]['state'] == 'ended'
    old = copy.deepcopy(sample())
    old['sessions'][0]['credential_id'] = ''
    relay_history.record(db, old, now=1400)
    assert len(relay_history.sessions(db, now=1400)) == 1


def test_archiving_reused_name_preserves_separate_relay_identity():
    db = Database()
    relay_history.record(db, sample(active=0), now=1010)
    archive = db.archive_client_history('alice')
    assert archive and relay_history.sessions(db, client='alice', now=1010) == []
    # Re-reading the old boot snapshot must not restore its old client name.
    relay_history.record(db, sample(active=0), now=1011)
    assert relay_history.sessions(db, client='alice', now=1011) == []
    assert relay_history.sessions(db, client=archive, now=1011)[0]['accepted'] == 3
    relay_history.record(db, sample('boot:2', 1020, 1030, credential_id='replacement'), now=1030)
    assert relay_history.sessions(db, client='alice', now=1030)[0]['accepted'] == 3
