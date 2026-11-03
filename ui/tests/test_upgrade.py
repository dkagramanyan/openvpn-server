"""Upgrade ordering: preserve the live VPN and recover the old UI on import failure."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize('failure', ['', 'build', 'import'])
def test_upgrade_orders_database_migration_before_recreation_and_recovers(failure, tmp_path):
    (tmp_path / 'bin').mkdir()
    (tmp_path / 'config').mkdir()
    shutil.copy(ROOT / 'server.conf.example', tmp_path / 'server.conf.example')
    shutil.copy(ROOT / 'config/client.conf.example', tmp_path / 'config/client.conf.example')
    for name in ('setup-env.py', 'upgrade-relay.sh'):
        shutil.copy(ROOT / 'bin' / name, tmp_path / 'bin' / name)
    (tmp_path / '.env').write_text("OVPN_PUBLIC_HOST=existing.example.com\nOPENVPN_ADMIN_PASSWORD='keep-this-value'\nOPENVPN_DB_PASSWORD='existing-db-secret'\nAPPLE_RELAY_AUTH_URL=http://127.0.0.1:8080/api/relay/authorize\n")
    tools = tmp_path / 'tools'
    tools.mkdir()
    fake = tools / 'docker'
    fake.write_text('''#!''' + sys.executable + '''
import json, os, sys
args = sys.argv[1:]
with open(os.environ['COMMAND_LOG'], 'a') as out: out.write(json.dumps(args) + '\\n')
if args[:3] == ['compose','ps','-q']:
    print('old-vpn' if args[3:] == ['openvpn'] else 'old-ui\\nold-relay')
if (os.environ['FAIL_STAGE'] == 'build' and args[:2] == ['compose','build']) or (os.environ['FAIL_STAGE'] == 'import' and args[-1:] == ['import']):
    sys.exit(1)
''')
    fake.chmod(0o755)
    log = tmp_path / 'commands'
    env = {**os.environ, 'PATH': str(tools) + ':' + os.environ['PATH'], 'COMMAND_LOG': str(log), 'FAIL_STAGE': failure}
    result = subprocess.run(['bash', str(tmp_path / 'bin/upgrade-relay.sh')], env=env, capture_output=True, text=True)
    commands = [json.loads(row) for row in log.read_text().splitlines()]
    assert result.returncode == (1 if failure else 0)
    assert not any(row[:2] == ['compose', 'down'] for row in commands)
    assert not any(row[:2] == ['compose', 'stop'] and 'openvpn' in row[2:] for row in commands)
    assert not any(row[:2] == ['compose', 'up'] and row[-1:] == ['openvpn'] for row in commands)
    if failure == 'build':
        assert not any(row[:2] == ['compose', 'stop'] for row in commands)
    elif failure == 'import':
        assert ['start','old-ui','old-relay'] in commands
        assert not any('--force-recreate' in row for row in commands)
    else:
        imported = next(i for i,row in enumerate(commands) if row[-1:] == ['import'])
        recreated = next(i for i,row in enumerate(commands) if '--force-recreate' in row)
        assert imported < recreated
    content = (tmp_path / '.env').read_text()
    assert "OPENVPN_DB_PASSWORD='existing-db-secret'" in content
    assert "OPENVPN_ADMIN_PASSWORD='keep-this-value'" in content
    assert 'OVPN_PUBLIC_HOST=existing.example.com' in content
    assert '127.0.0.1:8447/api/relay/authorize' in content
    assert (tmp_path / '.env').stat().st_mode & 0o777 == 0o600
    assert (tmp_path / 'server.conf').is_file()
    assert (tmp_path / 'config/client.conf').is_file()
    subprocess.run([sys.executable, str(tmp_path / 'bin/setup-env.py')], check=True, capture_output=True)
    assert (tmp_path / '.env').read_text() == content
    assert 'existing-db-secret' not in result.stdout + result.stderr


def test_legacy_archive_keeps_current_compose_and_restores_sqlite_for_import(tmp_path):
    target, source, tools = (tmp_path / name for name in ('target','backup','tools'))
    for folder in (target, source / 'db', tools): folder.mkdir(parents=True)
    current = 'services:\n  postgres:\n    image: postgres:18.6-alpine\n'
    old = 'services:\n  openvpn-ui:\n    image: openvpn-ui:old\n'
    (target / 'docker-compose.yml').write_text(current)
    (source / 'docker-compose.yml').write_text(old)
    (source / 'db/openvpn-ui.db').write_bytes(b'legacy database copy')
    fake = tools / 'docker'
    fake.write_text('#!/bin/sh\nexit 0\n')
    fake.chmod(0o755)
    result = subprocess.run(['bash', str(ROOT / 'backup.sh'), '-y', '-r', str(target), str(source)],
                            env={**os.environ, 'PATH': str(tools) + ':' + os.environ['PATH']}, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert (target / 'docker-compose.yml').read_text() == current
    assert (target / 'db/legacy-docker-compose.yml').read_text() == old
    assert (target / 'db/openvpn-ui.db').read_bytes() == b'legacy database copy'
