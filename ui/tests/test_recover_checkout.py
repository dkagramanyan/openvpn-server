"""Real Git interrupted-checkout recovery without moving live runtime files."""
import os
from pathlib import Path
import stat
import subprocess
import sys

import pytest

SCRIPT = Path(__file__).resolve().parents[2] / 'bin/recover-checkout.py'


def git(root, *args):
    return subprocess.run(['git', '-C', str(root), *args], check=True, capture_output=True).stdout.decode().strip()


def put(root, name, value):
    path = root / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value)
    return path


def fixture(tmp_path):
    origin, upstream, deployed = (tmp_path / n for n in ('origin.git', 'upstream', 'deployed'))
    subprocess.run(['git', 'init', '--bare', '--initial-branch=main', str(origin)], check=True, capture_output=True)
    subprocess.run(['git', 'clone', str(origin), str(upstream)], check=True, capture_output=True)
    git(upstream, 'config', 'user.name', 'Recovery Test')
    git(upstream, 'config', 'user.email', 'recovery@example.test')
    for name, content in {
        '.gitignore': '.env\npki/\ndb/\nconfig/management.pw\n',
        'README.md': 'old code\n', 'relay/main.go': 'old relay\n',
        'docker-compose.yml': 'services:\n  openvpn-ui:\n    image: old\n',
        'server.conf': 'port 1197\n', 'config/client.conf': 'remote old.example.com\n',
        'config/easy-rsa.vars': 'set_var EASYRSA_REQ_CN old\n', 'fw-rules.sh': '# old firewall\n',
    }.items(): put(upstream, name, content)
    git(upstream, 'add', '.')
    git(upstream, 'commit', '-m', 'old deployment')
    git(upstream, 'push', 'origin', 'main')
    subprocess.run(['git', 'clone', str(origin), str(deployed)], check=True, capture_output=True)
    git(deployed, 'config', 'user.name', 'Recovery Test')
    git(deployed, 'config', 'user.email', 'recovery@example.test')
    for name, content in {
        'README.md': 'new code\n', 'relay/main.go': 'new relay\n',
        'docker-compose.yml': 'services:\n  postgres:\n    image: postgres\n',
        'bin/setup-env.py': '# incoming helper\n', 'signer/service.py': '# incoming signer\n',
        'postgres/00-roles.sh': '# incoming roles\n',
    }.items(): put(upstream, name, content)
    git(upstream, 'add', '.')
    git(upstream, 'commit', '-m', 'new deployment')
    git(upstream, 'push', 'origin', 'main')
    # Model Git's failed checkout: new file contents, but the old HEAD/index.
    for name in ('README.md', 'relay/main.go', 'docker-compose.yml', 'bin/setup-env.py', 'signer/service.py', 'postgres/00-roles.sh'):
        put(deployed, name, (upstream / name).read_text())
    put(deployed, 'server.conf', 'port 443\n')
    put(deployed, 'config/client.conf', 'remote keep.example.com\n')
    put(deployed, 'config/easy-rsa.vars', 'set_var EASYRSA_REQ_CN KeepMe\n')
    put(deployed, 'fw-rules.sh', '# custom firewall\n')
    put(deployed, '.env', 'DO_NOT_PRINT=private-env-sentinel\n')
    put(deployed, 'pki/private/ca.key', 'private-key-sentinel\n')
    put(deployed, 'db/openvpn-ui.db', 'database-sentinel\n')
    put(deployed, 'guests/alice', '')  # Intentionally unignored; must never move.
    put(deployed, 'bin/local-only.sh', '# custom untracked script\n')
    git(deployed, 'stash', 'push', '-m', 'user stash after failed pull')
    return deployed, upstream, git(deployed, 'rev-parse', 'refs/stash')


def run(root):
    return subprocess.run([sys.executable, str(SCRIPT), '--repo', str(root)], capture_output=True, text=True)


def test_recovers_partial_checkout_and_old_stashed_config_without_touching_live_data(tmp_path):
    root, upstream, original_stash = fixture(tmp_path)
    protected = ('.env', 'pki/private/ca.key', 'db/openvpn-ui.db', 'guests/alice', 'bin/local-only.sh')
    before = {n: ((root / n).read_bytes(), (root / n).stat()) for n in protected}
    server_inode = (root / 'server.conf').stat().st_ino
    result = run(root)
    assert result.returncode == 0, result.stderr
    assert git(root, 'rev-parse', 'HEAD') == git(upstream, 'rev-parse', 'HEAD')
    assert (root / 'README.md').read_text() == 'new code\n'
    assert (root / 'bin/setup-env.py').is_file()
    assert (root / 'docker-compose.yml').read_text() == (upstream / 'docker-compose.yml').read_text()
    assert (root / 'server.conf').read_text() == 'port 443\n'
    assert (root / 'config/client.conf').read_text() == 'remote keep.example.com\n'
    assert (root / 'config/easy-rsa.vars').read_text() == 'set_var EASYRSA_REQ_CN KeepMe\n'
    assert (root / 'fw-rules.sh').read_text() == '# custom firewall\n'
    assert (root / 'server.conf').stat().st_ino == server_inode
    for name, (content, old) in before.items():
        now = (root / name).stat()
        assert (root / name).read_bytes() == content
        assert (now.st_ino, now.st_uid, now.st_gid, now.st_mode, now.st_mtime_ns) == (old.st_ino, old.st_uid, old.st_gid, old.st_mode, old.st_mtime_ns)
    stashes = git(root, 'stash', 'list', '--format=%H').splitlines()
    assert original_stash in stashes and len(stashes) == 2
    saved_untracked = git(root, 'ls-tree', '-r', '--name-only', stashes[0] + '^3').splitlines()
    assert saved_untracked == ['bin/setup-env.py', 'postgres/00-roles.sh', 'signer/service.py']
    records = root / '.git/openvpn-recovery'
    for path in records.rglob('*'):
        assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)
    assert 'private-env-sentinel' not in result.stdout + result.stderr
    assert 'private-key-sentinel' not in result.stdout + result.stderr
    again = run(root)
    assert again.returncode == 0, again.stderr
    assert git(root, 'stash', 'list', '--format=%H').splitlines() == stashes
    assert (root / 'server.conf').read_text() == 'port 443\n'


@pytest.mark.parametrize('conflict', ['runtime', 'compose', 'upstream-runtime'])
def test_preserves_independent_changes_and_stops_for_review(conflict, tmp_path):
    root, upstream, original_stash = fixture(tmp_path)
    if conflict == 'runtime':
        put(root, 'server.conf', 'port 8888\n')
    elif conflict == 'compose':
        git(root, 'stash', 'pop')  # Recreate the user's stash with actual custom Compose values.
        put(root, 'docker-compose.yml', 'services:\n  openvpn-ui:\n    image: custom\n')
        git(root, 'stash', 'push', '-m', 'custom deployment settings')
        original_stash = git(root, 'rev-parse', 'refs/stash')
    else:
        put(upstream, 'server.conf', 'port 5555\n')
        git(upstream, 'add', 'server.conf')
        git(upstream, 'commit', '-m', 'independent upstream runtime change')
        git(upstream, 'push', 'origin', 'main')
    head = git(root, 'rev-parse', 'HEAD')
    before = (root / 'server.conf').read_bytes()
    result = run(root)
    assert result.returncode == 1
    assert 'review' in result.stderr.lower()
    assert git(root, 'rev-parse', 'HEAD') == head
    assert git(root, 'rev-parse', 'refs/stash') == original_stash
    assert (root / 'server.conf').read_bytes() == before
    assert (root / 'guests/alice').is_file()
    assert (root / 'bin/setup-env.py').is_file()


@pytest.mark.skipif(os.environ.get('OVPN_TEST_REPAIR_PERMISSIONS') != '1' or os.geteuid() != 0,
                    reason='Real ownership repair runs only in the disposable Docker test container')
def test_repairs_root_owned_code_as_login_user_and_preserves_runtime_owners():
    import pwd
    import shutil
    import tempfile
    base = Path(tempfile.mkdtemp(prefix='ovpn-recovery-owners-'))
    sudoers = Path('/etc/sudoers.d/ovpn-checkout-recovery-test')
    try:
        try:
            account = pwd.getpwuid(1000)
        except KeyError:
            subprocess.run(['adduser', '-D', '-u', '1000', 'recoverytest'], check=True, capture_output=True)
            account = pwd.getpwuid(1000)
        uid, gid = account.pw_uid, account.pw_gid
        root, upstream, _ = fixture(base)
        target = git(upstream, 'rev-parse', 'HEAD')
        subprocess.run(['chown', '-R', f'{uid}:{gid}', str(base)], check=True)
        base.chmod(0o755)
        for name in ('.git', 'relay', 'bin', 'signer', 'postgres'):
            subprocess.run(['chown', '-R', '0:0', str(root / name)], check=True)
        protected = ('.env', 'pki/private/ca.key', 'db/openvpn-ui.db', 'guests/alice')
        for name in protected:
            os.chown(root / name, 65532, 65532)
            (root / name).chmod(0o600)
        os.chown(root / 'server.conf', 0, gid)
        (root / 'server.conf').chmod(0o640)
        before = {n: ((root / n).read_bytes(), (root / n).stat()) for n in protected}
        server_stat = (root / 'server.conf').stat()
        sudoers.parent.mkdir(exist_ok=True)
        sudoers.write_text(f'{account.pw_name} ALL=(root) NOPASSWD: /bin/chown, /usr/bin/chown, /bin/cat, /usr/bin/cat, /bin/tee, /usr/bin/tee\n')
        sudoers.chmod(0o440)
        result = subprocess.run([sys.executable, str(SCRIPT), '--repo', str(root), '--repair-permissions'],
                                user=uid, group=gid, env={**os.environ, 'HOME': str(base)}, capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
        head = subprocess.run(['git', '-C', str(root), 'rev-parse', 'HEAD'], user=uid, group=gid,
                              env={**os.environ, 'HOME': str(base)}, check=True, capture_output=True).stdout.decode().strip()
        assert head == target
        assert (root / '.git').stat().st_uid == uid
        assert (root / 'relay/main.go').stat().st_uid == uid
        assert (root / 'server.conf').read_text() == 'port 443\n'
        now = (root / 'server.conf').stat()
        assert (now.st_ino, now.st_uid, now.st_gid, now.st_mode) == (server_stat.st_ino, server_stat.st_uid, server_stat.st_gid, server_stat.st_mode)
        for name, (content, old) in before.items():
            now = (root / name).stat()
            assert (root / name).read_bytes() == content
            assert (now.st_ino, now.st_uid, now.st_gid, now.st_mode, now.st_mtime_ns) == (old.st_ino, old.st_uid, old.st_gid, old.st_mode, old.st_mtime_ns)
        assert 'private-env-sentinel' not in result.stdout + result.stderr
        assert 'private-key-sentinel' not in result.stdout + result.stderr
    finally:
        sudoers.unlink(missing_ok=True)
        shutil.rmtree(base)
